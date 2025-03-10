#include "headers/smartalloc.h"
#include "headers/checksum.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <inttypes.h>
#include <stdarg.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <sys/time.h>
#include <time.h>
#include </opt/homebrew/Cellar/igraph/0.10.15_1/include/igraph/igraph.h>
#include "headers/uthash.h"
#include "headers/controller.h"

void init_topology(){

    /* initialize the mutex */
    pthread_mutex_init(&topology.lock, NULL);

    /* initialize the graph */
    igraph_empty(&topology.graph, 0, IGRAPH_UNDIRECTED);
    igraph_vector_init(&topology.dpid_to_vertex, 0); /* mapping of dpid to vertex id */


    igraph_set_attribute_table(&igraph_cattribute_table);

}

/* ------------------------------------------------- SWITCH EVENTS ------------------------------------------------- */

/* funciton to handle a switch joining the graph, explore all connections */
void handle_switch_join(struct switch_info *sw) {
    pthread_mutex_lock(&topology.lock);
    
    /* add switch to topology if not exists */
    igraph_integer_t vertex_id = find_vertex_by_dpid(sw->datapath_id);

    if (vertex_id == -1) { /* does not exist in the topology yet */
        add_vertex(sw->datapath_id);
        
    }
    
    pthread_mutex_unlock(&topology.lock);
    
    /* send LLDP on all active ports to discover links */
    int i;
    for (i = 0; i < sw->num_ports; i++) { /* handle lldp packet will handle edge creation */
        uint16_t port_no = ntohs(sw->ports[i].port_no);
        if (port_no < OFPP_MAX && !(ntohl(sw->ports[i].state) & OFPPS_LINK_DOWN)) {
            send_lldp_packet(sw, port_no);
        }
    }
}

/* a function to handle switch disconnection which will require removal from the topology */
void handle_switch_disconnect(struct switch_info *sw) {
    pthread_mutex_lock(&topology.lock);
    
    /* remove all links associated with this switch */
    remove_all_switch_links(sw->datapath_id);
    
    igraph_integer_t vertex_id = find_vertex_by_dpid(sw->datapath_id);

    if (vertex_id >= 0) {
        /* remove the vertex */
        igraph_delete_vertices(&topology.graph, igraph_vss_1(vertex_id));
    }
    
    pthread_mutex_unlock(&topology.lock);
}

/* a function to handle a change on a switch which will updated the topology */
void handle_port_change(struct switch_info *sw, uint16_t src_port_no, bool is_up) {
    pthread_mutex_lock(&topology.lock);
    
    if (is_up) {
        /* port came up - send LLDP to discover new links */
        send_lldp_packet(sw, src_port_no);
    } else {
        /* port went down - remove any associated links */
        remove_links_for_port(sw->datapath_id, src_port_no);
    }
    
    pthread_mutex_unlock(&topology.lock);
}

/* ----------------------------------------- TOPOLOGY MODIFICATION HELPERS ----------------------------------------- */

/* a function to easily add a vertex to the graph and update the vtex -> dpid vector */
void add_vertex(uint64_t dpid){

    igraph_integer_t vertex_id;
    
    igraph_add_vertices(&topology.graph, 1, NULL); /* add one vertex */
    vertex_id = igraph_vcount(&topology.graph) - 1; /* the newest vertex will be the hightest counted id */
    
    /* set attributes */
    char dpid_str[20];  /* buffer for the string representation */
    snprintf(dpid_str, sizeof(dpid_str), "%llu", dpid);
    igraph_cattribute_VAS_set(&topology.graph, "dpid", vertex_id, dpid_str);
    
    /* map the dpid to the map of dpid to vector id 
    * the vector index is the dpid and the value at that
    * inedex is vertex id */
    
    /* resize if too small */
    if (dpid >= igraph_vector_size(&topology.dpid_to_vertex)) {
        igraph_vector_resize(&topology.dpid_to_vertex, dpid + 1);
    }

    /* set the value */
    VECTOR(topology.dpid_to_vertex)[dpid] = vertex_id;
}


/* a function to find a vertex based on its attribute */
igraph_integer_t find_vertex_by_dpid(uint64_t dpid){

    char dpid_str[20];
    snprintf(dpid_str, sizeof(dpid_str), "%llu", dpid);

    igraph_integer_t i, total = igraph_vcount(&topology.graph);
    for(i = 0; i < total; i++){

        /* pull a vetext by its attribute */
        const char *v_dpid = VAS(&topology.graph, "dpid", i);

        if(strcmp(v_dpid, dpid_str) == 0){
            return i; /* return i which is the vertex id*/
        }
    }

    return -1; /* not found */
}

/* add or update a link in the topology */
void add_or_update_link(uint64_t src_dpid, uint16_t src_port, uint64_t dst_dpid, uint16_t dst_port) {

    pthread_mutex_lock(&topology.lock);
    /* find or add source and destination vertices */
    igraph_integer_t src_vertex = find_vertex_by_dpid(src_dpid);
    igraph_integer_t dst_vertex = find_vertex_by_dpid(dst_dpid);

    if (src_vertex < 0 || dst_vertex < 0) {
        
    }
    
    /* check if edge already exists */
    igraph_integer_t edge_id;
    igraph_get_eid(&topology.graph, &edge_id, src_vertex, dst_vertex, IGRAPH_DIRECTED, 0);
    
    if (edge_id < 0) { /* edge not found */
        /* add new edge */
        igraph_add_edge(&topology.graph, src_vertex, dst_vertex);
        edge_id = igraph_ecount(&topology.graph) - 1;
    }
    
    /* set or update edge attributes */
    igraph_cattribute_EAN_set(&topology.graph, "src_port", edge_id, src_port);
    igraph_cattribute_EAN_set(&topology.graph, "dst_port", edge_id, dst_port);
    igraph_cattribute_EAN_set(&topology.graph, "last_seen", edge_id, time(NULL));

    pthread_mutex_unlock(&topology.lock);
}

/* a function to remove a link from the topology */
void remove_links_for_port(uint64_t dpid, uint16_t src_port_no){

    igraph_integer_t vertex = find_vertex_by_dpid(dpid);
    if (vertex < 0) {
        return; /* vertex not found */
    }

    char src_port_str[20];
    snprintf(src_port_str, sizeof(src_port_str), "%u", src_port_no);

    igraph_integer_t i, total = igraph_ecount(&topology.graph);
    for (i = 0; i < total; i++) {
        igraph_real_t src = EAN(&topology.graph, "src_dpid", i);
        igraph_real_t src_port = EAN(&topology.graph, "src_port", i);

        /* if current edge has switch with down port and the port number matches target */
        if ((igraph_integer_t)src == vertex && (uint16_t)src_port == src_port_no) {
            igraph_delete_edges(&topology.graph, igraph_ess_1(i));
        }
    }
}

/* a function to find all links in the graph with disconnected dpid */
void remove_all_switch_links(uint64_t dpid){

    igraph_integer_t i, total = igraph_ecount(&topology.graph);
    for(i = 0; i < total; i++){ /* i is edge id */
        igraph_real_t src = EAN(&topology.graph, "src_dpid", i);
        igraph_real_t dst = EAN(&topology.graph, "dst_dpid", i);

        /* any edge that contains the down switch, remove */
        if((uint64_t)src == dpid || (uint64_t)dst == dpid){
            igraph_delete_edges(&topology.graph, igraph_ess_1(i));
        }
    }
};

void send_lldp_packet(struct switch_info *sw, uint16_t port_no) {
    /* create the LLDP packet */
    uint8_t lldp_packet[128];
    int len = 0;
    
    /* send the packet */
    send_openflow_msg(sw, lldp_packet, len);
}
