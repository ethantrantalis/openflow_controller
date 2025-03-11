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

#if defined(__linux__)
    #include <endian.h>
#elif defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
    #define be64toh(x) OSSwapBigToHostInt64(x)
    #define htobe64(x) OSSwapHostToBigInt64(x)
#endif

void init_topology(){

    /* initialize the mutex */
    pthread_mutex_init(&topology.lock, NULL);

    /* initialize the graph */
    igraph_empty(&topology.graph, 0, IGRAPH_UNDIRECTED);
    igraph_vector_init(&topology.dpid_to_vertex, 0); /* mapping of dpid to vertex id */
    igraph_vector_fill(&topology.dpid_to_vertex, -1); /* fill with -1 to indicate not found */


    igraph_set_attribute_table(&igraph_cattribute_table);

}

/* ------------------------------------------------- SWITCH EVENTS ------------------------------------------------- */

/* funciton to handle a switch joining the graph, explore all connections */
void handle_switch_join(struct switch_info *sw) {
    pthread_mutex_lock(&topology.lock);
    
    /* add switch to topology if not exists */
    igraph_integer_t vertex_id = VECTOR(topology.dpid_to_vertex)[sw->datapath_id];

    if (vertex_id < 0) { /* does not exist in the topology yet */
        add_vertex(sw->datapath_id);
        
    }
    
    pthread_mutex_unlock(&topology.lock);
    
    /* send LLDP on all active ports to discover links */
    int i;
    for (i = 0; i < sw->num_ports; i++) { /* handle lldp packet will handle edge creation */
        uint16_t port_no = ntohs(sw->ports[i].port_no);
        if (port_no < OFPP_MAX && !(ntohl(sw->ports[i].state) & OFPPS_LINK_DOWN)) {
            send_topology_discovery_packet(sw, port_no);
        }
    }
}

/* a function to handle switch disconnection which will require removal from the topology */
void handle_switch_disconnect(struct switch_info *sw) {
    pthread_mutex_lock(&topology.lock);
    
    /* remove all links associated with this switch */
    remove_all_switch_links(sw->datapath_id);
    
    igraph_integer_t vertex_id = VECTOR(topology.dpid_to_vertex)[sw->datapath_id];

    if (vertex_id >= 0) { /* found */
        /* remove the vertex */
        igraph_delete_vertices(&topology.graph, igraph_vss_1(vertex_id));
        VECTOR(topology.dpid_to_vertex)[sw->datapath_id] = -1; /* mark as not found in case looked up later */
    }
    
    pthread_mutex_unlock(&topology.lock);
}

/* a function to handle a change on a switch which will updated the topology */
void handle_port_change(struct switch_info *sw, uint16_t src_port_no, bool is_up) {
    pthread_mutex_lock(&topology.lock);
    
    if (is_up) {
        /* port came up - send LLDP to discover new links */
        send_topology_discovery_packet(sw, src_port_no);
    } else {
        /* port went down - remove any associated links */
        remove_links_for_port(sw->datapath_id, src_port_no);
    }
    
    pthread_mutex_unlock(&topology.lock);
}

/* ----------------------------------------- TOPOLOGY MODIFICATION HELPERS ----------------------------------------- */

/* a function to easily add a vertex to the graph and update the vtex -> dpid vector */
void add_vertex(uint64_t dpid){
    
    pthread_mutex_lock(&topology.lock);

    igraph_integer_t vertex_id;

    igraph_add_vertices(&topology.graph, 1, NULL); /* add one vertex */
    vertex_id = igraph_vcount(&topology.graph) - 1; /* the newest vertex will be the hightest counted id */
    
    /* set attributes */
    char dpid_str[20];  /* buffer for the string representation */
    snprintf(dpid_str, sizeof(dpid_str), "%" PRIu64, dpid);
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

    pthread_mutex_unlock(&topology.lock);
}


/* add or update a link in the topology */
void add_or_update_link(uint64_t src_dpid, uint16_t src_port, uint64_t dst_dpid, uint16_t dst_port) {

    pthread_mutex_lock(&topology.lock);
    /* find or add source and destination vertices */
     
    igraph_integer_t src_vertex = VECTOR(topology.dpid_to_vertex)[src_dpid];
    igraph_integer_t dst_vertex = VECTOR(topology.dpid_to_vertex)[dst_dpid];

    if (src_vertex < 0 || dst_vertex < 0) {
        log_msg("Failed to find vertex in Vector\n");
        pthread_mutex_unlock(&topology.lock);
        return;
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
    igraph_cattribute_EAN_set(&topology.graph, "src_dpid", edge_id, src_dpid);
    igraph_cattribute_EAN_set(&topology.graph, "dst_dpid", edge_id, dst_dpid);
    igraph_cattribute_EAN_set(&topology.graph, "src_port", edge_id, src_port);
    igraph_cattribute_EAN_set(&topology.graph, "dst_port", edge_id, dst_port);
    igraph_cattribute_EAN_set(&topology.graph, "last_seen", edge_id, time(NULL));

    pthread_mutex_unlock(&topology.lock);
}

/* a function to remove a link from the topology */
void remove_links_for_port(uint64_t dpid, uint16_t src_port_no){

    pthread_mutex_lock(&topology.lock);

    igraph_integer_t vertex = VECTOR(topology.dpid_to_vertex)[dpid];
    if (vertex < 0) {
        log_msg("Failed to find vertex in Vector\n");
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

    pthread_mutex_unlock(&topology.lock);
}

/* a function to find all links in the graph with disconnected dpid */
void remove_all_switch_links(uint64_t dpid){

    pthread_mutex_lock(&topology.lock);

    igraph_integer_t edges_to_remove[igraph_ecount(&topology.graph)];
    int edges_marked_to_remove = 0;
    igraph_integer_t i, total = igraph_ecount(&topology.graph);
    for(i = 0; i < total; i++){ /* i is edge id */
        igraph_real_t src = EAN(&topology.graph, "src_dpid", i);
        igraph_real_t dst = EAN(&topology.graph, "dst_dpid", i);

        /* any edge that contains the down switch, remove */
        if((uint64_t)src == dpid || (uint64_t)dst == dpid){
            edges_to_remove[edges_marked_to_remove++] = i;
            
        }
    }

    /* in case outer edges are moved down to fill lower ID, remove after processing */
    for (i = 0; i < edges_marked_to_remove; i++) {
        igraph_delete_edges(&topology.graph, igraph_ess_1(edges_to_remove[i]));
    }

    pthread_mutex_unlock(&topology.lock);
};

/* ----------------------------------------- TOPOLOGY DISCOVERY FUNCTIONS ------------------------------------------ */
void send_topology_discovery_packet(struct switch_info *sw, uint16_t port_no) {


    /* 
     * ofp_packet_out - tells a switch to send the packet
     * ofp_action_output - tells a switch to output the message from specific port
     * ethernet - for L2 routing
     * custom LLDP - contains src dpid, src port, lldp type, magic number (OFTO)  
     * */

    /* create a simplified discovery packet */
    uint8_t disc_packet[64] = {0};
    int packet_size = 0;
    
    /* ethernet header */
    uint8_t dst_mac[MAC_ADDR_LEN] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E}; /* LLDP multicast */
    memcpy(disc_packet + packet_size, dst_mac, MAC_ADDR_LEN);
    packet_size += 6; /* increment the size for offsets */
    
    /* port MAC address for more specific forwarding */
    uint8_t src_mac[MAC_ADDR_LEN] = {0}; 
    int i;
    for (i = 0; i < sw->num_ports; i++) { /* find the port struct in the swtich to get more info */
        if (ntohs(sw->ports[i].port_no) == port_no) {
            memcpy(src_mac, sw->ports[i].hw_addr, 6);
            break;
        }
    }
    memcpy(disc_packet + packet_size, src_mac, MAC_ADDR_LEN);
    packet_size += 6; /* increment the size for offsets */
    
    /* set EtherType to commone LLDP type (0x88CC) */
    disc_packet[packet_size++] = 0x88;
    disc_packet[packet_size++] = 0xCC;
    

    /* start of custom packet structure */
    
    /* magic number to identify our custom packets */
    uint32_t magic = htonl(0x4F46544F); /* "OFTO" */
    memcpy(disc_packet + packet_size, &magic, 4);
    packet_size += 4;
    
    /* packet type: 1 = topology discovery */
    disc_packet[packet_size++] = 0x01;
    
    /* source datapath ID (8 bytes) */
    uint64_t dpid_net = htobe64(sw->datapath_id);
    memcpy(disc_packet + packet_size, &dpid_net, 8);
    packet_size += 8;
    
    /* source port number */
    uint16_t port_net = htons(port_no);
    memcpy(disc_packet + packet_size, &port_net, 2);
    packet_size += 2;
    
    /*  create action ouput message */
    struct ofp_action_output action;
    memset(&action, 0, sizeof(action));
    action.type = htons(OFPAT_OUTPUT);
    action.len = htons(sizeof(action));
    action.port = htons(port_no);
    action.max_len = htons(0);
    
    int total_len = sizeof(struct ofp_packet_out) + sizeof(action) + packet_size;
    struct ofp_packet_out *po = malloc(total_len);
    if (!po) {
        log_msg("Error: Failed to allocate memory for packet_out message\n");
        return;
    }
    
    memset(po, 0, total_len);
    po->header.version = OFP_VERSION;
    po->header.type = OFPT_PACKET_OUT;
    po->header.length = htons(total_len);
    po->header.xid = htonl(0);
    
    po->buffer_id = htonl(0xFFFFFFFF); /* OFP_NO_BUFFER */
    po->in_port = htons(OFPP_NONE);
    po->actions_len = htons(sizeof(action));
    
    memcpy((uint8_t*)po + sizeof(struct ofp_packet_out), &action, sizeof(action));
    memcpy((uint8_t*)po + sizeof(struct ofp_packet_out) + sizeof(action), 
           disc_packet, packet_size);
    
    send_openflow_msg(sw, po, total_len);
    
    log_msg("Sent discovery packet from switch %016" PRIx64 " port %d\n", 
            sw->datapath_id, port_no);
    
    free(po);
}

/* helper function to verify that a packet is link layer discovery */
bool is_topology_discovery_packet(uint8_t *data, size_t len) {
    if (len < 26) return false;
    
    /* check destination MAC is the multicast address */
    uint8_t expected_dst_mac[MAC_ADDR_LEN] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E}; 
    if (memcmp(data, expected_dst_mac, MAC_ADDR_LEN) != 0) return false; /* lldp multicast is ethernet dst */
    
    /* check EtherType */
    if (data[LLDP_ETHERTYPE_OFFSET] != 0x88 || data[LLDP_ETHERTYPE_OFFSET + 1] != 0xCC) return false; /* should be right after dst mac and src mac */
    
    /* check magic number */
    uint32_t magic;
    memcpy(&magic, data + LLDP_MAGIC_OFFSET, 4); /* 14 is dst mac (6) + src mac (6) + type (2) */
    return ntohl(magic) == 0x4F46544F; /* "OFTO" */
}

/* function to gain data from a lldp packet (pass by reference)*/
bool extract_discovery_packet_info(uint8_t *data, size_t len, uint64_t *src_dpid, uint16_t *src_port) {
    if (len < 29) return false;
    
    /* extract source datapath ID */

    /* 19 is dst mac (6) + src mac (6) + type (2) + magic (4) + lldp type (1) */
    memcpy(src_dpid, data + LLDP_SRC_DPID_OFFSET, 8); 
    *src_dpid = be64toh(*src_dpid);
    
    /* extract source port */

    /* 27 is dst mac (6) + src mac (6) + type (2) + magic (4) + lldp type (1) + src_dpid (8)*/
    memcpy(src_port, data + LLDP_SRC_PORT_OFFSET, 2);
    *src_port = ntohs(*src_port);
    
    return true;
}

void handle_discovery_packet(struct switch_info *sw, struct ofp_packet_in *pi) {
    uint64_t src_dpid;
    uint16_t src_port;
    uint64_t dst_dpid = sw->datapath_id;
    uint16_t dst_port = ntohs(pi->in_port);
    
    /* extract information from discovery packet, passed reference items */
    if (!extract_discovery_packet_info(pi->data, ntohs(pi->total_len), &src_dpid, &src_port)) {
        log_msg("Failed to extract information from discovery packet\n");
        return;
    }
    
    log_msg("Received discovery packet: Switch %016" PRIx64 " Port %d -> Switch %016" PRIx64 " Port %d\n",
            src_dpid, src_port, dst_dpid, dst_port);
    
    /* update topology with this link information */
    add_or_update_link(src_dpid, src_port, dst_dpid, dst_port);
}

uint64_t vertex_to_dpid(igraph_integer_t vertex_id) {
    pthread_mutex_lock(&topology.lock);

    /* size will be for iterating over vertices */
    igraph_integer_t size, i = igraph_vcount(&topology.graph);
    if (vertex_id < 0 || vertex_id >= size) {
        pthread_mutex_unlock(&topology.lock);
        return -1;
    }

    /* remember that for the vector the index is dpid and value is vertex*/
    for (i = 0; i < size; i++){

        if (VECTOR(topology.dpid_to_vertex)[i] == vertex_id) {
            pthread_mutex_unlock(&topology.lock);
            return i;
        }
    }
    
    pthread_mutex_unlock(&topology.lock);
    return -1;
}

/* 
mst
igraph_spanning_tree(&topology.graph, &mst_graph, -1)

unicast
igraph_shortest_paths_unweighted(&topology.graph, &distances, src_vertex, to_vertices, IGRAPH_OUT)

multiple calculations: 
Where src_vertices and to_vertices are vertex selectors specifying the source and target vertices.

igraph_shortest_paths_unweighted(&topology.graph, &distances, src_vertices, to_vertices, IGRAPH_OUT)
*/