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
#include </usr/include/igraph/igraph.h>
#include "headers/uthash.h"
#include "headers/controller.h"

#if defined(__linux__)
    #include <endian.h>
#elif defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
    #define be64toh(x) OSSwapBigToHostInt64(x)
    #define htobe64(x) OSSwapHostToBigInt64(x)
#endif

struct dpid_to_vertex_map * dpids_to_vertex = NULL;

void add_or_update_dpid(uint64_t dpid, igraph_integer_t vertex_id) {
    struct dpid_to_vertex_map *entry;
    
    /* use &dpid to pass a pointer to the key */
    HASH_FIND(hh, dpids_to_vertex, &dpid, sizeof(uint64_t), entry);
    if (entry == NULL) {
        entry = malloc(sizeof(struct dpid_to_vertex_map));
        entry->dpid = dpid;
        entry->vertex_id = vertex_id;
        HASH_ADD(hh, dpids_to_vertex, dpid, sizeof(uint64_t), entry);
    } else {

        /* update the vertex ID */
        entry->vertex_id = vertex_id;
    }
}

bool dpid_exists(uint64_t dpid) {

    struct dpid_to_vertex_map *entry;

    /* need to pass a pointer to the dpid value, not the value itself */
    HASH_FIND(hh, dpids_to_vertex, &dpid, sizeof(uint64_t), entry);
    return entry != NULL;
}

igraph_integer_t find_vertexid(struct switch_info *sw, uint64_t dpid) {
    
    struct dpid_to_vertex_map *entry;
    HASH_FIND(hh, dpids_to_vertex, &dpid, sizeof(uint64_t), entry);
    if (entry == NULL) {
        log_msg(sw, "DEBUG: find_vertexid(%016" PRIx64 ") returning %lld\n", 
        dpid, -1);
        return -1;  // Return invalid vertex ID if not found
    }
    log_msg(sw, "DEBUG: find_vertexid(%016" PRIx64 ") returning %lld\n", 
        dpid, entry->vertex_id);
    return entry->vertex_id;
}

void delete_dpid_mapping(uint64_t dpid) {
    struct dpid_to_vertex_map *entry;
    
    /* find the entry with the given dpid */
    HASH_FIND(hh, dpids_to_vertex, &dpid, sizeof(uint64_t), entry);
    
    /* if the entry exists, remove it from the hash and free memory */
    if (entry != NULL) {
        HASH_DEL(dpids_to_vertex, entry);
        free(entry);
    }
}

void init_topology(){

    printf("Initializing topology\n");

    /* initialize the mutex */
    pthread_mutex_init(&topology.lock, NULL);

    igraph_set_attribute_table(&igraph_cattribute_table);
    /* initialize the graph */
    igraph_empty(&topology.graph, 0, IGRAPH_UNDIRECTED);

}

/* function to clean up all topology resources */
void cleanup_topology() {
    struct dpid_to_vertex_map *current, *tmp;
    
    pthread_mutex_lock(&topology.lock);
    
    /* destroy the graph */
    igraph_destroy(&topology.graph);
    
    /* clean up the DPID to vertex mapping */
    HASH_ITER(hh, dpids_to_vertex, current, tmp) {
        HASH_DEL(dpids_to_vertex, current);
        free(current);
    }
    dpids_to_vertex = NULL;
    
    pthread_mutex_unlock(&topology.lock);
    pthread_mutex_destroy(&topology.lock);
}


void remove_all_switch_links(uint64_t dpid, struct switch_info *sw) {
    log_msg(sw, "Removing all links for switch %016" PRIx64 "\n", dpid);

    pthread_mutex_lock(&topology.lock);
    
    igraph_vector_int_t edges_to_delete;
    igraph_vector_int_init(&edges_to_delete, 0);
    
    /* collect all edges associated with this switch */
    for (igraph_integer_t i = 0; i < igraph_ecount(&topology.graph); i++) {
        uint64_t src_dpid = (uint64_t)EAN(&topology.graph, "src_dpid", i);
        uint64_t dst_dpid = (uint64_t)EAN(&topology.graph, "dst_dpid", i);
        
        if (src_dpid == dpid || dst_dpid == dpid) {
            igraph_vector_int_push_back(&edges_to_delete, i);
        }
    }
    
    /* selete edges in reverse order to avoid index shifting problems */
    for (igraph_integer_t i = igraph_vector_int_size(&edges_to_delete) - 1; i >= 0; i--) {
        igraph_delete_edges(&topology.graph, igraph_ess_1(VECTOR(edges_to_delete)[i]));
    }
    
    igraph_vector_int_destroy(&edges_to_delete);
    pthread_mutex_unlock(&topology.lock);
}
/* ------------------------------------------------- SWITCH EVENTS ------------------------------------------------- */

/* funciton to handle a switch joining the graph, explore all connections */
void handle_switch_join(struct switch_info *sw) {
    log_msg(sw, "Handling switch join to topology\n");

    
    /* add switch to topology if not exists */
    igraph_integer_t vertex_id;
    if(dpid_exists(sw->datapath_id)){
        log_msg(sw, "Switch already exists in topology\n");
        vertex_id = find_vertexid(sw, sw->datapath_id);


    } else {
        log_msg(sw, "Switch does not exist in topology\n");

        log_msg(sw, "Adding vertex for switch %016" PRIx64 "\n", sw->datapath_id);
        add_vertex(sw->datapath_id, sw);

        /* the newest vertex id will be the length of the vertex vector minus 1*/
        vertex_id = igraph_vcount(&topology.graph) - 1;
    }
    log_msg(sw, "Vertex id: %lld\n", vertex_id);
\
    
    /* send LLDP on all active ports to discover links */
    int i;
    for (i = 0; i < sw->num_ports; i++) { /* handle lldp packet will handle edge creation */
        uint16_t port_no = ntohs(sw->ports[i].port_no);
        if (port_no < OFPP_MAX && !(ntohl(sw->ports[i].state) & OFPPS_LINK_DOWN)) {
            send_topology_discovery_packet(sw, port_no);
        }
    }

    /* add all mac addresses to port from new switch */
    for (int i = 0; i < sw->num_ports; i++) {
        uint16_t port_no = ntohs(sw->ports[i].port_no);
        
        // Mark this MAC as belonging to switch infrastructure
        struct mac_entry *entry = malloc(sizeof(struct mac_entry));
        if (entry) {
            memcpy(entry->mac, sw->ports[i].hw_addr, MAC_ADDR_LEN);
            entry->switch_dpid = sw->datapath_id;
            entry->port_no = port_no;
            entry->last_seen = time(NULL);
            entry->is_trunk = true;  // Consider all switch ports as trunk initially
            entry->is_infrastructure = true;  // Mark as switch infrastructure
            
            // Add to MAC table with proper locking
            pthread_mutex_lock(&mac_table_lock);
            HASH_ADD(hh, mac_table, mac, MAC_ADDR_LEN, entry);
            pthread_mutex_unlock(&mac_table_lock);
        }
    }
}

/* a function to handle switch disconnection which will require removal from the topology */
void handle_switch_disconnect(struct switch_info *sw) {

    log_msg(sw, "Handling switch disconnect from topology\n");
    
    
    /* remove all links associated with this switch */
    remove_all_switch_links(sw->datapath_id, sw);
    
    igraph_integer_t vertex_id = find_vertexid(sw, sw->datapath_id);

    if (vertex_id >= 0) { /* found */
        /* remove the vertex */
        igraph_delete_vertices(&topology.graph, igraph_vss_1(vertex_id));
        delete_dpid_mapping(sw->datapath_id); /* mark as not found in case looked up later */
    }
    
}

/* a function to handle a change on a switch which will updated the topology */
void handle_port_change(struct switch_info *sw, uint16_t src_port_no, bool is_up) {

    log_msg(sw, "Handling port change for switch port %d\n", src_port_no);
    
    if (is_up) {
        /* port came up - send LLDP to discover new links */
        send_topology_discovery_packet(sw, src_port_no);
    } else {
        /* port went down - remove any associated links */
        remove_links_for_port(sw->datapath_id, src_port_no, sw);
    }
    

}

/* ----------------------------------------- TOPOLOGY MODIFICATION HELPERS ----------------------------------------- */

/* a function to easily add a vertex to the graph and update the vtex -> dpid vector */
void add_vertex(uint64_t dpid, struct switch_info * sw) {
    log_msg(sw, "DEBUG: Adding vertex for switch %016" PRIx64 "\n", dpid);

    // log_msg(sw, "MUTEX: Locking topology\n");
    pthread_mutex_lock(&topology.lock);

    /* first check if vertex already exists (important!) */
    if(dpid_exists(dpid)){

        igraph_integer_t existing_vertex = find_vertexid(sw, dpid);
        log_msg(sw, "DEBUG: Vertex already exists for switch %016" PRIx64 " at vertex ID %lld\n", 
               dpid, existing_vertex);
        
        pthread_mutex_unlock(&topology.lock);
        // log_msg(sw, "MUTEX: Unlocked topology\n");
        return;
    } 

    /* add new vertex - this creates a new UNIQUE vertex ID */
    igraph_add_vertices(&topology.graph, 1, NULL);

    igraph_integer_t vertex_id = igraph_vcount(&topology.graph) - 1;
    
    /* print information for debugging */

    
    /* set attributes */

    char dpid_str[20];
    snprintf(dpid_str, sizeof(dpid_str), "%" PRIu64, dpid);
    igraph_cattribute_VAS_set(&topology.graph, "dpid", vertex_id, dpid_str);
    
    /* add to the dpid -> vertex map, no mutex lock here */

    add_or_update_dpid(dpid, vertex_id); 

    pthread_mutex_unlock(&topology.lock);
    // log_msg(sw, "MUTEX: Unlocked topology\n");
    
    log_msg(sw, "DEBUG: Graph consistency - vertices: %lld, edges: %lld\n",
           igraph_vcount(&topology.graph), 
           igraph_ecount(&topology.graph));
}


/* add or update a link in the topology */
void add_or_update_link(uint64_t src_dpid, uint16_t src_port, uint64_t dst_dpid, uint16_t dst_port, struct switch_info * sw) {

 

    /* find or add source and destination vertices */
     
    igraph_integer_t src_vertex = find_vertexid(sw, src_dpid);
    igraph_integer_t dst_vertex = find_vertexid(sw, dst_dpid);

    if (src_vertex < 0 || dst_vertex < 0) {
        log_msg(sw, "Failed to find vertex in Vector\n");
        return;
    }
    
    /* check if edge already exists */

    igraph_integer_t edge_id;
    // log_msg(sw, "MUTEX: Locking topology\n");
    pthread_mutex_lock(&topology.lock);
    igraph_get_eid(&topology.graph, &edge_id, src_vertex, dst_vertex, IGRAPH_UNDIRECTED, 0);
    
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

    /* NEW: Add a deterministic weight based on switch DPIDs for consistent path selection */
    double weight = 1.0; // Default weight
    
    // If both switches have even or both have odd DPIDs, reduce weight slightly
    // This creates a preference that's consistent regardless of direction
    if ((src_dpid % 2 == 0 && dst_dpid % 2 == 0) || 
        (src_dpid % 2 != 0 && dst_dpid % 2 != 0)) {
        weight = 0.9;
    }
    
    igraph_cattribute_EAN_set(&topology.graph, "weight", edge_id, weight);


           
    /* print all current edges for verification */
    log_msg(sw, "DEBUG: Current topology has %lld edges:\n", igraph_ecount(&topology.graph));
    for (igraph_integer_t i = 0; i < igraph_ecount(&topology.graph); i++) {
        log_msg(sw, "  Edge %lld: %016" PRIx64 ":%d -> %016" PRIx64 ":%d\n",
               i,
               (uint64_t)EAN(&topology.graph, "src_dpid", i),
               (int)EAN(&topology.graph, "src_port", i),
               (uint64_t)EAN(&topology.graph, "dst_dpid", i),
               (int)EAN(&topology.graph, "dst_port", i));
    }

    pthread_mutex_unlock(&topology.lock);
    // log_msg(sw, "MUTEX: Unlocked topology\n");

}

/* a function to remove a link from the topology */
void remove_links_for_port(uint64_t dpid, uint16_t src_port_no, struct switch_info * sw) {

    log_msg(sw, "Removing links for switch %016" PRIx64 " port %u\n", dpid, src_port_no);

    igraph_integer_t vertex = find_vertexid(sw, dpid);
    log_msg(sw, "igraph vertex: %lld\n", vertex);
    if (vertex < 0) {
        log_msg(sw, "ERROR: Failed to find vertex in Vector\n");
        return; /* vertex not found */
    }

    char src_port_str[20];
    snprintf(src_port_str, sizeof(src_port_str), "%u", src_port_no);

    // log_msg(sw, "MUTEX: Locking topology\n");
    pthread_mutex_lock(&topology.lock);

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
    // (sw, "MUTEX: Unlocked topology\n");

}




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
    
    /* set EtherType to custom type (0x88CC) */
    disc_packet[packet_size++] = 0x88;
    disc_packet[packet_size++] = 0xBA;  
    

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
        log_msg(sw, "ERROR: Failed to allocate memory for packet_out message\n");
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
    
    queue_openflow_msg(sw, po, total_len);
    
    log_msg(sw, "Sent discovery packet from switch port %d\n", port_no);
    
    free(po);
}

/* helper function to verify that a packet is link layer discovery */
bool is_topology_discovery_packet(uint8_t *data, size_t len) {
    // printf("Entering check for topology discovery packet\n");
    if (len < 26){
        printf("Packet too short\n");
        return false;
    }

    /* check EtherType */
    if (data[LLDP_ETHERTYPE_OFFSET] != 0x88 || data[LLDP_ETHERTYPE_OFFSET + 1] != 0xBA){
        printf("EtherType: %02x%02x\n", data[LLDP_ETHERTYPE_OFFSET], data[LLDP_ETHERTYPE_OFFSET + 1]);
        return false;
    }  /* should be right after dst mac and src mac */
    // printf("EtherType correct: %02x%02x\n", data[LLDP_ETHERTYPE_OFFSET], data[LLDP_ETHERTYPE_OFFSET + 1]);
    
    /* check magic number */
    uint32_t magic;
    memcpy(&magic, data + LLDP_MAGIC_OFFSET, 4); /* 14 is dst mac (6) + src mac (6) + type (2) */
    // printf("Magic found: 0x%08x\n", ntohl(magic));
    
    /* check destination MAC is the multicast address */
    uint8_t expected_dst_mac[MAC_ADDR_LEN] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E}; 
    if (memcmp(data, expected_dst_mac, MAC_ADDR_LEN) != 0){
        printf("Dest MAC not multicast: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            data[0], data[1], data[2], data[3], data[4], data[5]);

        return false;
    } /* lldp multicast is ethernet dst */
    
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
    log_msg(sw, "Handling discovery packet for switch %016" PRIx64 "\n", sw->datapath_id);
    uint64_t src_dpid;
    uint16_t src_port;
    uint64_t dst_dpid = sw->datapath_id;
    uint16_t dst_port = ntohs(pi->in_port);

    
    
    /* extract information from discovery packet, passed reference items */
    if (!extract_discovery_packet_info(pi->data, ntohs(pi->total_len), &src_dpid, &src_port)) {
        log_msg(sw, "ERROR: Failed to extract information from discovery packet\n");
        return;
    }
    
    log_msg(sw, "Received discovery packet: Switch %016" PRIx64 " Port %d -> Switch %016" PRIx64 " Port %d\n",
            src_dpid, src_port, dst_dpid, dst_port);
    
    /* update topology with this link information */
    log_msg(sw, "Adding link to topology\n");
    add_or_update_link(src_dpid, src_port, dst_dpid, dst_port, sw);
}

uint64_t vertex_to_dpid(igraph_integer_t vertex_id, struct switch_info *sw) {
    struct dpid_to_vertex_map *entry, *tmp;
    bool found_match = false;
    uint64_t result_dpid = (uint64_t)-1;
    
    log_msg(sw, "DEBUG: Finding dpid for vertex %lld\n", vertex_id);
    
    HASH_ITER(hh, dpids_to_vertex, entry, tmp) {
        if (entry->vertex_id == vertex_id) {
            log_msg(sw, "DEBUG: Found DPID %016" PRIx64 " for vertex %lld\n", 
                   entry->dpid, vertex_id);
            
            // If we've already found a match, log a warning about duplicate mappings
            if (found_match) {
                log_msg(sw, "WARNING: Multiple DPIDs map to vertex ID %lld. Found %016" PRIx64 " and %016" PRIx64 "\n",
                      vertex_id, result_dpid, entry->dpid);
            }
            
            found_match = true;
            result_dpid = entry->dpid;
        }
    }
    
    if (!found_match) {
        log_msg(sw, "DEBUG: No DPID found for vertex %lld\n", vertex_id);
    }
    
    return result_dpid;
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