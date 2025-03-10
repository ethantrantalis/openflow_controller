#include "controller.h"
#include "topology.h"


/*
┌───────────────────────────────────────────────────────────────────────┐
│                           CONTROLLER                                  │
│                                                                       │
│  ┌───────────────────┐    ┌───────────────────┐    ┌───────────────┐  │
│  │ Topology Manager  │    │ Path Calculator   │    │ Flow Manager  │  │
│  │                   │    │                   │    │               │  │
│  │ - Builds graph    │───>│ - Dijkstra's      │───>│ - Creates     │  │
│  │ - Tracks links    │    │ - MST             │    │   flow rules  │  │
│  │ - Updates state   │    │ - Path caching    │    │ - Sends to    │  │
│  └───────────────────┘    └───────────────────┘    │   switches    │  │
│            ▲                                       └───────────────┘  │
│            │                                                 │        │
└────────────┼─────────────────────────────────────────────────┼────────┘
             │                                                 │
             │ PACKET_IN, LLDP, PORT_STATUS                    │ FLOW_MOD, PACKET_OUT
             │                                                 │
┌────────────┼─────────────────────────────────────────────────┼────────┐
│            │                                                 ▼        │
│   ┌────────┴───────┐     ┌───────────────┐     ┌───────────────────┐  │
│   │ Switch A       │     │ Switch B      │     │ Switch C          │  │
│   │                │     │               │     │                   │  │
│   │  Flow Table:   │     │  Flow Table:  │     │  Flow Table:      │  │
│   │  dst=MAC_X →   │────>│  dst=MAC_X →  │────>│  dst=MAC_X →      │  │
│   │  forward(port2)│     │ forward(port3)│     │ forward(port1)    │  │
│   └────────────────┘     └───────────────┘     └───────────────────┘  │
│                                                                       │
│                              NETWORK                                  │
└───────────────────────────────────────────────────────────────────────┘



*/




#if defined(__linux__)
    #include <endian.h>
#elif defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
    #define htobe64(x) OSSwapHostToBigInt64(x)
    #define be64toh(x) OSSwapBigToHostInt64(x)
#endif

/* -------------------------------------------------- Top Topology Functions --------------------------------------------------- */

void init_topology() {

    /* initialize the topology data structure, global struct */
    global_topology.nodes = NULL; 
    global_topology.num_links = 0;
    global_topology.capacity = 0;
    pthread_mutex_init(&global_topology.lock, NULL);
    
    /* start the topology discovery thread */
    if (pthread_create(&topology_thread, NULL, topology_discovery_loop, NULL) != 0) {
        perror("Failed to create topology thread");
        exit(1);
    }

}

void *topology_discovery_loop(void *arg) {

    /* for each switch in the switches array, an LLDP packet will be send out for all the ports 
     * then it will gain info on what is connected to that port and keep an up to data vision 
     * of the topology
     * 
     * this relies on port status changes being handled properly so that when a switch joins, leaves
     * or changes where it is connected then the topology will account for that
     * 
     * this is not an event triggered loop it will itterate over all the ports everytime this runs
     * 
     * */

    log_msg("Topology discovery thread started\n");

    int discovery_counter = 0;
    
    while (running) {

        /* full discovery every minute */
        bool do_full_discovery = (discovery_counter++ % 6 == 0);
        
        pthread_mutex_lock(&switches_lock);
        
        int i;
        for (i = 0; i < MAX_SWITCHES; i++) {
            if (switches[i].active && switches[i].features_received) {
                struct switch_info *sw = &switches[i];
                
                /* get list of ports to explore */
                uint16_t ports_to_explore[MAX_SWITCH_PORTS];
                int num_ports_to_explore = 0;
                
                if (do_full_discovery) {

                    /* full discovery - include all ports */
                    int j; 
                    for (j = 0; j < sw->num_ports; j++) {
                        uint16_t port_no = ntohs(sw->ports[j].port_no);
                        
                        /* skip non-physical ports or down ports */
                        if (port_no >= OFPP_MAX || 
                            (ntohl(sw->ports[j].state) & OFPPS_LINK_DOWN)) {
                            continue;
                        }
                        
                        ports_to_explore[num_ports_to_explore++] = port_no;
                    }
                } else {
                    /* targeted discovery - only modified ports */
                    pthread_mutex_lock(&sw->modified_ports_lock);
                    
                    int j;
                    for (j = 0; j < sw->num_modified_ports; j++) {
                        uint16_t port_no = sw->modified_ports[j];
                        
                        /* find the port in the ports array to check if it's still up */
                        int k;
                        for (k = 0; k < sw->num_ports; k++) {
                            if (ntohs(sw->ports[k].port_no) == port_no) {
                                // Only include if port is still up
                                if (!(ntohl(sw->ports[k].state) & OFPPS_LINK_DOWN)) {
                                    ports_to_explore[num_ports_to_explore++] = port_no;
                                }
                                break;
                            }
                        }
                    }
                    
                    /* clear the modified ports list */
                    sw->num_modified_ports = 0;
                    
                    pthread_mutex_unlock(&sw->modified_ports_lock);
                }
                
                /* send LLDP on all ports in the exploration list */
                int j;
                for (j = 0; j < num_ports_to_explore; j++) {
                    send_lldp_packet(sw, ports_to_explore[j]);
                }
            }
        }
        
        pthread_mutex_unlock(&switches_lock);
        
        topology_cleanup_stale_links();
        
        sleep(TOPOLOGY_DISCOVERY_INTERVAL);
    }


    
    printf("Topology discovery thread exiting\n");

    while(global_topology.nodes != NULL){
        struct topology_node *node = global_topology.nodes;
        global_topology.nodes = node->next;
        while(node->links != NULL){
            struct topology_link *link = node->links;
            node->links = link->next;
            free(link);
        }
        free(node);
    }
    printf("Freed global topology\n");
    return NULL;
}

/* ---------------------------------------------- End Top Topology Functions --------------------------------------------------- */

/* --------------------------------------------------------- LLDP -------------------------------------------------------------- */
void send_lldp_packet(struct switch_info *sw, uint16_t port_no) {
    
    /* create an LLDP packet on the stack */
    uint8_t lldp_packet[LLDP_PACKET_SIZE] = {0};
    int packet_size = 0;

    /* ethernet header */
    memcpy(lldp_packet, LLDP_MULTICAST_ADDR, ETHERNET_ADDR_LEN); /* dst MAC */
    memcpy(lldp_packet + ETHERNET_ADDR_LEN, sw->ports[port_no].hw_addr, ETHERNET_ADDR_LEN); /* src MAC */
    lldp_packet[12] = LLDP_ETHERTYPE >> 8; /* EtherType */
    lldp_packet[13] = LLDP_ETHERTYPE & 0xFF;
    packet_size = 14;
    
    /* switch ID (datapath_id) - 8 bytes */
    uint64_t dpid_net = htobe64(sw->datapath_id);
    memcpy(lldp_packet + packet_size, &dpid_net, 8);  
    packet_size += 8;
    
    /* port number - 2 bytes */
    uint16_t port_net = htons(port_no);
    memcpy(lldp_packet + packet_size, &port_net, 2);  
    packet_size += 2;
    
    /* create PACKET_OUT message */

    /* create the output action which commands the switch to send out a physical port */
    struct ofp_action_output output;
    memset(&output, 0, sizeof(output));
    output.type = htons(OFPAT_OUTPUT);
    output.len = htons(sizeof(output));
    output.port = htons(port_no);
    output.max_len = htons(0); /* Not relevant for output */
    
    /* create the packet_out message */
    int total_len = sizeof(struct ofp_packet_out) + sizeof(output) + packet_size;
    struct ofp_packet_out *po = malloc(total_len); /* oversized malloc for space after packet out */
    if (!po) {
        log_msg("Error: Failed to allocate memory for packet_out message\n");
        return;
    }
    memset(po, 0, total_len);
    po->header.version = OFP_VERSION;
    po->header.type = OFPT_PACKET_OUT;
    po->header.length = htons(total_len);
    po->header.xid = htonl(rand());
    po->buffer_id = htonl(0xFFFFFFFF); /* OFP_NO_BUFFER */
    po->in_port = htons(OFPP_NONE);
    po->actions_len = htons(sizeof(output));
    
    /* copy action and packet data after the header */
    memcpy((uint8_t*)po + sizeof(struct ofp_packet_out), &output, sizeof(output));
    memcpy((uint8_t*)po + sizeof(struct ofp_packet_out) + sizeof(output),
           lldp_packet, packet_size);
    
    /* send the packet_out message */
    send_openflow_msg(sw, po, total_len);
    free(po);
}

bool is_lldp_packet(uint8_t *data) {
    /* check for LLDP EtherType (0x88CC) */
    return (data[12] == (LLDP_ETHERTYPE >> 8) && 
            data[13] == (LLDP_ETHERTYPE & 0xFF));
}

void handle_lldp_packet(struct switch_info *sw, struct ofp_packet_in *pi) {

    /* get total packet length from header */
    uint16_t total_packet_length = ntohs(pi->header.length);

    /* this represents all the fields before the variable-length data portion */
    uint16_t header_overhead = sizeof(struct ofp_packet_in);

    /* calculate actual data length by subtracting header overhead */
    uint16_t data_length = total_packet_length - header_overhead;
    uint8_t *data = pi->data;
    
    /* we need at least an Ethernet header plus LLDP TLVs */
    if (data_length < 30) {
        return;
    }
    
    /* skip Ethernet header to get to LLDP payload */
    uint8_t *lldp_data = data + 14;
    int offset = 0;
    
    /* look for Chassis ID TLV */
    if (lldp_data[offset] != 0x02 || lldp_data[offset+1] != 0x07) {
        return;  /* Invalid TLV */
    }
    
    /* extract source datapath_id from Chassis ID TLV */
    uint64_t src_dpid = 0;
    memcpy(((uint8_t*)&src_dpid) + 2, lldp_data + offset + 3, 6);
    src_dpid = be64toh(src_dpid);
    offset += 9;  /* Move to next TLV */
    
    /* look for Port ID TLV */
    if (lldp_data[offset] != 0x04 || lldp_data[offset+1] != 0x03) {
        return;  /* Invalid TLV */
    }
    
    /* extract source port */
    uint16_t src_port = (lldp_data[offset+3] << 8) | lldp_data[offset+4];
    
    /* now we have all the information to identify the link */
    uint16_t dst_port = ntohs(pi->in_port);
    uint64_t dst_dpid = sw->datapath_id;
    
    /* add the link to our topology */
    topology_add_link(src_dpid, src_port, dst_dpid, dst_port);
    
    log_msg("Link discovered: Switch %016" PRIx64 " Port %u -> Switch %016" PRIx64 " Port %u\n",
            src_dpid, src_port, dst_dpid, dst_port);
            
}

/* -------------------------------------------------------- End LLDP ------------------------------------------------------------ */

/* ---------------------------------------------- Topology Helper Functions ----------------------------------------------------- */
struct topology_node* find_or_create_node(uint64_t dpid) {
    pthread_mutex_lock(&global_topology.lock);
    
    /* check if node already exists */
    struct topology_node *current = global_topology.nodes;
    while (current != NULL) {
        if (current->dpid == dpid) {
            pthread_mutex_unlock(&global_topology.lock);
            return current;
        }
        current = current->next;
    }
    
    /* if node doesnt exist create a new one */
    struct topology_node *new_node = malloc(sizeof(struct topology_node));
    if (!new_node) {
        log_msg("Error: Failed to allocate memory for new node\n");
        pthread_mutex_unlock(&global_topology.lock);
        return NULL;
    }
    
    new_node->dpid = dpid;
    new_node->num_links = 0;
    new_node->links = NULL;
    new_node->next = global_topology.nodes;  /* add at the beginning for efficiency */
    global_topology.nodes = new_node;
    global_topology.num_nodes++;
    
    pthread_mutex_unlock(&global_topology.lock);
    return new_node;
}

int topology_add_link(uint64_t src_dpid, uint16_t src_port, uint64_t dst_dpid, uint16_t dst_port) {

    /* find or create source node */
    struct topology_node *src_node = find_or_create_node(src_dpid);
    if (!src_node) {
        return -1;
    }
    
    pthread_mutex_lock(&global_topology.lock);
    
    /* check if link already exists */
    struct topology_link *link = src_node->links;
    while (link != NULL) {
        if (link->node_port == src_port && 
            link->linked_dpid == dst_dpid && 
            link->linked_port == dst_port) {
            /* update timestamp if link is found */
            link->last_seen = time(NULL);
            pthread_mutex_unlock(&global_topology.lock);
            return 0;
        }
        link = link->next;
    }
    
    /* create new link if not already created */
    struct topology_link *new_link = malloc(sizeof(struct topology_link));
    if (!new_link) {
        log_msg("Error: Failed to allocate memory for new link\n");
        pthread_mutex_unlock(&global_topology.lock);
        return -1;
    }
    
    new_link->node_port = src_port;
    new_link->linked_dpid = dst_dpid;
    new_link->linked_port = dst_port;
    new_link->last_seen = time(NULL);
    new_link->next = src_node->links;  /* add at the beginning for efficieny */
    src_node->links = new_link;
    src_node->num_links++;
    global_topology.num_links++;
    
    pthread_mutex_unlock(&global_topology.lock);
    
    log_msg("Added link: Switch %016" PRIx64 " Port %u -> Switch %016" PRIx64 " Port %u\n",
            src_dpid, src_port, dst_dpid, dst_port);
    
    return 0;
}

/* function mostly to remove links that have been timed out */
void topology_cleanup_stale_links() {
    pthread_mutex_lock(&global_topology.lock);
    time_t now = time(NULL);
    
    struct topology_node *node = global_topology.nodes;
    while (node != NULL) {
        struct topology_link *prev = NULL;
        struct topology_link *link = node->links;
        
        while (link != NULL) {
            if (now - link->last_seen > LINK_TIMEOUT) {


                /* find the switch that owns this node to mark the port as modified*/
                struct switch_info *sw = NULL;
                pthread_mutex_lock(&switches_lock);
                int i;
                for (i = 0; i < MAX_SWITCHES; i++) {
                    if (switches[i].active && switches[i].datapath_id == node->dpid) {
                        sw = &switches[i];
                        break;
                    }
                }
                
                /* found the switch, mark the port as modified */
                if (sw) {
                    mark_port_modified(sw, link->node_port);
                    log_msg("Marked port %u on switch %016" PRIx64 " as modified after stale link removal\n", 
                           link->node_port, node->dpid);
                }
                pthread_mutex_unlock(&switches_lock);
                
                /* find the destination switch and mark its port */
                sw = NULL;
                pthread_mutex_lock(&switches_lock);
                for (int i = 0; i < MAX_SWITCHES; i++) {
                    if (switches[i].active && switches[i].datapath_id == link->linked_dpid) {
                        sw = &switches[i];
                        break;
                    }
                }
                
                /* mark its port as modified */
                if (sw) {
                    mark_port_modified(sw, link->linked_port);
                    log_msg("Marked port %u on switch %016" PRIx64 " as modified after stale link removal\n", 
                           link->linked_port, link->linked_dpid);
                }
                pthread_mutex_unlock(&switches_lock);
                
                /* remove stale link */
                struct topology_link *to_remove = link;
                
                if (prev == NULL) {
                    node->links = link->next;
                } else {
                    prev->next = link->next;
                }
                
                link = link->next;
                free(to_remove);
                node->num_links--;
                global_topology.num_links--;
                
                log_msg("Removed stale link from node %016" PRIx64 "\n", node->dpid);
            } else {
                prev = link;
                link = link->next;
            }
        }
        
        node = node->next;
    }
    
    pthread_mutex_unlock(&global_topology.lock);
}

/* helper function for removing links in a */
void topology_remove_link(uint64_t dpid, uint16_t port_no){

    /* ensure that no other devices can modify the topology */
    pthread_mutex_lock(&global_topology.lock);
    
    struct topology_node *node = global_topology.nodes;
    while (node != NULL){
        if (node->dpid == dpid){ /* found the switch node associated with link to remove */
        struct topology_link *prev = NULL;
        struct topology_link *next = node->links;

        while (next != NULL){

            /* found the link that needs to be removed */
            if (next->node_port == port_no){
                if (prev == NULL){
                    node->links = next->next; /* set head of links to be next if start was null */
                } else {
                    prev->next = next->next; /* set previous link to point to next link */
                }
                
                #ifdef DEBUG
                log_msg("Removed link from switch %016" PRIx64 " port %u to switch %016" PRIx64 " port %u\n",
                                                        dpid, port_no, next->linked_dpid, next->linked_port);
                #endif
                free(next);
                node->num_links--;
                global_topology.num_links--;
                break;
            }
            prev = next;
            next = next->next;
        }
        }
    }

    if (node == NULL){
        log_msg("Error: Switch %016" PRIx64 " not found in topology\n", dpid);
    }
    
    pthread_mutex_unlock(&global_topology.lock);
}

/* find a node in the topology by datapath ID */
struct topology_node* find_node(uint64_t dpid) {
    pthread_mutex_lock(&global_topology.lock);
    
    struct topology_node *current = global_topology.nodes;
    while (current != NULL) {
        if (current->dpid == dpid) {
            pthread_mutex_unlock(&global_topology.lock);
            return current;
        }
        current = current->next;
    }
    
    pthread_mutex_unlock(&global_topology.lock);
    return NULL; /* node not found */
}

/* --------------------------------------------- End Topology Helper Functions --------------------------------------------------- */

/* -------------------------------------------------------- Path Calculation Functions ------------------------------------------- */

struct path* calculate_shortest_path(uint64_t src_dpid, uint64_t dst_dpid) {
    /* assumption: all edge weights are 1 */

    pthread_mutex_lock(&global_topology.lock);
    
    /* create distance and visited tracking */
    struct distance_entry {
        uint64_t dpid;
        int distance;
        uint64_t prev_dpid;
        uint16_t prev_port;
        uint16_t next_port;
        bool visited;
    };
    
    /* initialize distances */
    struct distance_entry *distances = malloc(global_topology.num_nodes * sizeof(struct distance_entry));
    if (!distances) {
        log_msg("Error: Failed to allocate memory for Dijkstra's algorithm\n");
        pthread_mutex_unlock(&global_topology.lock);
        return NULL;
    }
    
    int count = 0;
    struct topology_node *node = global_topology.nodes;
    
    /* initialize all nodes with infinite distance */
    while (node != NULL) {
        distances[count].dpid = node->dpid;
        distances[count].distance = INT_MAX;
        distances[count].prev_dpid = 0;
        distances[count].prev_port = 0;
        distances[count].next_port = 0;
        distances[count].visited = false;
        
        /* set source distance to 0 */
        if (node->dpid == src_dpid) {
            distances[count].distance = 0;
        }
        
        count++;
        node = node->next;
    }
    
    /* dijkstra's algorithm */
    int i;
    for (i = 0; i < global_topology.num_nodes; i++) {
        /* find node with minimum distance */
        int min_dist = INT_MAX;
        int min_idx = -1;
        int j;
        for (j = 0; j < global_topology.num_nodes; j++) {
            if (!distances[j].visited && distances[j].distance < min_dist) {
                min_dist = distances[j].distance;
                min_idx = j;
            }
        }
        
        if (min_idx == -1) break; /* no reachable nodes left*/
        
        /* mark as visited */
        distances[min_idx].visited = true;
        
        /* find the node in the topology */
        struct topology_node *current = find_node(distances[min_idx].dpid);
        if (!current) continue;
        
        /* check all adjacent nodes */
        struct topology_link *link = current->links;
        while (link != NULL) {

            /* find the adjacent node in our distances array */
            int adj_idx = -1;
            int j;
            for (j = 0; j < global_topology.num_nodes; j++) {
                if (distances[j].dpid == link->linked_dpid) {
                    adj_idx = j;
                    break;
                }
            }
            
            if (adj_idx != -1 && !distances[adj_idx].visited) {
                /* update distance if shorter path found */
                int alt_dist = distances[min_idx].distance + 1; /* assuming all links have weight 1 */
                if (alt_dist < distances[adj_idx].distance) {
                    distances[adj_idx].distance = alt_dist;
                    distances[adj_idx].prev_dpid = distances[min_idx].dpid;
                    distances[adj_idx].prev_port = link->node_port;
                    
                    /* find the port on the destination that connects back */
                    struct topology_node *adj_node = find_node(link->linked_dpid);
                    if (adj_node) {
                        struct topology_link *adj_link = adj_node->links;
                        while (adj_link != NULL) {
                            if (adj_link->linked_dpid == current->dpid) {
                                distances[adj_idx].next_port = adj_link->node_port;
                                break;
                            }
                            adj_link = adj_link->next;
                        }
                    }
                }
            }
            
            link = link->next;
        }
    }
    
    /* construct the path from source to destination */
    struct path *result = NULL;
    
    /* find destination in distances */
    int dst_idx = -1;
    int i;
    for (i = 0; i < global_topology.num_nodes; i++) {
        if (distances[i].dpid == dst_dpid) {
            dst_idx = i;
            break;
        }
    }
    
    if (dst_idx != -1 && distances[dst_idx].distance != INT_MAX) {

        /* reconstruct path */

        struct path_node *path_head = NULL;
        uint64_t current_dpid = dst_dpid;
        
        while (current_dpid != src_dpid) {

            /* find current node in distances */
            int curr_idx = -1;
            for (int i = 0; i < global_topology.num_nodes; i++) {
                if (distances[i].dpid == current_dpid) {
                    curr_idx = i;
                    break;
                }
            }
            
            if (curr_idx == -1) break; /* error in path */
            
            // Add to path
            struct path_node *node = malloc(sizeof(struct path_node));
            if (!node) {
                log_msg("Error: Failed to allocate memory for path node\n");
                break;
            }
            
            node->dpid = current_dpid;
            node->in_port = distances[curr_idx].next_port;
            node->out_port = distances[curr_idx].prev_port;
            node->next = path_head;
            path_head = node;
            
            current_dpid = distances[curr_idx].prev_dpid;
        }
        
        /* add source node */
        struct path_node *src_path_node = malloc(sizeof(struct path_node));
        if (src_path_node) {
            src_path_node->dpid = src_dpid;
            src_path_node->in_port = 0; /* not used for source */
            if (path_head)
                src_path_node->out_port = path_head->in_port;
            else
                src_path_node->out_port = 0;
            src_path_node->next = path_head;
            path_head = src_path_node;
        } else {
            log_msg("Error: Failed to allocate memory for source path node\n");
            struct path_node *node = path_head;
            while (node) {
                struct path_node *next = node->next;
                free(node);
                node = next;
            }
        }
        
        /* create the result */
        result = malloc(sizeof(struct path));

        if (result) {
            result->length = distances[dst_idx].distance + 1;
            result->nodes = path_head;
        } else {

            /* free the path nodes */
            log_msg("Error: Failed to allocate memory for path result");
            struct path_node *node = path_head;
            while (node) {
                struct path_node *next = node->next;
                free(node);
                node = next;
            }
        }
    }
    
    free(distances);
    pthread_mutex_unlock(&global_topology.lock);
    return result;
}

/* calculate a Minimum Spanning Tree */
struct mst* calculate_mst(uint64_t root_dpid) {
    pthread_mutex_lock(&global_topology.lock);
    
    /* struct for Prim Algorithm */
    struct mst_entry {
        uint64_t dpid;
        bool in_mst;
        uint64_t parent_dpid;
        uint16_t parent_port;
        uint16_t child_port;
    };
    
    /* initialize MST entries */
    struct mst_entry *mst_nodes = malloc(global_topology.num_nodes * sizeof(struct mst_entry));
    if (!mst_nodes) {
        log_msg("Error: Failed to allocate memory for MST calculation\n");
        pthread_mutex_unlock(&global_topology.lock);
        return NULL;
    }
    
    int count = 0;
    struct topology_node *node = global_topology.nodes;
    
    /* initialize all nodes */
    while (node != NULL) {
        mst_nodes[count].dpid = node->dpid;
        mst_nodes[count].in_mst = false;
        mst_nodes[count].parent_dpid = 0;
        mst_nodes[count].parent_port = 0;
        mst_nodes[count].child_port = 0;
        
        /* set root node as first node in MST */
        if (node->dpid == root_dpid) {
            mst_nodes[count].in_mst = true;
        }
        
        count++;
        node = node->next;
    }
    
    /* prim's algorithm */
    int nodes_in_mst = 1; /* start with root */
    
    while (nodes_in_mst < global_topology.num_nodes) {
        int min_weight = INT_MAX;
        int min_src_idx = -1;
        int min_dst_idx = -1;
        uint16_t min_src_port = 0;
        uint16_t min_dst_port = 0;
        
        /* find the minimum weight edge from MST to non-MST vertex */
        for (int i = 0; i < global_topology.num_nodes; i++) {
            if (mst_nodes[i].in_mst) {
                /* find the node in the topology */
                struct topology_node *current = find_node(mst_nodes[i].dpid);
                if (!current) continue;
                
                /* check all adjacent nodes */
                struct topology_link *link = current->links;
                while (link != NULL) {
                    /* find the adjacent node in our MST array */
                    int adj_idx = -1;
                    for (int j = 0; j < global_topology.num_nodes; j++) {
                        if (mst_nodes[j].dpid == link->linked_dpid) {
                            adj_idx = j;
                            break;
                        }
                    }
                    
                    if (adj_idx != -1 && !mst_nodes[adj_idx].in_mst) {
                        /* assuming all links have weight 1 for simplicity */
                        int weight = 1;
                        
                        if (weight < min_weight) {
                            min_weight = weight;
                            min_src_idx = i;
                            min_dst_idx = adj_idx;
                            min_src_port = link->node_port;
                            
                            /* find the port on the destination that connects back */
                            struct topology_node *adj_node = find_node(link->linked_dpid);
                            if (adj_node) {
                                struct topology_link *adj_link = adj_node->links;
                                while (adj_link != NULL) {
                                    if (adj_link->linked_dpid == current->dpid) {
                                        min_dst_port = adj_link->node_port;
                                        break;
                                    }
                                    adj_link = adj_link->next;
                                }
                            }
                        }
                    }
                    
                    link = link->next;
                }
            }
        }
        
        if (min_src_idx != -1 && min_dst_idx != -1) {
            /* add the minimum edge to MST */
            mst_nodes[min_dst_idx].in_mst = true;
            mst_nodes[min_dst_idx].parent_dpid = mst_nodes[min_src_idx].dpid;
            mst_nodes[min_dst_idx].parent_port = min_dst_port;
            mst_nodes[min_dst_idx].child_port = min_src_port;
            nodes_in_mst++;
        } else {
            /* graph is not fully connected */
            break;
        }
    }
    
    /* construct the MST result */
    struct mst *result = malloc(sizeof(struct mst));
    if (!result) {
        log_msg("Error: Failed to allocate memory for MST result");
        free(mst_nodes);
        pthread_mutex_unlock(&global_topology.lock);
        return NULL;
    }
    
    result->root_dpid = root_dpid;
    result->num_nodes = nodes_in_mst;
    
    /* create array of MST nodes */
    result->nodes = malloc(nodes_in_mst * sizeof(struct mst_node));
    if (!result->nodes) {
        log_msg("Error: Failed to allocate memory for MST nodes");
        free(result);
        free(mst_nodes);
        pthread_mutex_unlock(&global_topology.lock);
        return NULL;
    }
    
    /* fill in the MST nodes */
    int mst_idx = 0;
    for (int i = 0; i < global_topology.num_nodes && mst_idx < nodes_in_mst; i++) {
        if (mst_nodes[i].in_mst) {
            result->nodes[mst_idx].dpid = mst_nodes[i].dpid;
            result->nodes[mst_idx].parent_dpid = mst_nodes[i].parent_dpid;
            result->nodes[mst_idx].parent_port = mst_nodes[i].parent_port;
            
            /* count and collect children */
            int child_count = 0;
            for (int j = 0; j < global_topology.num_nodes; j++) {
                if (mst_nodes[j].in_mst && mst_nodes[j].parent_dpid == mst_nodes[i].dpid) {
                    child_count++;
                }
            }
            
            result->nodes[mst_idx].num_children = child_count;
            if (child_count > 0) {
                result->nodes[mst_idx].child_ports = malloc(child_count * sizeof(uint16_t));
                if(!result->nodes[mst_idx].child_ports) {
                    log_msg("Error: Failed to allocate memory for MST child ports");
                    free(result->nodes);
                    free(result);
                    free(mst_nodes);
                    pthread_mutex_unlock(&global_topology.lock);
                    return NULL;
                }
                if (result->nodes[mst_idx].child_ports) {
                    int cp_idx = 0;
                    for (int j = 0; j < global_topology.num_nodes && cp_idx < child_count; j++) {
                        if (mst_nodes[j].in_mst && mst_nodes[j].parent_dpid == mst_nodes[i].dpid) {
                            result->nodes[mst_idx].child_ports[cp_idx++] = mst_nodes[j].child_port;
                        }
                    }
                }
            } else {
                result->nodes[mst_idx].child_ports = NULL;
            }
            
            mst_idx++;
        }
    }
    
    free(mst_nodes);
    pthread_mutex_unlock(&global_topology.lock);
    return result;
}

/* ------------------------------------------------------ End Path Calculation Functions ------------------------------------------ */

