#include "controller.h"
#include "topology.h"

#if defined(__linux__)
    #include <endian.h>
#elif defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
    #define htobe64(x) OSSwapHostToBigInt64(x)
    #define be64toh(x) OSSwapBigToHostInt64(x)
#endif

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
    log_msg("Topology discovery thread started\n");
    
    while (running) {
        /* send LLDP packets from all switch ports in global array */
        pthread_mutex_lock(&switches_lock);
        int i;
        for (i = 0; i < MAX_SWITCHES; i++) {
            if (switches[i].active && switches[i].features_received) { /* verify that this slot has an active switch */

                /* iterate over all ports on the switch to discover links on this node */
                int j;
                for (j = 0; j < switches[i].num_ports; j++) {
                    uint16_t port_no = ntohs(switches[i].ports[j].port_no);
                    
                    /* skip non-physical ports */
                    if (port_no >= OFPP_MAX) {
                        continue;
                    }
                    
                    /* skip ports that are down */
                    if (ntohl(switches[i].ports[j].state) & OFPPS_LINK_DOWN) { /* bitwise 'and' verify the port is up */
                        continue;
                    }
                    
                    send_lldp_packet(&switches[i], port_no);
                }
            }
        }
        pthread_mutex_unlock(&switches_lock);
        
        /* clean up stale links */
        // topology_cleanup_stale_links();
        
        /* sleep before next discovery round */
        sleep(TOPOLOGY_DISCOVERY_INTERVAL); 
    }
    
    log_msg("Topology discovery thread exiting\n");
    return NULL;
}

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
    
    /* Look for Chassis ID TLV */
    if (lldp_data[offset] != 0x02 || lldp_data[offset+1] != 0x07) {
        return;  /* Invalid TLV */
    }
    
    /* Extract source datapath_id from Chassis ID TLV */
    uint64_t src_dpid = 0;
    memcpy(((uint8_t*)&src_dpid) + 2, lldp_data + offset + 3, 6);
    src_dpid = be64toh(src_dpid);
    offset += 9;  /* Move to next TLV */
    
    /* Look for Port ID TLV */
    if (lldp_data[offset] != 0x04 || lldp_data[offset+1] != 0x03) {
        return;  /* Invalid TLV */
    }
    
    /* Extract source port */
    uint16_t src_port = (lldp_data[offset+3] << 8) | lldp_data[offset+4];
    
    /* Now we have all the information to identify the link */
    uint16_t dst_port = ntohs(pi->in_port);
    uint64_t dst_dpid = sw->datapath_id;
    
    /* Add the link to our topology */
    topology_add_link(src_dpid, src_port, dst_dpid, dst_port);
    
    log_msg("Link discovered: Switch %016" PRIx64 " Port %u -> Switch %016" PRIx64 " Port %u\n",
            src_dpid, src_port, dst_dpid, dst_port);
            
}

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

void topology_cleanup_stale_links() {

    pthread_mutex_lock(&global_topology.lock);
    time_t now = time(NULL);
    
    struct topology_node *node = global_topology.nodes;
    while (node != NULL) { /* start at the head to prevent infinite loops */
        struct topology_link *prev = NULL;
        struct topology_link *link = node->links; /* copy links to new pointer */
        
        /* iterate through all the links */
        while (link != NULL) {
            if (now - link->last_seen > LINK_TIMEOUT) {

                /* remove stale link */
                struct topology_link *to_remove = link;
                
                if (prev == NULL) {
                    /* if this link is first link in the list */
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
                free(next);
                node->num_links--;
                global_topology.num_links--;
                #ifdef DEBUG
                log_msg("Removed link from switch %016" PRIx64 " port %u to switch %016" PRIx64 " port %u\n",
                                                        dpid, port_no, next->linked_dpid, next->linked_port);
                #endif
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
