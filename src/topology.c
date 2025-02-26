#include "controller.h"
#include "topology.h"


void init_topology() {

    /* initialize the topology data structure, global struct */
    topology.links = NULL; 
    topology.num_links = 0;
    topology.capacity = 0;
    pthread_mutex_init(&topology.lock, NULL);
    
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
        topology_cleanup_stale_links();
        
        /* sleep before next discovery round */
        sleep(TOPOLOGY_DISCOVERY_INTERVAL); 
    }
    
    log_msg("Topology discovery thread exiting\n");
    return NULL;
}

void topology_add_link(uint64_t src_dpid, uint16_t src_port, 
                       uint64_t dst_dpid, uint16_t dst_port) {
    pthread_mutex_lock(&topology.lock);
    
    /* check if link already exists */
    int i;
    for (i = 0; i < topology.num_links; i++) {
        if (topology.links[i].src_dpid == src_dpid && 
            topology.links[i].src_port == src_port &&
            topology.links[i].dst_dpid == dst_dpid && 
            topology.links[i].dst_port == dst_port) {
            /* Update last seen time */
            topology.links[i].last_seen = time(NULL);
            pthread_mutex_unlock(&topology.lock);
            return;
        }
    }
    
    /* expand the links array if needed */
    if (topology.num_links >= topology.capacity) {
        int new_capacity = (topology.capacity == 0) ? 16 : topology.capacity * 2;
        struct link *new_links = realloc(topology.links, new_capacity * sizeof(struct link));
        if (!new_links) {
            log_msg("Failed to allocate memory for links\n");
            pthread_mutex_unlock(&topology.lock);
            return;
        }
        topology.links = new_links;
        topology.capacity = new_capacity;
    }
    
    /* add new link */
    struct link *new_link = &topology.links[topology.num_links++];
    new_link->src_dpid = src_dpid;
    new_link->src_port = src_port;
    new_link->dst_dpid = dst_dpid;
    new_link->dst_port = dst_port;
    new_link->last_seen = time(NULL);
    
    log_msg("New link added to topology\n");
    pthread_mutex_unlock(&topology.lock);
}

void topology_cleanup_stale_links() {
    pthread_mutex_lock(&topology.lock);
    time_t now = time(NULL);
    int i = 0;
    
    while (i < topology.num_links) {
        if (now - topology.links[i].last_seen > LINK_TIMEOUT) {

            /* remove stale link */
            log_msg("Removing stale link: Switch %016" PRIx64 " Port %u -> Switch %016" PRIx64 " Port %u\n",
                    topology.links[i].src_dpid, topology.links[i].src_port, 
                    topology.links[i].dst_dpid, topology.links[i].dst_port);
            
            /* move the last link to this position */
            if (i < topology.num_links - 1) {
                topology.links[i] = topology.links[topology.num_links - 1];
            }
            topology.num_links--;
        } else {
            i++;
        }
    }
    
    pthread_mutex_unlock(&topology.lock);
}

/* -------------------------------------------------------- LLDP --------------------------------------------------------------- */
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
    
    /* Copy action and packet data after the header */
    memcpy((uint8_t*)po + sizeof(struct ofp_packet_out), &output, sizeof(output));
    memcpy((uint8_t*)po + sizeof(struct ofp_packet_out) + sizeof(output),
           lldp_packet, packet_size);
    
    /* Send the packet_out message */
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
    
    /* Skip Ethernet header to get to LLDP payload */
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
