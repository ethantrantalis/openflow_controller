#include "controller.h"
#include "communication.h"

/* ------------------------------------------------ Packet Handler Functions --------------------------------------------------- */

/* handle incoming OpenFlow message, see while loop in switch handler */
void handle_switch_message(struct switch_info *sw, uint8_t *msg, size_t len) {
    struct ofp_header *oh = (struct ofp_header *)msg;
    
    /* verify message length */
    if (len < sizeof(*oh)) {
        log_msg("Message too short\n");
        return;
    }
    
    /* Hhndle based on message type */
    switch (oh->type) {
        case OFPT_HELLO:
            handle_hello(sw, oh);
            break;
            
        case OFPT_ECHO_REQUEST:
            handle_echo_request(sw, oh);
            break;
            
        case OFPT_ECHO_REPLY:
            handle_echo_reply(sw, oh);
            break;
            
        case OFPT_FEATURES_REPLY:
            handle_features_reply(sw, (struct ofp_switch_features *)msg);
            sw->features_received = 1;
            break;
            
        case OFPT_PACKET_IN:
            handle_packet_in(sw, (struct ofp_packet_in *)msg);
            break;
            
        case OFPT_PORT_STATUS:
            handle_port_status(sw, (struct ofp_port_status *)msg);
            break;
            
        default:
            log_msg("Unhandled message type: %d\n", oh->type);
    }
}

/* handle HELLO message */
void handle_hello(struct switch_info *sw, struct ofp_header *oh) {
    sw->version = oh->version;
    sw->hello_received = 1;  /* mark HELLO as received */
    log_msg("Switch hello received, version 0x%02x\n", sw->version);
    
    /* only send features request after HELLO exchange is complete */
    if (sw->version == OFP_VERSION) {
        send_features_request(sw);
    } else {
        /* version mismatch - should send error */
        struct ofp_error_msg error;
        error.header.version = OFP_VERSION;
        error.header.type = OFPT_ERROR;
        error.header.length = htons(sizeof(error));
        error.header.xid = oh->xid;
        error.type = htons(OFPET_HELLO_FAILED);
        error.code = htons(OFPHFC_INCOMPATIBLE);
        send_openflow_msg(sw, &error, sizeof(error));
        sw->active = 0;  /* mark for disconnection */
    }
}

/* handle echo requests/replies */
void handle_echo_request(struct switch_info *sw, struct ofp_header *oh) {
    struct ofp_header echo;
    
    /* simply change the type to reply and send it back */
    memcpy(&echo, oh, sizeof(echo));
    echo.type = OFPT_ECHO_REPLY;
    
    send_openflow_msg(sw, &echo, sizeof(echo));
}

/* handle features reply */
void handle_features_reply(struct switch_info *sw, struct ofp_switch_features *features) {
    sw->datapath_id = be64toh(features->datapath_id);
    sw->n_tables = features->n_tables;
    
    /* calculate number of ports */
    size_t port_list_len = ntohs(features->header.length) - sizeof(*features);
    int num_ports = port_list_len / sizeof(struct ofp_phy_port);
    
    /* store port information */
    sw->ports = malloc(port_list_len);
    if (sw->ports) {
        memcpy(sw->ports, features->ports, port_list_len);
        sw->num_ports = num_ports;
    }
    
    log_msg("\nSwitch features:\n");
    log_msg("  Datapath ID: %016" PRIx64 "\n", sw->datapath_id);
    log_msg("  OpenFlow version: 0x%02x\n", sw->version);
    log_msg("  Number of tables: %d\n", sw->n_tables);
    log_msg("  Number of buffers: %d\n", ntohl(features->n_buffers));
    log_msg("  Number of ports: %d\n", num_ports);
    
    /* print capabilities for debugging purposes */
    log_msg("  Capabilities:\n");
    uint32_t capabilities = ntohl(features->capabilities);
    if (capabilities & OFPC_FLOW_STATS)    log_msg("    - Flow statistics\n");
    if (capabilities & OFPC_TABLE_STATS)   log_msg("    - Table statistics\n");
    if (capabilities & OFPC_PORT_STATS)    log_msg("    - Port statistics\n");
    if (capabilities & OFPC_STP)           log_msg("    - 802.1d spanning tree\n");
    if (capabilities & OFPC_IP_REASM)      log_msg("    - IP reasm\n");
    if (capabilities & OFPC_QUEUE_STATS)   log_msg("    - Queue statistics\n");
    if (capabilities & OFPC_ARP_MATCH_IP)  log_msg("    - ARP match IP\n");
    
    /* Print ports for debugging purposes */
    int i;
    for (i= 0; i < num_ports; i++) {
        struct ofp_phy_port *port = &sw->ports[i];
        log_msg("\nPort %d:\n", ntohs(port->port_no));
        log_msg("  Name: %s\n", port->name);
        log_msg("  HW Addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
                port->hw_addr[0], port->hw_addr[1], port->hw_addr[2],
                port->hw_addr[3], port->hw_addr[4], port->hw_addr[5]);
        
        /* print port state */
        if (ntohl(port->state) & OFPPS_LINK_DOWN)
            log_msg("  State: Link down\n");
        else
            log_msg("  State: Link up\n");
            
        /* print port features */
        uint32_t curr = ntohl(port->curr);
        log_msg("  Current features:\n");
        if (curr & OFPPF_10MB_HD)    log_msg("    - 10Mb half-duplex\n");
        if (curr & OFPPF_10MB_FD)    log_msg("    - 10Mb full-duplex\n");
        if (curr & OFPPF_100MB_HD)   log_msg("    - 100Mb half-duplex\n");
        if (curr & OFPPF_100MB_FD)   log_msg("    - 100Mb full-duplex\n");
        if (curr & OFPPF_1GB_HD)     log_msg("    - 1Gb half-duplex\n");
        if (curr & OFPPF_1GB_FD)     log_msg("    - 1Gb full-duplex\n");
        if (curr & OFPPF_10GB_FD)    log_msg("    - 10Gb full-duplex\n");
        if (curr & OFPPF_COPPER)     log_msg("    - Copper\n");
        if (curr & OFPPF_FIBER)      log_msg("    - Fiber\n");
        if (curr & OFPPF_AUTONEG)    log_msg("    - Auto-negotiation\n");
        if (curr & OFPPF_PAUSE)      log_msg("    - Pause\n");
        if (curr & OFPPF_PAUSE_ASYM) log_msg("    - Asymmetric pause\n");
    }
}

/* handle echo reply messages */
void handle_echo_reply(struct switch_info *sw, struct ofp_header *oh) {
    pthread_mutex_lock(&sw->lock);
    
    /* update both last reply and last echo time */
    sw->last_echo_reply = time(NULL);
    sw->echo_pending = false;  /* Mark that anothe echo can be send, meaning echos have vbeen recienved */

    /* for debugging */
    #ifdef DEBUG
    log_msg("Echo reply received from switch %016" PRIx64 " (XID: %u)\n", 
            sw->datapath_id, ntohl(oh->xid));
    #endif
    
    pthread_mutex_unlock(&sw->lock);
}

/* handle port status changes */
void handle_port_status(struct switch_info *sw, struct ofp_port_status *ps) {
    if (!ps) {
        log_msg("Error: Null port_status message\n");
        return;
    }

    pthread_mutex_lock(&sw->lock);
    
    /* increment port change counter */
    sw->port_changes++;
    
    /* get the port description */
    struct ofp_phy_port *port = &ps->desc;
    
    /* convert port state to string */
    const char *state_str;
    if (ntohl(port->state) & OFPPS_LINK_DOWN) {
        state_str = "DOWN";
    } else {
        state_str = "UP";
    }
    
    /* convert reason to string */
    const char *reason_str;
    switch (ps->reason) {
        case OFPPR_ADD:
            reason_str = "PORT ADDED";
            /* DISCOVER NEW DEVICE ON THAT PORT HERE */
            send_lldp_packet(sw, ntohs(port->port_no));
            break;
        case OFPPR_DELETE:
            reason_str = "PORT REMOVED";
            /* FIND THE SWITCH IN TOPOLGY AND REMOVE THE PORT FOR IT */
            topology_remove_link(sw->datapath_id, ntohs(port->port_no));
            break;
        case OFPPR_MODIFY:
            reason_str = "PORT MODIFIED";
            if (!(ntohl(port->state) & OFPPS_LINK_DOWN)) { /* port is down */
                /* UPDATE THE LINK STATUS */
                topology_remove_link(sw->datapath_id, ntohs(port->port_no));
                send_lldp_packet(sw, ntohs(port->port_no));
            } else { /* port is up */
                /* UPDATE THE LINK STATUS */
                topology_remove_link(sw->datapath_id, ntohs(port->port_no));
                send_lldp_packet(sw, ntohs(port->port_no));


            }
            break;
        default:
            reason_str = "UNKNOWN";
    }
    
    /* log the port status change */
    log_msg("\nPort status change on switch %016" PRIx64 ":\n", sw->datapath_id);
    log_msg("  Port: %u (%s)\n", ntohs(port->port_no), port->name);
    log_msg("  Reason: %s\n", reason_str);
    log_msg("  State: %s\n", state_str);
    log_msg("  Hardware Addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
            port->hw_addr[0], port->hw_addr[1], port->hw_addr[2],
            port->hw_addr[3], port->hw_addr[4], port->hw_addr[5]);
    
    pthread_mutex_unlock(&sw->lock);
}

/* ----------------------------------------------- End Packet Handler Functions ------------------------------------------------ */

/* --------------------------------------------------- Flow Installation ------------------------------------------------------- */

/* handle incoming packets from the switch */
void handle_packet_in(struct switch_info *sw, struct ofp_packet_in *pi) {
    /*
    Case 1: Unicast to Same Switch
    When source and destination MAC addresses are on the same switch:

    Check your MAC table to confirm destination port
    Install a flow rule that matches destination MAC and input port
    Action will be to output to the specific destination port
    Send a PACKET_OUT to handle the current packet

    Case 2: Unicast to Different Switch
    When destination MAC is known but on a different switch:

    Use Dijkstra's algorithm to find shortest path
    Install flow rule on current switch to forward to the next hop
    The flow matches destination MAC and has output action to the appropriate port
    Send a PACKET_OUT for the current packet

    Case 3: Broadcast
    When destination is broadcast/multicast (first byte has least significant bit set):

    Calculate MST with current switch as root (or use pre-calculated MST)
    Install flow rule that matches the broadcast MAC
    Action will indeed be to output to MULTIPLE ports (all ports in the MST except the input port)
    For this, you'll need to construct a flow rule with multiple actions
    */

    if (!pi) {
        log_msg("Error: Null packet_in message\n");
        return;
    }

    /* first check for an lldp packet - see topology.c  */
    if (is_lldp_packet(pi->data)) {
        handle_lldp_packet(sw, pi);
        return;  /* no further processing for LLDP packets */
    }

    /* extract ethernet frame information */
    uint8_t *eth_frame_start = pi->data;
    uint8_t *eth_dst = eth_frame_start;
    uint8_t *eth_src = eth_frame_start + ETHERNET_ADDR_LEN;

    /* add info from packet to global MAC table */
    add_mac(eth_src, sw->datapath_id, ntohs(pi->in_port));
    
    /* lock switch for thread safety while accessing switch info */
    pthread_mutex_lock(&sw->lock);
    
    /* increment packet counter */
    sw->packet_in_count++;
    
    /* extract basic packet information */
    uint32_t buffer_id = ntohl(pi->buffer_id);
    uint16_t total_len = ntohs(pi->total_len);
    uint16_t in_port = ntohs(pi->in_port);
    
    /* get reason for packet in */
    const char *reason_str = "Unknown";
    switch (pi->reason) {
        case OFPR_NO_MATCH:
            if (memcmp(eth_dst, eth_src, ETHERNET_ADDR_LEN) == 0) {

                /* DIJKSTAS CALCULATION */
                /* INSTALL FLOW WITH TO FORWARD TO SELF */
                /* PACKEY OUT WITH pi */

                reason_str = "UNICAST, SAME SRC AND DST";
            } else if (memcmp(eth_dst, "\xff\xff\xff\xff\xff\xff", ETHERNET_ADDR_LEN) == 0) {

                /* MST CALCULATION */
                /* INSTALL FLOW FOR BROADCAST */
                /* PACKET OUT WITH pi */

                reason_str = "BROADCAST";
            } else {

                /* DIJKSTAS CALCULATION */
                /* INSTALL FLOW WITH TO FORWARD TO NEXT HOP */
                /* PACKET OUT WITH pi */

                reason_str = "UNICAST, DIFFERENT SRC AND DST";
            }
            break;
        case OFPR_ACTION:
            reason_str = "Action explicitly output to controller";
            break;
        default:
            reason_str = "Unknown reason";
    }
    
    /* log packet information */
    #ifdef DEBUG
    log_msg("\nPACKET_IN from switch %016" PRIx64 ":\n", sw->datapath_id);
    log_msg("  Buffer ID: %u\n", buffer_id);
    log_msg("  Total Length: %u bytes\n", total_len);
    log_msg("  In Port: %u\n", in_port);
    log_msg("  Reason: %s\n", reason_str);
    #endif

    
    pthread_mutex_unlock(&sw->lock);
}

void send_flow_mod(struct switch_info *sw, uint8_t *dst_mac, uint16_t output_port) {

    /* length calculations and allocations */
    int actions_len = sizeof(struct ofp_action_output);
    int total_len = sizeof(struct ofp_flow_mod) + actions_len;

    struct ofp_flow_mod *flow_mod = malloc(total_len);
    memset(flow_mod, 0, total_len);
    
    /* fill in the ofp_header */
    flow_mod->header.version = OFP_VERSION;
    flow_mod->header.type = OFPT_FLOW_MOD;
    flow_mod->header.length = htons(total_len);
    flow_mod->header.xid = htonl(0);
    
    /* set the match fields to match on destination MAC */
    flow_mod->match.wildcards = htonl(OFPFW_ALL & ~OFPFW_DL_DST);  /* only match on dl_dst */

    /* IMPORTANT set the mac address to match on in the flow */
    memcpy(flow_mod->match.dl_dst, dst_mac, OFP_ETH_ALEN);  
    
    /* fill in the flow mod fields */
    flow_mod->command = htons(OFPFC_ADD);  /* new flow */
    flow_mod->idle_timeout = htons(60);    /* 60 seconds idle timeout */
    flow_mod->hard_timeout = htons(300);   /* 5 minutes hard timeout */
    flow_mod->priority = htons(100);      /* priority level MEDIUM */
    flow_mod->buffer_id = htonl(0xFFFFFFFF);  
    flow_mod->out_port = htons(OFPP_NONE); /* ignored for flow add */
    flow_mod->flags = htons(OFPFF_SEND_FLOW_REM);  
    
    /* add the output action */
    struct ofp_action_output *action = (struct ofp_action_output *)flow_mod->actions;
    action->type = htons(OFPAT_OUTPUT);
    action->len = htons(sizeof(struct ofp_action_output));
    action->port = htons(output_port);  /* the port to output matching packets to */
    action->max_len = htons(0);

    send_openflow_msg(sw, flow_mod, total_len);
    free(flow_mod);
}

// In communication.c

// Install flow for unicast traffic along a path
void install_unicast_flows(struct path *path, uint8_t *dst_mac) {
    if (!path || !path->nodes) {
        log_msg("Error: Invalid path for flow installation\n");
        return;
    }
    
    struct path_node *node = path->nodes;
    
    while (node != NULL) {
        struct switch_info *sw = find_switch_by_dpid(node->dpid);
        if (sw && node->out_port != 0) {
            send_flow_mod(sw, dst_mac, node->out_port);
            log_msg("Installed unicast flow on switch %016" PRIx64 " for MAC %02x:%02x:%02x:%02x:%02x:%02x to port %u\n",
                   node->dpid, dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], node->out_port);
        }
        
        node = node->next;
    }
}

// Install flow for broadcast traffic based on MST
void install_broadcast_flows(struct mst *tree, uint8_t *broadcast_mac) {
    if (!tree || !tree->nodes) {
        log_msg("Error: Invalid MST for flow installation\n");
        return;
    }
    
    for (int i = 0; i < tree->num_nodes; i++) {
        struct mst_node *node = &tree->nodes[i];
        struct switch_info *sw = find_switch_by_dpid(node->dpid);
        
        if (!sw) continue;
        
        // Collect all ports that are part of the MST
        uint16_t mst_ports[MAX_SWITCH_PORTS];
        int num_ports = 0;
        
        // Add parent port if this is not the root
        if (node->dpid != tree->root_dpid && node->parent_port != 0) {
            mst_ports[num_ports++] = node->parent_port;
        }
        
        // Add all child ports
        for (int j = 0; j < node->num_children; j++) {
            if (node->child_ports && node->child_ports[j] != 0) {
                mst_ports[num_ports++] = node->child_ports[j];
            }
        }
        
        // Install flow with multiple output actions
        if (num_ports > 0) {
            install_multiport_flow(sw, broadcast_mac, mst_ports, num_ports);
            
            log_msg("Installed broadcast flow on switch %016" PRIx64 " with %d output ports\n",
                   node->dpid, num_ports);
        }
    }
}

// Install a flow with multiple output ports
void install_multiport_flow(struct switch_info *sw, uint8_t *dst_mac, uint16_t *output_ports, int num_ports) {
    int actions_len = num_ports * sizeof(struct ofp_action_output);
    int total_len = sizeof(struct ofp_flow_mod) + actions_len;
    
    struct ofp_flow_mod *flow_mod = malloc(total_len);
    memset(flow_mod, 0, total_len);
    
    // Fill in the ofp_header
    flow_mod->header.version = OFP_VERSION;
    flow_mod->header.type = OFPT_FLOW_MOD;
    flow_mod->header.length = htons(total_len);
    flow_mod->header.xid = htonl(0);
    
    // Set match on destination MAC
    flow_mod->match.wildcards = htonl(OFPFW_ALL & ~OFPFW_DL_DST);
    memcpy(flow_mod->match.dl_dst, dst_mac, OFP_ETH_ALEN);
    
    // Fill in flow mod fields
    flow_mod->command = htons(OFPFC_ADD);
    flow_mod->idle_timeout = htons(60);
    flow_mod->hard_timeout = htons(300);
    flow_mod->priority = htons(100);
    flow_mod->buffer_id = htonl(0xFFFFFFFF);
    flow_mod->out_port = htons(OFPP_NONE);
    flow_mod->flags = htons(OFPFF_SEND_FLOW_REM);
    
    // Add output actions for each port
    struct ofp_action_output *action = (struct ofp_action_output *)flow_mod->actions;
    for (int i = 0; i < num_ports; i++) {
        action[i].type = htons(OFPAT_OUTPUT);
        action[i].len = htons(sizeof(struct ofp_action_output));
        action[i].port = htons(output_ports[i]);
        action[i].max_len = htons(0);
    }
    
    send_openflow_msg(sw, flow_mod, total_len);
    free(flow_mod);
}

// Helper function to find a switch by datapath ID
struct switch_info *find_switch_by_dpid(uint64_t dpid) {
    pthread_mutex_lock(&switches_lock);
    
    for (int i = 0; i < MAX_SWITCHES; i++) {
        if (switches[i].active && switches[i].datapath_id == dpid) {
            pthread_mutex_unlock(&switches_lock);
            return &switches[i];
        }
    }
    
    pthread_mutex_unlock(&switches_lock);
    return NULL;
}

void send_packet_out(struct switch_info *sw, uint8_t *data, size_t data_len, uint16_t out_port) {

    /* length calculations and allocations */
    int total_len = sizeof(struct ofp_packet_out) + data_len;
    struct ofp_packet_out *packet_out = malloc(total_len);

    if (!packet_out) {
        log_msg("Failed to allocate memory for packet out message\n");
        return;
    }

    memset(packet_out, 0, total_len);
    
    /* fill in the ofp_header */
    packet_out->header.version = OFP_VERSION;
    packet_out->header.type = OFPT_PACKET_OUT;
    packet_out->header.length = htons(total_len);
    packet_out->header.xid = htonl(0);
    
    /* fill in the packet out fields */
    packet_out->buffer_id = htonl(0xFFFFFFFF);  /* no buffer */
    packet_out->in_port = htons(OFPP_NONE);     /* no input port */
    packet_out->actions_len = htons(0);         /* no actions */
    
    /* copy the packet data */
    memcpy(packet_out + sizeof(struct ofp_packet_out), data, data_len);
    
    /* send the packet out message */
    send_openflow_msg(sw, packet_out, total_len);
    free(packet_out);
}

/* ------------------------------------------------ End Flow Installation ------------------------------------------------------ */

/* ------------------------------------------------ Send Openflow Messages ----------------------------------------------------- */

/* default function for sending OpenFlow message LOW LEVEL FUNCTION */
int send_openflow_msg(struct switch_info *sw, void *msg, size_t len) {

    pthread_mutex_lock(&sw->lock);      /* lock threads for safety */
    if (sw->active) {
        if (send(sw->socket, msg, len, 0) < 0) {      /* send to socket at switch */
            perror("Failed to send message");
            pthread_mutex_unlock(&sw->lock);
            return -1; /* modified to return an int for better error checking */
        }
    }
    pthread_mutex_unlock(&sw->lock);
    return 0;
}

/* send HELLO message */
void send_hello(struct switch_info *sw) {
    struct ofp_header hello;
    
    hello.version = OFP_VERSION;
    hello.type = OFPT_HELLO;
    hello.length = htons(sizeof(hello));
    hello.xid = htonl(0);
    
    /* use OpenFlow hello packet */
    send_openflow_msg(sw, &hello, sizeof(hello));
}

/* add echo request/reply support */
bool send_echo_request(struct switch_info *sw) {

    if (!sw->echo_pending) {
        struct ofp_header echo;
        
        echo.version = OFP_VERSION;
        echo.type = OFPT_ECHO_REQUEST;
        echo.length = htons(sizeof(echo));
        echo.xid = htonl(sw->last_echo_xid++);
        
        sw->echo_pending = true;
        
        pthread_mutex_lock(&sw->lock);
        bool success = false;
        sw->last_echo = time(NULL);
        if (sw->active) {
            success = send_openflow_msg(sw, &echo, sizeof(echo)) >= 0;
            if (!success) {
                sw->echo_pending = false;  /* reset if send failed */
            }
            #ifdef DEBUG
            log_msg("Echo request sent to switch %016" PRIx64 " (XID: %u)\n", 
                    sw->datapath_id, ntohl(echo.xid));
            #endif
        }
        pthread_mutex_unlock(&sw->lock);
        
        return success;
    }
    log_msg("Echo request already pending for switch %016" PRIx64 "\n", sw->datapath_id);
    return false;
}

/* send features request */
void send_features_request(struct switch_info *sw) {
    struct ofp_header freq;
    
    freq.version = OFP_VERSION;
    freq.type = OFPT_FEATURES_REQUEST;
    freq.length = htons(sizeof(freq));
    freq.xid = htonl(1);
    
    send_openflow_msg(sw, &freq, sizeof(freq));
}

/* ------------------------------------------------ End Send Openflow Messages -------------------------------------------------- */