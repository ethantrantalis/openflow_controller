#include "controller.h"
#include "communication.h"

/* ----------------------------------------------- Handle Openflow Messages ---------------------------------------------------- */

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

/* handle incoming packets from the switch */
void handle_packet_in(struct switch_info *sw, struct ofp_packet_in *pi) {
    if (!pi) {
        log_msg("Error: Null packet_in message\n");
        return;
    }

    /* first check for an lldp packet - see topology.c  */
    if (is_lldp_packet(pi->data)) {
        handle_lldp_packet(sw, pi);
        return;  /* no further processing for LLDP packets */
    }

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
            /* UPDATE THE */
            /* HANDLE UNICAST AND BROADCASY TRAFFIC HERE */
            reason_str = "No matching flow";
            break;
        case OFPR_ACTION:
            reason_str = "Action explicitly output to controller";
            break;
        default:
            reason_str = "Unknown reason";
    }
    
    /* log packet information */
    log_msg("\nPACKET_IN from switch %016" PRIx64 ":\n", sw->datapath_id);
    log_msg("  Buffer ID: %u\n", buffer_id);
    log_msg("  Total Length: %u bytes\n", total_len);
    log_msg("  In Port: %u\n", in_port);
    log_msg("  Reason: %s\n", reason_str);

    
    pthread_mutex_unlock(&sw->lock);
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

/* ------------------------------------------------ Send Openflow Messages ----------------------------------------------------- */

/* default function for sending OpenFlow message */
void send_openflow_msg(struct switch_info *sw, void *msg, size_t len) {

    pthread_mutex_lock(&sw->lock);      /* lock threads for safety */
    if (sw->active) {
        if (send(sw->socket, msg, len, 0) < 0) {      /* send to socket at switch */
            perror("Failed to send message");
        }
    }
    pthread_mutex_unlock(&sw->lock);
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
            success = (send(sw->socket, &echo, sizeof(echo), 0) >= 0);
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