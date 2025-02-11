/* 
 * sudo mn --controller=remote,ip=IP,port=6633 --switch=ovsk,protocols=OpenFlow13
 */

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

#if defined(__linux__)
    #include <endian.h>
#elif defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
    #define be64toh(x) OSSwapBigToHostInt64(x)
#endif

#include "controller.h"
#include "openflow.h"


/* signal handler */
void signal_handler(int signum) {
    printf("\nShutdown signal received, cleaning up...\n");
    running = 0;
}

/* thread-safe logging function */
void log_msg(const char *format, ...) {
    va_list args;
    va_start(args, format);      /* initialize variatric args starting at format */
    pthread_mutex_lock(&switches_lock);      /* lock to prevent other threads from writing */
    vprintf(format, args);
    fflush(stdout);      /* clear out buffered output */
    pthread_mutex_unlock(&switches_lock);
    va_end(args);      /* cleans up args*/
}

/* clean up function for threads and and switches*/
void cleanup_switch(struct switch_info *sw) {
    pthread_mutex_lock(&sw->lock);
    if (sw->active) {
        sw->active = 0;
        close(sw->socket);
        free(sw->ports);
        sw->ports = NULL;
        sw->num_ports = 0;
        sw->hello_received = 0;
        sw->features_received = 0;
    }
    pthread_mutex_unlock(&sw->lock);
}

/* main controller function */
int main(int argc, char *argv[]) {
    int port = OFP_TCP_PORT;
    
    /* handle command line args for port number */
    if (argc > 1) {

        /* convert second arg to int for port from user */
        port = atoi(argv[1]);
    }
    
    /* set up signal handling */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("OpenFlow Controller starting on port %d...\n", port);
    printf("Supported OpenFlow version: 0x%02x\n", OFP_VERSION);
    
    /* initialize controller */
    init_controller(port);
    
    /* main loop - just wait for shutdown signal */
    while (running) {
        sleep(1);
    }
    
    /* cleanup threads */
    for (int i = 0; i < MAX_SWITCHES; i++) {
        pthread_mutex_lock(&switches[i].lock);
        if (switches[i].active) {
            switches[i].active = 0;
            close(switches[i].socket);
            free(switches[i].ports);
        }
        pthread_mutex_unlock(&switches[i].lock);
        pthread_mutex_destroy(&switches[i].lock);
    }
    
    /* close server socket */
    close(server_socket);
    
    /* destroy global mutex */
    pthread_mutex_destroy(&switches_lock);
    return 0;
}

/* initialize controller */
void init_controller(int port) {

    
    struct sockaddr_in addr;
    int i, opt = 1;
    
    /* initialize switch array which will handle info about connected switches */
    /* each will have a thread lock for thread safety */
    for (i = 0; i < MAX_SWITCHES; i++) {
        memset(&switches[i], 0, sizeof(struct switch_info));
        pthread_mutex_init(&switches[i].lock, NULL);
    }
    
    /* GLOBAL VARIABLE create a tcp server socket, SOCK_STREAM = TCP */
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Failed to create socket");
        exit(1);
    }

    printf("Server socket created successfully\n");
    
    /* set socket options */
    
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    printf("Socket options set\n");
    
    /* bind to port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;      /* listen on all interfaces */
    addr.sin_port = htons(port);      /* default openflow port */
    
    /* associate the socket descriptor we got with the address/port */
    if (bind(server_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Failed to bind");
        exit(1);
    }

    printf("Socket bound successfully to port %d\n", port);
    
    /* listen for connections */
    if (listen(server_socket, 5) < 0) {
        perror("Failed to listen");
        exit(1);
    }
    
    /* start accept thread, creates a thread that listens for new connections
     * the handler will create new threads for each new connection 
     * pass no args to handler */
    pthread_t accept_thread;
    if (pthread_create(&accept_thread, NULL, accept_handler, NULL) != 0) {
        perror("Failed to create accept thread");
        exit(1);
    }
}

/* -------------------------------------------------- Initialize Threads ------------------------------------------------------- */

/* accept incoming switch connections, spawns new threads for each connection */
void *accept_handler(void *arg) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    
    printf("Accept handler thread started\n");
    
    while (running) {
        printf("Waiting for connection on port %d...\n", OFP_TCP_PORT);
        /* accept new connection from the socket created in init_controller */
        int client = accept(server_socket, (struct sockaddr *)&addr, &addr_len);
        if (client < 0) {
            if (errno == EINTR && !running) {
                printf("Accept interrupted by shutdown\n");
                break;
            }
            printf("Accept failed with error: %s\n", strerror(errno));
            continue;
        }
        
        printf("New connection accepted from %s:%d\n", 
               inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        /* find free switch slot */
        pthread_mutex_lock(&switches_lock);
        int i;
        for (i = 0; i < MAX_SWITCHES; i++) {
            if (!switches[i].active) {
                printf("Using switch slot %d\n", i);
                switches[i].socket = client;
                switches[i].active = 1;
                
                /* create handler thread */
                if (pthread_create(&switches[i].thread, NULL, switch_handler, &switches[i]) != 0) {
                    perror("Failed to create switch handler thread");
                    close(client);
                    switches[i].active = 0;
                    printf("Failed to create handler thread for switch %d\n", i);
                } else {
                    printf("Successfully created handler thread for switch %d\n", i);
                }
                break;
            }
        }
        pthread_mutex_unlock(&switches_lock);
        
        if (i == MAX_SWITCHES) {
            printf("Maximum number of switches reached, rejecting connection\n");
            close(client);
        }
    }
    printf("Accept handler exiting\n");
    return NULL;
}

/* handler for each connected switch, manages the lifecycle of a connection  */
void *switch_handler(void *arg) {
    struct switch_info *sw = (struct switch_info *)arg;
    uint8_t buf[OFP_MAX_MSG_SIZE];
    ssize_t len;
    
    printf("Switch handler started for new connection\n");
    
    /* initialize switch state */
    sw->hello_received = 0;
    sw->features_received = 0;
    
    /* start OpenFlow handshake */
    send_hello(sw);
    
    /* message handling loop */
    while (sw->active && running) {
        len = recv(sw->socket, buf, sizeof(buf), 0);
        
        if (len == 0) {
            log_msg("Connection closed cleanly by switch %016" PRIx64 "\n", sw->datapath_id);
            break;
        } else if (len < 0) {
            if (errno == EINTR) {
                continue; 
            } else if (errno == ECONNRESET) {
                log_msg("Connection reset by switch %016" PRIx64 "\n", sw->datapath_id);
            } else {
                log_msg("Receive error on switch %016" PRIx64 ": %s\n", 
                        sw->datapath_id, strerror(errno));
            }
            break;
        }
        
        /* process message */
        handle_switch_message(sw, buf, len);
        
        /* keep connection alive with echo requests */
        if (sw->features_received) {
            time_t now = time(NULL);
            if (now - sw->last_echo > ECHO_INTERVAL) {
                send_echo_request(sw);
                sw->last_echo = now;
            }
        }
    }
    
    /* clean up connection */
    pthread_mutex_lock(&sw->lock);
    if (sw->active) {
        sw->active = 0;
        close(sw->socket);
        free(sw->ports);
        sw->ports = NULL;
        sw->num_ports = 0;
    }
    pthread_mutex_unlock(&sw->lock);
    
    printf("Switch handler exiting\n");
    return NULL;
}

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
    
    /* Only send features request after HELLO exchange is complete */
    if (sw->version == OFP_VERSION) {
        send_features_request(sw);
    } else {
        /* Version mismatch - should send error */
        struct ofp_error_msg error;
        error.header.version = OFP_VERSION;
        error.header.type = OFPT_ERROR;
        error.header.length = htons(sizeof(error));
        error.header.xid = oh->xid;
        error.type = htons(OFPET_HELLO_FAILED);
        error.code = htons(OFPHFC_INCOMPATIBLE);
        send_openflow_msg(sw, &error, sizeof(error));
        sw->active = 0;  /* Mark for disconnection */
    }
}

/* Handle echo requests/replies */
void handle_echo_request(struct switch_info *sw, struct ofp_header *oh) {
    struct ofp_header echo;
    
    /* Simply change the type to reply and send it back */
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
    for (int i = 0; i < num_ports; i++) {
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
    sw->last_echo = sw->last_echo_reply;  // Add this line
    
    /* for debugging */
    log_msg("Echo reply received from switch %016" PRIx64 "\n", sw->datapath_id);
    
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
    
    /* onvert port state to string */
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
            break;
        case OFPPR_DELETE:
            reason_str = "PORT REMOVED";
            break;
        case OFPPR_MODIFY:
            reason_str = "PORT MODIFIED";
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
    
    /* update port information in switch state */
    switch (ps->reason) {
        case OFPPR_ADD:
            /* would need to reallocate ports array to add new port */
            break;
            
        case OFPPR_DELETE:
            /* would need to remove port from ports array */
            break;
            
        case OFPPR_MODIFY:
            /* update existing port information */
            for (int i = 0; i < sw->num_ports; i++) {
                if (ntohs(sw->ports[i].port_no) == ntohs(port->port_no)) {
                    memcpy(&sw->ports[i], port, sizeof(struct ofp_phy_port));
                    break;
                }
            }
            break;
    }
    
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
void send_echo_request(struct switch_info *sw) {
    struct ofp_header echo;
    
    echo.version = OFP_VERSION;
    echo.type = OFPT_ECHO_REQUEST;
    echo.length = htons(sizeof(echo));
    echo.xid = htonl(sw->echo_xid++);
    
    send_openflow_msg(sw, &echo, sizeof(echo));
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





