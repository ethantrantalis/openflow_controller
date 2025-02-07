/* OpenFlow Controller - Milestone 1 
 * CPE 465 - Winter 2025
 * 
 * Essentially the flow of the controller works as follows:
 * 1. A socket is spawned and listens for incoming connections from switches on TCP. 
 * A thread is spawned that continuously listens for new connections using this socket and handles
 * new connections by spawning a new thread for each switch connection.
 * 2. The controller sends a HELLO message to the switch and waits for a HELLO message in return.
 * 3. The controller sends a FEATURES_REQUEST message to the switch and waits for a FEATURES_REPLY message.
 * 4. The controller then waits for incoming messages from the switch and processes them accordingly.
 * 5. The controller can handle multiple switches at once up to 16.
 * 
 * 
 * 
 * 
 * sudo mn --controller=remote,ip=127.0.0.1,port=6653 --switch=ovsk,protocols=OpenFlow13
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
    
    /* cleanup */
    cleanup();
    return 0;
}

/* initialize controller */
void init_controller(int port) {

    
    struct sockaddr_in addr;
    int i, opt = 1;
    
    /* initialize switch array */
    for (i = 0; i < MAX_SWITCHES; i++) {
        memset(&switches[i], 0, sizeof(struct switch_info));
        pthread_mutex_init(&switches[i].lock, NULL);
    }
    
    /* global variable create a tcp server socket, SOCK_STREAM = TCP */
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Failed to create socket");
        exit(1);
    }
    
    /* set socket options */
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    /* Bind to port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;      /* listen on all interfaces */
    addr.sin_port = htons(port);      /* default openflow port */
    
    /* associate the socket descriptor we got with the address/port */
    if (bind(server_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Failed to bind");
        exit(1);
    }
    
    /* listen for connections */
    if (listen(server_socket, 5) < 0) {
        perror("Failed to listen");
        exit(1);
    }
    
    /* start accept thread, creates a thread that listens for new connections
     * the handler will create new threads for each new connection */
    pthread_t accept_thread;
    if (pthread_create(&accept_thread, NULL, accept_handler, NULL) != 0) {
        perror("Failed to create accept thread");
        exit(1);
    }
}

/* accept incoming switch connections, spawns new threads for each connection */
void *accept_handler(void *arg) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    
    while (running) {
        /* accept new connection from the socket created in init_controller */
        int client = accept(server_socket, (struct sockaddr *)&addr, &addr_len);
        if (client < 0) {

            /* if accept fails, check if it was interrupted by a signal and if the controller is shutting down */
            if (errno == EINTR && !running){
                break;
            } else {
                perror("Accept failed");
                continue;
            }
        }
        
        /* find free switch slot */
        pthread_mutex_lock(&switches_lock);      /* lock to prevent other threads from writing */
        int i;
        for (i = 0; i < MAX_SWITCHES; i++) {
            if (!switches[i].active) {
                switches[i].socket = client;     /* assign socket to switch */
                switches[i].active = 1;
                
                /* create thread to handle that new switch connection  */
                if (pthread_create(&switches[i].thread, NULL, switch_handler, &switches[i]) != 0) {
                    perror("Failed to create switch handler thread");
                    close(client);
                    switches[i].active = 0;     /* mark as inactive */
                } else {
                    log_msg("New switch connection from %s:%d\n", 
                           inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
                }
                break;
            }
        }

        /* unlock threads */
        pthread_mutex_unlock(&switches_lock);
        
        /* edge case handler where max switches has been reached */
        if (i == MAX_SWITCHES) {
            log_msg("Maximum number of switches reached, rejecting connection\n");
            close(client);
        }
    }
    return NULL;
}

/* handler for each connected switch, manages the lifecycle of a connection  */
void *switch_handler(void *arg) {
    struct switch_info *sw = (struct switch_info *)arg;
    uint8_t buf[OFP_MAX_MSG_SIZE]; /* buffer for incoming messages */
    
    /* start OpenFlow handshake with HELLO message */
    send_hello(sw);
    
    /* message handling loop */
    while (sw->active && running) {
        /* receive message */
        ssize_t len = recv(sw->socket, buf, sizeof(buf), 0);
        if (len <= 0) {     /* connection closed or error */
            if (len < 0) perror("Receive failed");
            break;
        }
        
        /* process message */
        handle_switch_message(sw, buf, len);
    }
    
    /* clean up connection once switch has left */
    pthread_mutex_lock(&sw->lock);
    if (sw->active) {
        sw->active = 0;
        close(sw->socket);
        free(sw->ports);
    }
    pthread_mutex_unlock(&sw->lock);
    
    return NULL;
}

/* --------------------------------- Response/Reply Funtions ----------------------------------- */

/* Send HELLO message */
void send_hello(struct switch_info *sw) {
    struct ofp_header hello;
    
    hello.version = OFP_VERSION;
    hello.type = OFPT_HELLO;
    hello.length = htons(sizeof(hello));
    hello.xid = htonl(0);
    
    /* use OpenFlow hello packet */
    send_openflow_msg(sw, &hello, sizeof(hello));
}

/* send OpenFlow message */
void send_openflow_msg(struct switch_info *sw, void *msg, size_t len) {

    pthread_mutex_lock(&sw->lock);      /* lock threads for safety */
    if (sw->active) {
        if (send(sw->socket, msg, len, 0) < 0) {      /* send to socket at switch */
            perror("Failed to send message");
        }
    }
    pthread_mutex_unlock(&sw->lock);
}

/* handle incoming OpenFlow message, see while loop in switch handler */
void handle_switch_message(struct switch_info *sw, uint8_t *msg, size_t len) {
    struct ofp_header *oh = (struct ofp_header *)msg;
    
    /* verify message length */
    if (len < sizeof(*oh)) {
        log_msg("Message too short\n");
        return;
    }
    
    /* handle based on message type */
    switch (oh->type) {
        case OFPT_HELLO:
            handle_hello(sw, oh);
            break;
            
        case OFPT_FEATURES_REPLY:
            handle_features_reply(sw, (struct ofp_switch_features *)msg);
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
    log_msg("Switch hello received, version 0x%02x\n", sw->version);
    
    /* request switch features once a hello response has been recieved*/
    send_features_request(sw);
}

/* Send features request */
void send_features_request(struct switch_info *sw) {
    struct ofp_header freq;
    
    freq.version = OFP_VERSION;
    freq.type = OFPT_FEATURES_REQUEST;
    freq.length = htons(sizeof(freq));
    freq.xid = htonl(1);
    
    send_openflow_msg(sw, &freq, sizeof(freq));
}

/* Handle features reply */
/* Handle features reply for OpenFlow 1.0 */
void handle_features_reply(struct switch_info *sw, struct ofp_switch_features *features) {
    sw->datapath_id = be64toh(features->datapath_id);
    sw->n_tables = features->n_tables;
    
    /* Calculate number of ports */
    size_t port_list_len = ntohs(features->header.length) - sizeof(*features);
    int num_ports = port_list_len / sizeof(struct ofp_phy_port);
    
    /* Store port information */
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
    
    /* Print capabilities */
    log_msg("  Capabilities:\n");
    uint32_t capabilities = ntohl(features->capabilities);
    if (capabilities & OFPC_FLOW_STATS)    log_msg("    - Flow statistics\n");
    if (capabilities & OFPC_TABLE_STATS)   log_msg("    - Table statistics\n");
    if (capabilities & OFPC_PORT_STATS)    log_msg("    - Port statistics\n");
    if (capabilities & OFPC_STP)           log_msg("    - 802.1d spanning tree\n");
    if (capabilities & OFPC_IP_REASM)      log_msg("    - IP reasm\n");
    if (capabilities & OFPC_QUEUE_STATS)   log_msg("    - Queue statistics\n");
    if (capabilities & OFPC_ARP_MATCH_IP)  log_msg("    - ARP match IP\n");
    
    /* Print ports */
    for (int i = 0; i < num_ports; i++) {
        struct ofp_phy_port *port = &sw->ports[i];
        log_msg("\nPort %d:\n", ntohs(port->port_no));
        log_msg("  Name: %s\n", port->name);
        log_msg("  HW Addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
                port->hw_addr[0], port->hw_addr[1], port->hw_addr[2],
                port->hw_addr[3], port->hw_addr[4], port->hw_addr[5]);
        
        /* Print port state */
        if (ntohl(port->state) & OFPPS_LINK_DOWN)
            log_msg("  State: Link down\n");
        else
            log_msg("  State: Link up\n");
            
        /* Print port features */
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