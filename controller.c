/* 
 * sudo mn --controller=remote,ip=IP,port=6633 --switch=ovsk,protocols=OpenFlow10
 */

/*
* From my understanding of OpenFlow, here is how the conrtoller works
* 1. The controller listens for incoming connections from switches
*  - A socket is created for TCP connections.
*  - The socket is bound to a port and listens for incoming connections.
*  - All indexes in the switch array have a mutex locked placed on them for later.
*  - A thread is created to handle incoming connections by running the accept_handler.
*
* 2. The accept_handler function is called when a new connection is accepted by the listener thread.
*  - The function locks the switch array and finds a free slot to store the switch information.
*  - Once locked, finds a free slot in the switch array to store the switch information.
*  - The switch socket is stored in the switch array and a new thread is created run switch_handler.
*  - The switch array is unlocked.
*  - If the maximum number of switches is reached, the connection is rejected.
*  - Each new thread handles communication between the controller and the switch.
*
* 3. In the switch handler, the thread begins the OpenFlow handshake.
*  - Thread sends a HELLO message to the switch with send_hello.
*  - The switch handler thread waits for incoming messages from the switch.
*  - The thread processes incoming messages with handle_switch_message.
*  - The switch handler thread sends an ECHO_REQUEST to the switch every 5 seconds.
*  - The switch handler thread waits for an ECHO_REPLY from the switch.
*
* 4. The handle_switch_message function processes incoming OpenFlow messages.
*  - The function verifies the message length.
*  - The function processes the message based on the message type.
*       - handle_hello updates the switch version and sends a features request.
*       - handle_echo_request sends an ECHO_REPLY back to the switch.
*       - handle_echo_reply updates the last_echo_reply time.
*       - handle_features_reply updates switch features and port information.
*       - handle_packet_in logs packet information.
*       - handle_port_status logs port status changes.
*
* 5. The send_openflow_msg function sends OpenFlow messages to the switch.
*  - The function locks the switch mutex.
*  - The function sends the message to the switch socket.
*  - The function unlocks the switch mutex.
*
* 6. The send_hello function sends a HELLO message to the switch.
*  - The function creates a HELLO message and sends it to the switch.
*
* 7. The send_features_request function sends a FEATURES_REQUEST to the switch.
*  - The function creates a FEATURES_REQUEST message and sends it to the switch.
*
* 8. The send_echo_request function sends an ECHO_REQUEST to the switch.
*  - The function creates an ECHO_REQUEST message and sends it to the switch.
*/
#include "smartalloc.h"
#include "checksum.h"
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
    va_start(args, format);
    
    pthread_mutex_lock(&switches_lock);
    
    // Get current time with microsecond precision
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = localtime(&tv.tv_sec);
    
    // Print timestamp in HH:MM:SS.microseconds format
    printf("[%02d:%02d:%02d.%06ld] ", 
           tm_info->tm_hour,
           tm_info->tm_min, 
           tm_info->tm_sec,
           (long)tv.tv_usec);
    
    vprintf(format, args);
    fflush(stdout);
    pthread_mutex_unlock(&switches_lock);
    va_end(args);
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

    if (argc == 1) {
        /* handle command line args for port number */
        fprintf(stderr, "Usage: %s [debug 0/1] [port]\n", argv[0]);
        return -1;
    } else if (argc > 1) {
        /* handle command line args for port number */
        int debug = atoi(argv[1]);
        if(debug){
            #define DEBUG
        }
        if (argc > 2) {
            /* convert second arg to int for port from user */
            port = atoi(argv[2]);
        }
    }
    
    /* handle command line args for port number */
    
    
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
    time_t next_echo = 0;
    time_t now;
    
    printf("Switch handler started for new connection\n");
    
    /* initialize switch state */
    sw->hello_received = 0;
    sw->features_received = 0;
    sw->last_echo_xid = 0;
    sw->echo_pending = false;
    
    /* start OpenFlow handshake */
    send_hello(sw);
    
    /* message handling loop */
    while (sw->active && running) {
        struct timeval tv;
        tv.tv_sec = 1; 
        tv.tv_usec = 0;
        
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sw->socket, &readfds);
        
        int ret = select(sw->socket + 1, &readfds, NULL, NULL, &tv);
        
        now = time(NULL);
        
        /* handle echo timing independent of message receipt */
        if (sw->features_received) {
            if (next_echo == 0) {
                next_echo = now + ECHO_INTERVAL;
            }
            
            if (sw->echo_pending && (now - sw->last_echo) > ECHO_TIMEOUT) {
                sw->echo_pending = false;
            }
            
            if (!sw->echo_pending && now >= next_echo) {
                if (send_echo_request(sw)) {
                    next_echo = now + ECHO_INTERVAL;
                }
            }
        }
        
        /* handle incoming messages if any */
        if (ret > 0 && FD_ISSET(sw->socket, &readfds)) {
            len = recv(sw->socket, buf, sizeof(buf), 0);
            if (len == 0) {
                log_msg("Connection closed cleanly by switch %016" PRIx64 "\n", 
                       sw->datapath_id);
                break;
            } else if (len < 0) {
                if (errno == EINTR) {
                    continue;
                } else if (errno == ECONNRESET) {
                    log_msg("Connection reset by switch %016" PRIx64 "\n", 
                           sw->datapath_id);
                } else {
                    log_msg("Receive error on switch %016" PRIx64 ": %s\n",
                           sw->datapath_id, strerror(errno));
                }
                break;
            }
            
            /* process message */
            handle_switch_message(sw, buf, len);
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
    pthread_mutex_lock(&sw->lock);
    
    /* clean up any existing port data */
    if (sw->ports) {
        free(sw->ports);
        sw->ports = NULL;
        sw->num_ports = 0;
    }

    sw->datapath_id = be64toh(features->datapath_id);
    sw->n_tables = features->n_tables;
    
    /* calculate number of ports */
    size_t port_list_len = ntohs(features->header.length) - sizeof(*features);
    int num_ports = port_list_len / sizeof(struct ofp_phy_port);
    
    log_msg("Received features reply from switch %016" PRIx64 "\n", sw->datapath_id);
    
    /* store port information */
    sw->ports = malloc(port_list_len);
    if (!sw->ports) {
        log_msg("Error: Failed to allocate memory for ports\n");
        pthread_mutex_unlock(&sw->lock);
        return;
    }
    
    memcpy(sw->ports, features->ports, port_list_len);
    sw->num_ports = num_ports;
    
    /* mark features as received */
    sw->features_received = 1;
    
    /* log switch features */
    log_msg("\nSwitch features:\n");
    log_msg("  Datapath ID: %016" PRIx64 "\n", sw->datapath_id);
    log_msg("  OpenFlow version: 0x%02x\n", sw->version);
    log_msg("  Number of tables: %d\n", sw->n_tables);
    log_msg("  Number of buffers: %d\n", ntohl(features->n_buffers));
    log_msg("  Number of ports: %d\n", num_ports);

    /* print capabilities */
    log_msg("  Capabilities:\n");
    uint32_t capabilities = ntohl(features->capabilities);
    if (capabilities & OFPC_FLOW_STATS)    log_msg("    - Flow statistics\n");
    if (capabilities & OFPC_TABLE_STATS)   log_msg("    - Table statistics\n");
    if (capabilities & OFPC_PORT_STATS)    log_msg("    - Port statistics\n");
    if (capabilities & OFPC_STP)           log_msg("    - 802.1d spanning tree\n");
    if (capabilities & OFPC_IP_REASM)      log_msg("    - IP reasm\n");
    if (capabilities & OFPC_QUEUE_STATS)   log_msg("    - Queue statistics\n");
    if (capabilities & OFPC_ARP_MATCH_IP)  log_msg("    - ARP match IP\n");
    
    /* print port details */
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
    
    pthread_mutex_unlock(&sw->lock);
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

    /* Examine ethernet frame if present */
    if (total_len >= 14) { // Minimum ethernet frame size
        uint8_t *data = pi->data;
        log_msg("  Ethernet: dst=%02x:%02x:%02x:%02x:%02x:%02x "
                "src=%02x:%02x:%02x:%02x:%02x:%02x type=0x%04x\n",
                data[0], data[1], data[2], data[3], data[4], data[5],
                data[6], data[7], data[8], data[9], data[10], data[11],
                (data[12] << 8) | data[13]);
    }
    
    pthread_mutex_unlock(&sw->lock);
}

/* handle echo reply messages */
void handle_echo_reply(struct switch_info *sw, struct ofp_header *oh) {
    pthread_mutex_lock(&sw->lock);
    
    /* update both last reply and last echo time */
    sw->last_echo_reply = time(NULL);
    sw->echo_pending = false;  /* Mark that anothe echo can be send, meaning echos have vbeen recienved */

    /* for debugging */
    
    
    pthread_mutex_unlock(&sw->lock);
}

/* handle port status changes */
void handle_port_status(struct switch_info *sw, struct ofp_port_status *ps) {
    if (!ps) {
        log_msg("Error: Null port_status message\n");
        return;
    }

    pthread_mutex_lock(&sw->lock);

    /* only process if features have been recieved */
    if (!sw->features_received || sw->datapath_id == 0) {
        log_msg("Warning: Received port status before features reply\n");
        pthread_mutex_unlock(&sw->lock);
        return;
    }
    
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





