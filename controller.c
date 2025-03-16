/* 
 * sudo mn --controller=remote,ip=IP,port=6653 --switch=ovsk,protocols=OpenFlow10
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

#if defined(__linux__)
    #include <endian.h>
#elif defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
    #define be64toh(x) OSSwapBigToHostInt64(x)
#endif

#include "headers/controller.h"
#include "headers/openflow.h"

#define MAX_PORTS_PER_SWITCH 256

#define DEF_PORT 6653

/* global variables */
struct switch_info switches[MAX_SWITCHES];
pthread_mutex_t switches_lock = PTHREAD_MUTEX_INITIALIZER;
int server_socket;
volatile int running = 1; /* for controller clean up and running */
struct network_topology topology;

struct mac_entry *mac_table = NULL;

/* add or update an entry */
void add_or_update_mac(uint8_t *mac, uint64_t dpid, uint16_t port_no) {
    struct mac_entry *entry;
    
    HASH_FIND(hh, mac_table, mac, MAC_ADDR_LEN, entry);
    if (entry == NULL) {
        entry = malloc(sizeof(struct mac_entry));
        memcpy(entry->mac, mac, MAC_ADDR_LEN);
        HASH_ADD(hh, mac_table, mac, MAC_ADDR_LEN, entry);
        printf("DEBUG: Added new MAC %02x:%02x:%02x:%02x:%02x:%02x to table for switch %016" PRIx64 " port %d\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], dpid, port_no);
    }else {
        printf("DEBUG: Updated MAC %02x:%02x:%02x:%02x:%02x:%02x from switch %016" PRIx64 " port %d to switch %016" PRIx64 " port %d\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 
               entry->switch_dpid, entry->port_no, dpid, port_no);
    }
    
    /* add other values of update values if already exists */
    entry->switch_dpid = dpid;
    entry->port_no = port_no;
    entry->last_seen = time(NULL);
}

/* find an entry */
struct mac_entry *find_mac(uint8_t *mac) {
    struct mac_entry *entry;
    HASH_FIND(hh, mac_table, mac, MAC_ADDR_LEN, entry);
    printf("DEBUG: MAC lookup for %02x:%02x:%02x:%02x:%02x:%02x: %s\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           entry ? "Found" : "Not found");

    if (entry) {
        printf("DEBUG: MAC %02x:%02x:%02x:%02x:%02x:%02x is on switch %016" PRIx64 " port %d\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 
               entry->switch_dpid, entry->port_no);
    }
    return entry;
}


/* signal handler */
void signal_handler(int signum) {
    printf("\nShutdown signal received, cleaning up...\n");
    running = 0;

}

/* thread-safe logging function */
void log_msg(struct switch_info * sw, const char *format, ...) {
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

    if (sw) {
        printf("> Switch %016" PRIx64 ": ", sw->datapath_id);
    }
    
    vprintf(format, args);
    fflush(stdout);
    pthread_mutex_unlock(&switches_lock);
    va_end(args);
}

/* clean up function for threads and and switches*/
void cleanup_switch(struct switch_info *sw) {

    /* remove from topology first */
    handle_switch_disconnect(sw);
    printf("Cleaning up switch %016" PRIx64 " from topology\n", sw->datapath_id);

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

    pthread_mutex_lock(&switches_lock);
    int i;
    for (i = 0; i < MAX_SWITCHES; i++) {
        if (&switches[i] == sw) {
            pthread_mutex_lock(&switches[i].lock);
            switches[i].active = 0;
            pthread_mutex_unlock(&switches[i].lock);
            break;
        }
    }
}

/* main controller function */
int main(int argc, char *argv[]) {
    int port = DEF_PORT;
    
    /* handle command line args for port number */
    if (argc > 1) {

        /* convert second arg to int for port from user */
        port = atoi(argv[1]);
    }
    
    /* set up signal handling */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("OpenFlow Controller starting on port %d...\n", port);
    
    /* initialize controller */
    init_controller(port);
    
    /* main loop - just wait for shutdown signal */
    while (running) {
        sleep(1);
    }
    
    /* cleanup threads */
    int i;
    for (i = 0; i < MAX_SWITCHES; i++) {
        pthread_mutex_lock(&switches[i].lock);
        if (switches[i].active) {
            switches[i].active = 0;
            close(switches[i].socket);
            if(switches[i].ports){
                free(switches[i].ports);
            }

        }
        pthread_mutex_unlock(&switches[i].lock);
        pthread_mutex_destroy(&switches[i].lock);
    }

    /* clean global topology structure */
    pthread_mutex_lock(&topology.lock);
    igraph_destroy(&topology.graph);
    pthread_mutex_unlock(&topology.lock);
    pthread_mutex_destroy(&topology.lock);
    
    /* close server socket */
    close(server_socket);
    
    /* destroy global mutex */
    pthread_mutex_destroy(&switches_lock);
    return 0;
}

/* initialize controller */
void init_controller(int port) {

    printf("Initializing controller\n");

    
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

    printf("Controller socket created\n");
    
    /* set socket options */
    
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
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

    /* create the global topology so new sitches can call its functions */
    init_topology();
    
    /* start accept thread, creates a thread that listens for new connections
     * the handler will create new threads for each new connection 
     * pass no args to handler */
    pthread_t accept_thread;
    if (pthread_create(&accept_thread, NULL, accept_handler, NULL) != 0) {
        perror("Failed to create accept thread");
        exit(1);
    }

    printf("Controller initialized\n");

}

/* accept incoming switch connections, spawns new threads for each connection */
void *accept_handler(void *arg) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    

    
    while (running) {

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

        /* Configure TCP socket options for robustness */
        int flag = 1;
        if (setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int)) < 0) {
            perror("Failed to set TCP_NODELAY");
        }
        
        if (setsockopt(client, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(int)) < 0) {
            perror("Failed to set SO_KEEPALIVE");
        }
        
        #ifdef __linux__
        /* Linux-specific keepalive parameters */
        int idle = 10;  /* Start sending keepalive probes after 10 seconds of idle */
        if (setsockopt(client, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(int)) < 0) {
            perror("Failed to set TCP_KEEPIDLE");
        }
        
        int interval = 5;  /* Send keepalive probes every 5 seconds */
        if (setsockopt(client, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int)) < 0) {
            perror("Failed to set TCP_KEEPINTVL");
        }
        
        int count = 3;  /* Consider connection dead after 3 failed probes */
        if (setsockopt(client, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(int)) < 0) {
            perror("Failed to set TCP_KEEPCNT");
        }
        #endif
        
        #ifdef __APPLE__
        /* macOS has different keepalive settings */
        /* macOS uses system-wide settings by default */
        /* You can use sysctl to check/change system-wide settings */
        printf("TCP keepalive enabled (using system defaults for macOS)\n");
        #endif
        

        /* find free switch slot */
        printf("Finding free switch slot\n");
        pthread_mutex_lock(&switches_lock);
        int i;
        for (i = 0; i < MAX_SWITCHES; i++) {
            printf("Checking switch slot %d\n", i);
            if (!switches[i].active) {
                printf("Using switch slot %d\n", i);
                switches[i].socket = client;
                switches[i].active = 1;
                
                /* create handler thread */
                printf("Creating handler thread for switch %d\n", i);
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
            printf("Switch slot %d is active\n", i);
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

    time_t connection_start = time(NULL);
    
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
        /* switch while loop */
        struct timeval tv;
        tv.tv_sec = 1; 
        tv.tv_usec = 0;
        
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sw->socket, &readfds);
        
        int ret = select(sw->socket + 1, &readfds, NULL, NULL, &tv);
        
        now = time(NULL);

        /* ----------------------------------------------- ECHO INTERVAL ------------------------------------------- */
        
        /* handle echo timing independent of message receipt */
        /* switch echo processing */
        if (sw->features_received && sw->hello_received) {
            if (next_echo == 0) {
                next_echo = now + ECHO_INTERVAL;
            }
            
            if (sw->echo_pending && (now - sw->last_echo) > ECHO_TIMEOUT) {
                log_msg(sw, "Connection to switch timed out\n");
                sw->echo_pending = false;
                cleanup_switch(sw); /* clean up now that connection ended */
                log_msg(sw,"Switch cleaned, exiting...\n");
                return NULL; /* connection endded */
            }
            
            if (!sw->echo_pending && now >= next_echo) {
                if (send_echo_request(sw)) {
                    next_echo = now + ECHO_INTERVAL;
                }
            }
        }

        /* ---------------------------------------------- INCOMING MESSAGE ----------------------------------------- */
        
        /* handle incoming messages if any */
        if (ret > 0 && FD_ISSET(sw->socket, &readfds)) {
            len = recv(sw->socket, buf, sizeof(buf), 0);
            if (len == 0) {
                log_msg(sw, "DEBUG: Connection closed cleanly after %ld seconds uptime\n", time(NULL) - connection_start);
                break;
            } else if (len < 0) {
                if (errno == EINTR) {
                    log_msg(sw, "ERROR: Connection error after %ld seconds uptime\n",  time(NULL) - connection_start);
                    continue;
                } else if (errno == ECONNRESET) {
                    log_msg(sw, "ERROR: Connection reset by switch\n");
                } else {
                    log_msg(sw, "ERROR: Receive error on switch: %s\n", sw->datapath_id, strerror(errno));
                }
                break;
            }
            
            /* process message */
            handle_switch_message(sw, buf, len);
        }
    }

    log_msg(sw, "Cleaning switch\n");
    cleanup_switch(sw);
    
    printf("Switch handler exiting\n");
    return NULL;
}

/* ------------------------------------------------- MESSAGE IN/OUT ------------------------------------------------ */

/* handle incoming OpenFlow message, see while loop in switch handler */
void handle_switch_message(struct switch_info *sw, uint8_t *msg, size_t len) {
    struct ofp_header *oh = (struct ofp_header *)msg;
    
    /* verify message length */
    if (len < sizeof(*oh)) {
        printf("Message too short\n");
        return;
    }
    
    /* handle based on message type */
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

        case OFPT_ERROR:
            {
                struct ofp_error_msg *err = (struct ofp_error_msg *)msg;
                log_msg(sw, "ERROR: Received OpenFlow error from switch: type=%d, code=%d\n", ntohs(err->type), ntohs(err->code));
                
                if (ntohs(err->type) == OFPET_FLOW_MOD_FAILED) {
                    log_msg(sw, "ERROR: Flow modification failed: ");
                    switch(ntohs(err->code)) {
                        case OFPFMFC_ALL_TABLES_FULL:
                            printf("\tAll tables full\n");
                            break;
                        case OFPFMFC_OVERLAP:
                            printf("\tOverlapping entry\n");
                            break;
                        
                        default:
                            printf("\tUnknown code: %d\n", ntohs(err->code));
                    }
                }
            }
            break;
            
        default:
            log_msg(sw, "ERROR: Unhandled message type: %d\n", oh->type);
    }
}

/* default function for sending OpenFlow message */
void send_openflow_msg(struct switch_info *sw, void *msg, size_t len) {

    pthread_mutex_lock(&sw->lock);      /* lock threads for safety */
    if (sw->active) {
        if (send(sw->socket, msg, len, 0) < 0) {      /* send to socket at switch */
            log_msg(sw, "ERROR: Failed to send openflow message: %s\n", strerror(errno));

             /* try send again if failed */

             if (send(sw->socket, msg, len, 0) < 0) {      /* send to socket at switch */
                log_msg(sw, "ERROR: Failed to send openflow message again: %s\n", strerror(errno));
                pthread_mutex_unlock(&sw->lock);
                return;
            }
        }

    }
    pthread_mutex_unlock(&sw->lock);
}

/* ------------------------------------------------------ HELLO ---------------------------------------------------- */

/* send HELLO message */
void send_hello(struct switch_info *sw) {
    struct ofp_header hello;
    
    hello.version = OFP_VERSION;
    hello.type = OFPT_HELLO;
    hello.length = htons(sizeof(hello));
    hello.xid = htonl(0);
    
    /* use OpenFlow hello packet */
    send_openflow_msg(sw, &hello, sizeof(hello));

    log_msg(sw, "Sent HELLO to switch\n");
}

/* handle HELLO message */
void handle_hello(struct switch_info *sw, struct ofp_header *oh) {
    sw->version = oh->version;
    sw->hello_received = 1;  /* mark HELLO as received */
    log_msg(sw, "Switch hello received, version 0x%02x\n", sw->version);
    
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

/* ---------------------------------------------------- FEATURES --------------------------------------------------- */

/* send features request */
void send_features_request(struct switch_info *sw) {

    log_msg(sw, "Sending features request.\n");
    struct ofp_header freq;
    
    freq.version = OFP_VERSION;
    freq.type = OFPT_FEATURES_REQUEST;
    freq.length = htons(sizeof(freq));
    freq.xid = htonl(1);
    
    send_openflow_msg(sw, &freq, sizeof(freq));
}

/* handle features reply */
void handle_features_reply(struct switch_info *sw, struct ofp_switch_features *features) {

    sw->features_received = 1;
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
    
    log_msg(sw, "Switch features:\n");
    log_msg(sw, "  Datapath ID: %016" PRIx64 "\n", sw->datapath_id);
    /*
    printf("  OpenFlow version: 0x%02x\n", sw->version);
    printf("  Number of tables: %d\n", sw->n_tables);
    printf("  Number of buffers: %d\n", ntohl(features->n_buffers));
    */
    log_msg(sw, "  Number of ports: %d\n", num_ports);
    
    /* print capabilities for debugging purposes */
    /*
    printf("  Capabilities:\n");
    uint32_t capabilities = ntohl(features->capabilities);
    if (capabilities & OFPC_FLOW_STATS)    printf("    - Flow statistics\n");
    if (capabilities & OFPC_TABLE_STATS)   printf("    - Table statistics\n");
    if (capabilities & OFPC_PORT_STATS)    printf("    - Port statistics\n");
    if (capabilities & OFPC_STP)           printf("    - 802.1d spanning tree\n");
    if (capabilities & OFPC_IP_REASM)      printf("    - IP reasm\n");
    if (capabilities & OFPC_QUEUE_STATS)   printf("    - Queue statistics\n");
    if (capabilities & OFPC_ARP_MATCH_IP)  printf("    - ARP match IP\n");
    */

    /* Print ports for debugging purposes */
    // int i;
    // for (i = 0; i < num_ports; i++) {
    //     struct ofp_phy_port *port = &sw->ports[i];
    //     printf("\nPort %d:\n", ntohs(port->port_no));
    //     printf("  Name: %s\n", port->name);
    //     printf("  HW Addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
    //             port->hw_addr[0], port->hw_addr[1], port->hw_addr[2],
    //             port->hw_addr[3], port->hw_addr[4], port->hw_addr[5]);
        
    //     /* print port state */
    //     if (ntohl(port->state) & OFPPS_LINK_DOWN)
    //         printf("  State: Link down\n");
    //     else
    //         printf("  State: Link up\n");
            
    //     /* print port features */
        
    //     /*
    //     uint32_t curr = ntohl(port->curr);
    //     printf("  Current features:\n");
    //     if (curr & OFPPF_10MB_HD)    printf("    - 10Mb half-duplex\n");
    //     if (curr & OFPPF_10MB_FD)    printf("    - 10Mb full-duplex\n");
    //     if (curr & OFPPF_100MB_HD)   printf("    - 100Mb half-duplex\n");
    //     if (curr & OFPPF_100MB_FD)   printf("    - 100Mb full-duplex\n");
    //     if (curr & OFPPF_1GB_HD)     printf("    - 1Gb half-duplex\n");
    //     if (curr & OFPPF_1GB_FD)     printf("    - 1Gb full-duplex\n");
    //     if (curr & OFPPF_10GB_FD)    printf("    - 10Gb full-duplex\n");
    //     if (curr & OFPPF_COPPER)     printf("    - Copper\n");
    //     if (curr & OFPPF_FIBER)      printf("    - Fiber\n");
    //     if (curr & OFPPF_AUTONEG)    printf("    - Auto-negotiation\n");
    //     if (curr & OFPPF_PAUSE)      printf("    - Pause\n");
    //     if (curr & OFPPF_PAUSE_ASYM) printf("    - Asymmetric pause\n");
    //     */
    // }

    /* add switch to topology */
    
    handle_switch_join(sw);
    log_msg(sw, "Added switch to topolgy\n");
}

/* ------------------------------------------------------- ECHO ---------------------------------------------------- */

/* send echo request */
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

            log_msg(sw, "Echo request sent to switch (XID: %u)\n", sw->datapath_id, ntohl(echo.xid));
        }
        pthread_mutex_unlock(&sw->lock);
        
        return success;
    }
    log_msg(sw, "Echo request already pending for switch \n");
    return false;
}

/* handle echo reply messages */
void handle_echo_reply(struct switch_info *sw, struct ofp_header *oh) {
    pthread_mutex_lock(&sw->lock);
    
    /* update both last reply and last echo time */
    sw->last_echo_reply = time(NULL);
    sw->echo_pending = false;  /* Mark that anothe echo can be send, meaning echos have vbeen recienved */

    /* for debugging */
    log_msg(sw, "Echo reply received from switch (XID: %u)\n", ntohl(oh->xid));
    
    pthread_mutex_unlock(&sw->lock);
}

/* handle echo requests */
void handle_echo_request(struct switch_info *sw, struct ofp_header *oh) {
    struct ofp_header echo;
    
    /* simply change the type to reply and send it back */
    memcpy(&echo, oh, sizeof(echo));
    echo.type = OFPT_ECHO_REPLY;
    
    send_openflow_msg(sw, &echo, sizeof(echo));
}

/* ------------------------------------------------ SWITCH MESSAGING ----------------------------------------------- */

/* handle port status changes */
void handle_port_status(struct switch_info *sw, struct ofp_port_status *ps) {
    if (!ps) {
        log_msg(sw, "ERROR: Null port_status message\n");
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
            handle_port_change(sw, ntohs(port->port_no), true);
            log_msg(sw, "Port %hu added for switch\n",port->port_no);
            break;
        case OFPPR_DELETE:
            reason_str = "PORT REMOVED";
            handle_port_change(sw, ntohs(port->port_no), false);
            log_msg(sw, "Port %hu removed for switch\n",port->port_no);
            break;
        case OFPPR_MODIFY:

            /* the handle discovery packet function handles both adding and updateding connections */
            reason_str = "PORT MODIFIED";
            handle_port_change(sw, ntohs(port->port_no), true);
            log_msg(sw, "Port %hu modified for switch \n",port->port_no);
            break;
        default:
            reason_str = "UNKNOWN";
    }
    
    /* log the port status change */
    log_msg(sw, "\nPort status change on switch:\n");
    log_msg(sw, "  Port: %u (%s)\n", ntohs(port->port_no), port->name);
    log_msg(sw, "  Reason: %s\n", reason_str);
    log_msg(sw, "  State: %s\n", state_str);
    log_msg(sw, "  Hardware Addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
            port->hw_addr[0], port->hw_addr[1], port->hw_addr[2],
            port->hw_addr[3], port->hw_addr[4], port->hw_addr[5]);
    
    pthread_mutex_unlock(&sw->lock);
}

/* handle incoming packets from the switch */
void handle_packet_in(struct switch_info *sw, struct ofp_packet_in *pi) {
    if (!pi) {
        log_msg(sw, "ERROR: Null packet_in message\n");
        return;
    }

    log_msg(sw, "Packet in details: reason=%d, port=%d, buffer_id=%u, data_len=%u\n", 
       pi->reason, ntohs(pi->in_port), ntohl(pi->buffer_id), ntohs(pi->total_len));

    /* lock switch for thread safety while accessing switch info */
    pthread_mutex_lock(&sw->lock);
    
    /* increment packet counter */
    sw->packet_in_count++;

    /* first check if its a topology discovery packet */
    log_msg(sw, "Checking for topology discovery packet\n");
    if(is_topology_discovery_packet(pi->data, ntohs(pi->total_len))) {
        handle_discovery_packet(sw, pi);
        log_msg(sw, "Topology discovery packet received from switch \n");
        pthread_mutex_unlock(&sw->lock);
        return; /* return succesfully */
    }
    
    /* extract basic packet information */
    uint16_t in_port = ntohs(pi->in_port);

    log_msg(sw, "This is a regular packet in (not discovery)\n");
    log_msg(sw, "Preparing to insall flow\n");
    /* extract information used for the flow resulting from this packet */
    uint8_t *eth_frame = pi->data;
    uint8_t *dst_mac = eth_frame + ETH_DST_OFFSET;
    uint8_t *src_mac = eth_frame + ETH_SRC_OFFSET;
    // uint16_t eth_type = ntohs(*(uint16_t *)(eth_frame + ETH_ETHERTYPE_OFFSET));


    log_msg(sw, "Learning MAC %02x:%02x:%02x:%02x:%02x:%02x on switch port %d\n",
        src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], in_port);

    /* add or update source mac to mac table */
    add_or_update_mac(src_mac, sw->datapath_id, in_port);

    /*
    printf("  Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            src_mac[0], src_mac[1], src_mac[2], 
            src_mac[3], src_mac[4], src_mac[5]);
    printf("  Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
            dst_mac[0], dst_mac[1], dst_mac[2],
            dst_mac[3], dst_mac[4], dst_mac[5]);
    */


    struct mac_entry *dst = find_mac(dst_mac);

    /* case for OFPR_ACTION */
    static const uint8_t BROADCAST_MAC[MAC_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    if (memcmp(dst_mac, BROADCAST_MAC, MAC_ADDR_LEN)){ /* broadcast/multicast bit set*/
        log_msg(sw, "Broadcast packet\n");
        handle_broadcast_packet(sw, pi, find_mac(src_mac));

    } else {

        /* unicast packet */
        if (dst) { /* destination found in table so install a flow based on that */
            log_msg(sw, "Destination MAC found in table sending unicast message\n");
            handle_unicast_packet(sw, pi, dst);





            
        } else { /* destination not found in table so flood similar to broadcast */

            log_msg(sw, "Destination MAC not found in table, flooding with broadcast \n");
            handle_broadcast_packet(sw, pi, find_mac(src_mac));
            
        }
    }

    /* log packet information 
    printf("\nPACKET_IN from switch %016" PRIx64 ":\n", sw->datapath_id);
    printf("  Buffer ID: %u\n", buffer_id);
    printf("  Total Length: %u bytes\n", total_len);
    printf("  In Port: %u\n", in_port);
    printf("  Reason: %s\n", reason_str);
    */

    pthread_mutex_unlock(&sw->lock);
}

/* --------------------------------------------- ROUTING/FLOW INSTALLATION ----------------------------------------- */

void handle_unicast_packet(struct switch_info *sw, struct ofp_packet_in *pi, struct mac_entry *dst){

    log_msg(sw, "DEBUG: Attempting unicast path from switch to switch %016" PRIx64 "\n", dst->switch_dpid);

    /* extract data */
    uint64_t src_dpid = sw->datapath_id;
    uint64_t dst_dpid = dst->switch_dpid;
    uint16_t in_port = ntohs(pi->in_port);
    uint16_t out_port = dst->port_no;

    if (src_dpid == dst_dpid){

        /* install flow to self */
        install_flow(sw, in_port, out_port, ntohl(pi->buffer_id), dst);
        send_packet_out(sw, in_port, out_port, pi->buffer_id, pi->data, ntohs(pi->total_len));
        return;
    }

    /* initialize vectors to store results */
    pthread_mutex_lock(&topology.lock);
    igraph_integer_t src_vertex_id = find_vertexid(src_dpid);
    igraph_integer_t dst_vertex_id = find_vertexid(dst_dpid);
    pthread_mutex_unlock(&topology.lock);

    /* flood packet as backup */
    if (src_vertex_id < 0 || dst_vertex_id < 0) {
        log_msg(sw, "ERROR: Can't find vertices for path calculation\n");
    
        /* CONSTRUCT PACKET OUT */

        return;
    }

    /* calculate shortest path */
    
    /* init vectors for funciton call, path stored here */
    igraph_vector_int_t vertices;
    igraph_vector_int_t edges;

    igraph_vector_int_init(&vertices, 0);
    igraph_vector_int_init(&edges, 0);

    pthread_mutex_lock(&topology.lock);
    igraph_error_t result = igraph_get_shortest_path(&topology.graph, &vertices, &edges, src_vertex_id, dst_vertex_id, IGRAPH_OUT);
    if(result != IGRAPH_SUCCESS) {
        log_msg(sw, "ERROR: Failed to calculate shortest path\n");
        igraph_vector_int_destroy(&vertices);
        igraph_vector_int_destroy(&edges);
        return;
    }
    pthread_mutex_unlock(&topology.lock);

    /* INSTALL FLOWS FOR EACH SWITCH IN THE GRAPH */
    igraph_integer_t num_edges = igraph_vector_int_size(&edges);
    igraph_integer_t i;
    if (num_edges == 0) {
        log_msg(sw, "No path found between switches\n");
        return;
    }

    uint16_t src_port, dst_port = -1;
    uint64_t curr_src_dpid = -1;
    for (i = 0; i < num_edges; i++){
        igraph_integer_t edge_id = VECTOR(edges)[i]; /* edges is result of finding minimum path */
        igraph_integer_t src_vertex, dst_vertex;
        

        pthread_mutex_lock(&topology.lock);
        igraph_edge(&topology.graph, edge_id, &src_vertex, &dst_vertex);

        
        /* extract port info from edge */
        igraph_integer_t src_port_from_edge = -1;
        src_port_from_edge = igraph_cattribute_EAN(&topology.graph, "src_port", edge_id);
        if (src_port_from_edge <= 65535){
            src_port = (uint16_t)src_port_from_edge;
            log_msg(sw, "DEBUG: Using src_port = %d\n", src_port);
        } else {
            log_msg(sw, "ERROR: Failed to extract port info from edge\n");
            pthread_mutex_unlock(&topology.lock);
            igraph_vector_int_destroy(&vertices);
            igraph_vector_int_destroy(&edges);
            return;
        }
        igraph_integer_t dst_port_from_edge = -1;
        dst_port_from_edge = igraph_cattribute_EAN(&topology.graph, "dst_port", edge_id);
        if (dst_port_from_edge <= 65535){
            dst_port = (uint16_t)dst_port_from_edge;
            log_msg(sw, "DEBUG: Using dst_port = %d\n", dst_port);
        } else {
            log_msg(sw, "ERROR: Failed to extract port info from edge\n");
            pthread_mutex_unlock(&topology.lock);
            igraph_vector_int_destroy(&vertices);
            igraph_vector_int_destroy(&edges);
            return;
        }
        igraph_integer_t src_dpid_from_edge = -1;
        src_dpid_from_edge = igraph_cattribute_EAN(&topology.graph, "src_dpid", edge_id);
        if(src_dpid_from_edge > 0){
            curr_src_dpid = (uint64_t)src_dpid_from_edge;
        } else {
            log_msg(sw, "ERROR: Failed to extract dpid info from edge\n");
            pthread_mutex_unlock(&topology.lock);
            igraph_vector_int_destroy(&vertices);
            igraph_vector_int_destroy(&edges);
            return;
        }

        /* get the switch associated with the dpid at src of edge */
        struct switch_info *src_sw = NULL;
        int i;
        for (i = 0; i < MAX_SWITCHES; i++) {
            if (switches[i].active && switches[i].datapath_id == curr_src_dpid) {
                src_sw = &switches[i];
                break;
            }
        }

        if (src_sw == NULL){
            log_msg(sw, "ERROR: Failed to find switch with dpid %016" PRIx64 "\n", curr_src_dpid);
            pthread_mutex_unlock(&topology.lock);
            igraph_vector_int_destroy(&vertices);
            igraph_vector_int_destroy(&edges);
            return;
        }
        pthread_mutex_unlock(&topology.lock);


        log_msg(sw, "DEBUG: Edge attributes - src_dpid=%f, dst_dpid=%f, src_port=%f, dst_port=%f\n",
            igraph_cattribute_EAN(&topology.graph, "src_dpid", edge_id),
            igraph_cattribute_EAN(&topology.graph, "dst_dpid", edge_id),
            igraph_cattribute_EAN(&topology.graph, "src_port", edge_id),
            igraph_cattribute_EAN(&topology.graph, "dst_port", edge_id));


        /* install flow */
        install_flow(src_sw, src_port, dst_port, ntohl(pi->buffer_id), dst);

        /* log flow installation */
        log_msg(sw, "Flow installed on switch %016" PRIx64 ":\n", src_dpid);
    }

    /* after all flows are installed send a packet out */
    send_packet_out(sw, src_port, dst_port, pi->buffer_id, pi->data, ntohs(pi->total_len));

    /* clean up */
    igraph_vector_int_destroy(&vertices);
    igraph_vector_int_destroy(&edges);

}

bool test_simple_flow_mod(struct switch_info *sw, uint16_t in_port, uint16_t out_port) {
    log_msg(sw, "DEBUG: Testing minimal flow mod: in_port=%d -> out_port=%d\n", in_port, out_port);
    
    // Minimal flow mod message
    int action_len = sizeof(struct ofp_action_output);
    int total_len = sizeof(struct ofp_flow_mod) + action_len;
    
    struct ofp_flow_mod *fm = malloc(total_len);
    if (!fm) {
        log_msg(sw, "ERROR: Memory allocation failed\n");
        return false;
    }
    
    memset(fm, 0, total_len);
    
    // Header
    fm->header.version = OFP_VERSION;
    fm->header.type = OFPT_FLOW_MOD;
    fm->header.length = htons(total_len);
    fm->header.xid = htonl(0);  // Fixed XID for easier debugging
    
    // Match only on in_port
    fm->match.wildcards = htonl(OFPFW_ALL & ~OFPFW_IN_PORT);
    fm->match.in_port = htons(in_port);
    
    // Minimal flow parameters
    fm->command = htons(OFPFC_ADD);
    fm->idle_timeout = htons(10);  // Short timeout
    fm->hard_timeout = htons(0);   // No hard timeout
    fm->priority = htons(100);     // Lower than default
    fm->buffer_id = htonl(0xFFFFFFFF);  // NO_BUFFER
    fm->flags = 0;
    
    // Single output action
    struct ofp_action_output *action = (struct ofp_action_output *)fm->actions;
    action->type = htons(OFPAT_OUTPUT);
    action->len = htons(sizeof(struct ofp_action_output));
    action->port = htons(out_port);
    action->max_len = htons(0);
    
    // Add a delay before sending
    usleep(50000);  // 50ms pause to ensure the connection is stable
    
    log_msg(sw, "DEBUG: Sending minimal test flow mod\n");
    pthread_mutex_lock(&sw->lock);
    
    if (!sw->active) {
        log_msg(sw, "ERROR: Switch inactive before flow mod\n");
        pthread_mutex_unlock(&sw->lock);
        free(fm);
        return false;
    }
    
    // Send with more careful error handling
    ssize_t sent = send(sw->socket, fm, total_len, 0);
    if (sent < 0) {
        log_msg(sw, "ERROR: Flow mod send failed: %s\n", strerror(errno));
        pthread_mutex_unlock(&sw->lock);
        free(fm);
        return false;
    } else if (sent < total_len) {
        log_msg(sw, "WARNING: Partial flow mod send: %zd of %d bytes\n", sent, total_len);
    } else {
        log_msg(sw, "SUCCESS: Sent complete flow mod: %zd bytes\n", sent);
    }
    
    // Add another delay after sending
    usleep(50000);  // 50ms pause
    
    if (!sw->active) {
        log_msg(sw, "ERROR: Switch inactive immediately after flow mod\n");
        pthread_mutex_unlock(&sw->lock);
        free(fm);
        return false;
    }
    
    pthread_mutex_unlock(&sw->lock);
    free(fm);
    return true;
}

void handle_broadcast_packet(struct switch_info *sw, struct ofp_packet_in *pi, struct mac_entry *src) {
    uint16_t packet_in_port = ntohs(pi->in_port);
    uint64_t packet_in_dpid = sw->datapath_id;

    
    
    /* calculate MST of the network */
    igraph_vector_int_t mst_edges;
    igraph_vector_int_init(&mst_edges, 0);

    pthread_mutex_lock(&topology.lock);
    igraph_error_t result = igraph_minimum_spanning_tree(&topology.graph, &mst_edges, NULL);
    if(result != IGRAPH_SUCCESS) {
        log_msg(sw, "ERROR: Failed to calculate minimum spanning tree\n");
        igraph_vector_int_destroy(&mst_edges);
        pthread_mutex_unlock(&topology.lock);
        return;
    }
    
    igraph_integer_t num_edges = igraph_vector_int_size(&mst_edges);
    log_msg(sw, "MST calculation result: %d, found %lld edges\n", result, num_edges);
    
    /* extract edge information (code remains the same) */
    struct mst_edge {
        uint64_t src_dpid;
        uint64_t dst_dpid;
        uint16_t src_port;
        uint16_t dst_port;
    };
    
    struct mst_edge *edges = malloc(num_edges * sizeof(struct mst_edge));
    if (!edges) {
        log_msg(sw, "ERROR: Failed to allocate memory for MST edges\n");
        igraph_vector_int_destroy(&mst_edges);
        pthread_mutex_unlock(&topology.lock);
        return;
    }
    
    /* extract edge information */
    for (igraph_integer_t i = 0; i < num_edges; i++) {
        igraph_integer_t edge_id = VECTOR(mst_edges)[i];
        
        edges[i].src_dpid = (uint64_t)EAN(&topology.graph, "src_dpid", edge_id);
        edges[i].dst_dpid = (uint64_t)EAN(&topology.graph, "dst_dpid", edge_id);
        edges[i].src_port = (uint16_t)EAN(&topology.graph, "src_port", edge_id);
        edges[i].dst_port = (uint16_t)EAN(&topology.graph, "dst_port", edge_id);
        
        log_msg(sw, "MST Edge %lld: src_dpid=%llu (port %d) -> dst_dpid=%llu (port %d)\n",
               i, edges[i].src_dpid, edges[i].src_port, edges[i].dst_dpid, edges[i].dst_port);
    }
    pthread_mutex_unlock(&topology.lock);
    log_msg(sw, "MST edges extracted\n");
    
    /* create broadcast MAC entry */
    struct mac_entry *bcast_entry = malloc(sizeof(struct mac_entry));
    if (!bcast_entry) {
        log_msg(sw, "ERROR: Failed to allocate memory for broadcast MAC entry\n");
        free(edges);
        igraph_vector_int_destroy(&mst_edges);
        return;
    }
    memset(bcast_entry, 0, sizeof(struct mac_entry));
    memset(bcast_entry->mac, 0xFF, MAC_ADDR_LEN);
    
    /* process the switch that received the packet first */
    /* we need to find all MST ports on this switch, excluding the incoming port */
    uint16_t out_ports[MAX_PORTS_PER_SWITCH];
    int num_out_ports = 0;
    
    /* add all MST ports except the incoming port */
    log_msg(sw, "Processing switch for broadcast, identifying output ports\n", packet_in_dpid);
    for (igraph_integer_t i = 0; i < num_edges; i++) {
        if (edges[i].src_dpid == packet_in_dpid) {
            if (edges[i].src_port != packet_in_port) {
                out_ports[num_out_ports++] = edges[i].src_port;
            }
        } else if (edges[i].dst_dpid == packet_in_dpid) {
            if (edges[i].dst_port != packet_in_port) {
                out_ports[num_out_ports++] = edges[i].dst_port;
            }
        }
    }
    
    /* also add access ports (ports that connect to hosts, not in MST) */
    int i;
    for (i = 0; i < sw->num_ports; i++) {
        uint16_t port_no = ntohs(sw->ports[i].port_no);
        if (port_no < OFPP_MAX && port_no != packet_in_port) {
            /* check if this port is already in out_ports (part of MST) */
            bool is_mst_port = false;
            for (int j = 0; j < num_out_ports; j++) {
                if (out_ports[j] == port_no) {
                    is_mst_port = true;
                    break;
                }
            }
            
            /* if not part of MST and not the incoming port, add it */
            if (!is_mst_port) {
                out_ports[num_out_ports++] = port_no;
            }
        }
    }

    // In your handle_broadcast_packet function:
    if (test_simple_flow_mod(sw, packet_in_port, out_ports[0])) {
        log_msg(sw, "Simple flow mod test succeeded\n");
        // Continue with the rest of your broadcast handling
    } else {
        log_msg(sw, "Simple flow mod test failed, skipping MST flows\n");
        // Just send packet out instead
        for (int i = 0; i < num_out_ports; i++) {
            send_packet_out(sw, packet_in_port, out_ports[i], 
                        (i == 0) ? ntohl(pi->buffer_id) : 0xFFFFFFFF, 
                        pi->data, ntohs(pi->total_len));
        }
    }
    
    
    /* install separate flow for each output port */
    log_msg(sw, "Installing %d separate broadcast flows on switch %016" PRIx64 "\n", 
            num_out_ports, packet_in_dpid);
    
    for (i = 0; i < num_out_ports; i++) {
        install_single_output_flow(sw, packet_in_port, out_ports[i], 0xFFFFFFFF, bcast_entry);
        /* add small delay between flow installations */
        usleep(10000); /* 10ms delay */
    }

    
    /* Now process other switches in the MST - similar to before */
    for (int i = 0; i < MAX_SWITCHES; i++) {
        if (switches[i].active && switches[i].datapath_id != packet_in_dpid) {
            struct switch_info *other_sw = &switches[i];
            uint64_t other_dpid = other_sw->datapath_id;
            
            uint16_t ingress_port = OFPP_NONE;
            for (igraph_integer_t j = 0; j < num_edges; j++) {
                if (edges[j].src_dpid == other_dpid || edges[j].dst_dpid == other_dpid) {
                    if (edges[j].src_dpid == other_dpid) {
                        ingress_port = edges[j].src_port;
                    } else {
                        ingress_port = edges[j].dst_port;
                    }
                    break;
                }
            }
            
            if (ingress_port != OFPP_NONE) {
                uint16_t other_out_ports[MAX_PORTS_PER_SWITCH];
                int other_num_out_ports = 0;
                
                for (igraph_integer_t k = 0; k < num_edges; k++) {
                    if (edges[k].src_dpid == other_dpid && edges[k].src_port != ingress_port) {
                        other_out_ports[other_num_out_ports++] = edges[k].src_port;
                    }
                    if (edges[k].dst_dpid == other_dpid && edges[k].dst_port != ingress_port) {
                        other_out_ports[other_num_out_ports++] = edges[k].dst_port;
                    }
                }
                
                for (int p = 0; p < other_sw->num_ports; p++) {
                    uint16_t port_no = ntohs(other_sw->ports[p].port_no);
                    if (port_no < OFPP_MAX && port_no != ingress_port) {
                        bool is_mst_port = false;
                        for (int q = 0; q < other_num_out_ports; q++) {
                            if (other_out_ports[q] == port_no) {
                                is_mst_port = true;
                                break;
                            }
                        }
                        
                        if (!is_mst_port) {
                            other_out_ports[other_num_out_ports++] = port_no;
                        }
                    }
                }
                
                log_msg(sw, "Installing %d separate broadcast flows on other switch %016" PRIx64 "\n", 
                        other_num_out_ports, other_dpid);
                
                for (int p = 0; p < other_num_out_ports; p++) {
                    install_single_output_flow(other_sw, ingress_port, other_out_ports[p], 
                                              0xFFFFFFFF, bcast_entry);
                    usleep(10000); /* Add slight delay between installations */
                }
            }
        }
    }
    
    /* Send packet out on first switch - no change needed */
    if (num_out_ports > 0) {
        uint32_t buffer_id = ntohl(pi->buffer_id);
        
        for (int i = 0; i < num_out_ports; i++) {
            /* For each output port, send the packet out */
            send_packet_out(sw, packet_in_port, out_ports[i], 
                          (i == 0) ? buffer_id : 0xFFFFFFFF, 
                          pi->data, ntohs(pi->total_len));
        }
    }
    
    /* Clean up */
    free(bcast_entry);
    free(edges);
    igraph_vector_int_destroy(&mst_edges);
}

/* function for installing a flow to a switch once links have been discovered */
void install_flow(struct switch_info *sw, uint16_t in_port, uint16_t dst_port, uint32_t buff_id, struct mac_entry *dst){
    
    if(dst_port < 0 || in_port < 0){
        log_msg(sw, "ERROR: Invalid port number in attempeted flow install\n");
        return;
    }

    log_msg(sw, "DEBUG: Installing flow on switch %016" PRIx64 ": in_port=%d -> out_port=%d, dst_mac=%02x:%02x:%02x:%02x:%02x:%02x\n", 
           sw->datapath_id, in_port, dst_port,
           dst->mac[0], dst->mac[1], dst->mac[2], dst->mac[3], dst->mac[4], dst->mac[5]);

    log_msg(sw, "Current topology: %lld vertices, %lld edges\n", 
       igraph_vcount(&topology.graph), 
       igraph_ecount(&topology.graph));

    int action_len = sizeof(struct ofp_action_output);
    int total_len = sizeof(struct ofp_flow_mod) + action_len;

    struct ofp_flow_mod * fm = malloc(total_len); 
    if (!fm) {
        log_msg(sw, "ERROR: Failed to allocate memory for flow_mod\n");
        return;
    }
    memset(fm, 0, total_len);

    /*
    1. Create the flow_mod message
    2. Set up the match fields (match incoming port and maybe MAC addresses)
    3. Set up the action (forward to outgoing port)
    4. Set appropriate timeouts and flags
    5. Send the message to the switch
    */

    /* setup the ofp header first */
    fm->header.version = OFP_VERSION;
    fm->header.type = OFPT_FLOW_MOD;
    fm->header.length = htons(total_len);
    fm->header.xid = htonl(sw->packet_in_count++);

    /* initialize the wildcards to match on in port and destinatin mac */
    fm->match.wildcards = htonl(OFPFW_ALL & ~OFPFW_IN_PORT & ~OFPFW_DL_DST);
    fm->match.in_port = htons(in_port);
    memcpy(fm->match.dl_dst, dst->mac, OFP_ETH_ALEN);

    fm->command = htons(OFPFC_ADD); /* new flow */
    fm->idle_timeout = htons(60); /* 60 seconds idle timeout */
    fm->hard_timeout = htons(300); /* 300 seconds hard timeout */
    fm->priority = htons(OFP_DEFAULT_PRIORITY); /* default priority */
    fm->buffer_id = htonl(buff_id); /* buffer id */    
    fm->flags = htons(OFPFF_SEND_FLOW_REM); /* get flow removal notifications */

    /* setup the action which tells swithc to ouput a specified port for this packet */
    struct ofp_action_output *action = (struct ofp_action_output *)fm->actions;
    action->type = htons(OFPAT_OUTPUT);
    action->len = htons(sizeof(struct ofp_action_output));
    action->port = htons(dst_port);
    action->max_len = htons(0); /* no buffer limit */

    log_msg(sw, "DEBUG: Flow details: wildcards=0x%x, match.in_port=%d, action.port=%d\n",
           ntohl(fm->match.wildcards), ntohs(fm->match.in_port), ntohs(action->port));

    /* send the flow_mod message to the switch */
    send_openflow_msg(sw, fm, total_len);

    log_msg(sw, "DEBUG: Flow installation complete for switch, buffer ID: %u\n", 
           sw->datapath_id, buff_id);

    free(fm);
}

void install_single_output_flow(struct switch_info *sw, uint16_t in_port, uint16_t out_port, 
                              uint32_t buffer_id, struct mac_entry *dst) {
    if(out_port < 0 || in_port < 0) {
        log_msg(sw, "ERROR: Invalid port number in attempted flow install\n");
        return;
    }

    log_msg(sw, "DEBUG: Installing single output flow on switch %016" PRIx64 ": in_port=%d -> out_port=%d\n", 
            sw->datapath_id, in_port, out_port);

    int action_len = sizeof(struct ofp_action_output);
    int total_len = sizeof(struct ofp_flow_mod) + action_len;

    struct ofp_flow_mod *fm = malloc(total_len); 
    if (!fm) {
        log_msg(sw, "ERROR: Failed to allocate memory for flow_mod\n");
        return;
    }
    memset(fm, 0, total_len);

    /* setup header */
    fm->header.version = OFP_VERSION;
    fm->header.type = OFPT_FLOW_MOD;
    fm->header.length = htons(total_len);
    fm->header.xid = htonl(sw->packet_in_count++);

    /* match on in_port and broadcast MAC */
    fm->match.wildcards = htonl(OFPFW_ALL & ~OFPFW_IN_PORT & ~OFPFW_DL_DST);
    fm->match.in_port = htons(in_port);
    memcpy(fm->match.dl_dst, dst->mac, OFP_ETH_ALEN);

    /* set flow parameters */
    fm->command = htons(OFPFC_ADD);
    fm->idle_timeout = htons(60);   /* 60 seconds idle timeout */
    fm->hard_timeout = htons(300);  /* 5 minutes hard timeout */
    fm->priority = htons(OFP_DEFAULT_PRIORITY);
    fm->buffer_id = htonl(0xFFFFFFFF); /* Don't use buffer ID for these flows */
    fm->flags = htons(OFPFF_SEND_FLOW_REM);

    /* setup action for single output port */
    struct ofp_action_output *action = (struct ofp_action_output *)fm->actions;
    action->type = htons(OFPAT_OUTPUT);
    action->len = htons(sizeof(struct ofp_action_output));
    action->port = htons(out_port);
    action->max_len = htons(0);

    /* send flow mod to switch */
    log_msg(sw, "DEBUG: SENDING SIGNLE OUPUT FLOW TO SWITCH %016" PRIx64 ": in_port=%d -> out_port=%d\n", 
            sw->datapath_id, in_port, out_port);
    send_openflow_msg(sw, fm, total_len);
    
    log_msg(sw, "DEBUG: Single output flow installed on switch %016" PRIx64 ": in_port=%d -> out_port=%d\n", 
            sw->datapath_id, in_port, out_port);

    free(fm);
}

/* a function for sending packet out fucntion to a swtich */
void send_packet_out(struct switch_info *sw, uint16_t in_port, uint16_t out_port, 
                    uint32_t buffer_id, uint8_t *data, size_t len) {
    
    if (in_port < 0 || out_port < 0) {
        log_msg(sw, "ERROR: Invalid port number in attempted packet out\n");
        return;
    }

    // Calculate size - if using buffer_id, we don't need to include data
    int action_len = sizeof(struct ofp_action_output);
    int data_len = (buffer_id == 0xFFFFFFFF) ? len : 0;
    int total_len = sizeof(struct ofp_packet_out) + action_len + data_len;
    
    struct ofp_packet_out *po = malloc(total_len);
    if (!po) {
        printf("Error: Failed to allocate memory for packet_out\n");
        return;
    }
    memset(po, 0, total_len);

    po->header.version = OFP_VERSION;
    po->header.type = OFPT_PACKET_OUT;
    po->header.length = htons(total_len);
    po->header.xid = htonl(sw->packet_in_count++);

    po->buffer_id = htonl(buffer_id);
    po->in_port = htons(in_port);
    po->actions_len = htons(sizeof(struct ofp_action_output));

    struct ofp_action_output *action = (struct ofp_action_output *)po->actions;
    action->type = htons(OFPAT_OUTPUT);
    action->len = htons(sizeof(struct ofp_action_output));
    action->port = htons(out_port);
    action->max_len = htons(0);

    // Only copy data if we're not using a buffer_id
    if (buffer_id == 0xFFFFFFFF && data != NULL) {
        memcpy((uint8_t *)po + sizeof(struct ofp_packet_out) + action_len, data, len);
    }

    send_openflow_msg(sw, po, total_len);

    log_msg(sw, "Packet out sent to switch %016" PRIx64 ": in_port=%d, out_port=%d, buffer_id=%s\n", 
           sw->datapath_id, in_port, out_port, 
           (buffer_id == 0xFFFFFFFF) ? "NO_BUFFER" : "BUFFERED");

    free(po);
}