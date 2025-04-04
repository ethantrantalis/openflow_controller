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
#include <fcntl.h>
#include </usr/include/igraph/igraph.h>
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

/* ------------------------------------------------------ GLOBAL --------------------------------------------------- */

/* global variables */
struct switch_info switches[MAX_SWITCHES];
pthread_mutex_t switches_lock = PTHREAD_MUTEX_INITIALIZER;
int server_socket;
volatile int running = 1; /* for controller clean up and running */
struct network_topology topology;


#define MESSAGE_QUEUE_TIMEOUT 5  /* 5 seconds timeout for queued messages */

/* ---------------------------------------------------- FLOW TABLE ------------------------------------------------- */

/* add a new flow entry */
bool add_flow_entry(struct switch_info *sw, uint64_t dpid, uint16_t in_port, uint8_t *dst_mac, uint16_t out_port) {


    log_msg(sw, "DEBUG: Adding new flow to switch flow table with dpid %016" PRIx64 " in_port %u dst_mac %02x:%02x:%02x:%02x:%02x:%02x out_port %u\n",
            dpid, in_port, dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], out_port);
    //log_msg(sw, "MUTEX: Locking flow table\n");
    pthread_mutex_lock(&sw->flow_table_lock);    
    /* first check if the flow already exists */
    for (int i = 0; i < sw->num_flows; i++) {
        if (sw->flow_table[i].active && 
            sw->flow_table[i].switch_dpid == dpid &&
            sw->flow_table[i].in_port == in_port &&
            memcmp(sw->flow_table[i].dst_mac, dst_mac, MAC_ADDR_LEN) == 0 &&
            sw->flow_table[i].out_port == out_port) {
            
            /* flow exists, update timestamp */
            sw->flow_table[i].install_time = time(NULL);
            log_msg(sw, "DEBUG: Flow already exists, updating timestamp\n");

            pthread_mutex_unlock(&sw->flow_table_lock);
            // log_msg(sw, "MUTEX: Unlocked flow table\n");
            return false;  /* flow wasn't newly added */
        }
    }
    
    /* check if we have room for a new flow */
    if (sw->num_flows >= MAX_FLOWS) {
        log_msg(NULL, "ERROR: Flow table full, cannot add new flow\n");

        pthread_mutex_unlock(&sw->flow_table_lock);
        // log_msg(sw, "MUTEX: Unlocked flow table\n");

        return false;
    }
    
    /* add new flow */
    sw->flow_table[sw->num_flows].switch_dpid = dpid;
    sw->flow_table[sw->num_flows].in_port = in_port;
    memcpy(sw->flow_table[sw->num_flows].dst_mac, dst_mac, MAC_ADDR_LEN);
    sw->flow_table[sw->num_flows].out_port = out_port;
    sw->flow_table[sw->num_flows].install_time = time(NULL);
    sw->flow_table[sw->num_flows].active = true;
    sw->num_flows++;
    log_msg(sw, "DEBUG: Added new flow to switch flow table\n");
    
    pthread_mutex_unlock(&sw->flow_table_lock);
    // log_msg(sw, "MUTEX: Unlocked flow table\n");
    return true;  /* new flow was added */
}

/* check if a flow exists */
bool flow_exists(struct switch_info * sw, uint64_t dpid, uint16_t in_port, uint8_t *dst_mac, uint16_t out_port) {
    bool exists = false;
    
    // log_msg(sw, "MUTEX: Locking flow table\n");
    pthread_mutex_lock(&sw->flow_table_lock);

    for (int i = 0; i < sw->num_flows; i++) {
        if (sw->flow_table[i].active && 
            sw->flow_table[i].switch_dpid == dpid &&
            sw->flow_table[i].in_port == in_port &&
            memcmp(sw->flow_table[i].dst_mac, dst_mac, MAC_ADDR_LEN) == 0 &&
            sw->flow_table[i].out_port == out_port) {
            
            exists = true;
            break;
        }
    }
    
    /* exit with existance of flow */
    pthread_mutex_unlock(&sw->flow_table_lock);
    // log_msg(sw, "MUTEX: Unlocked flow table\n");
    return exists;
}

/* -------------------------------------------------- PORT VALIDATION ---------------------------------------------- */

/* check if a port number is valid */
bool is_valid_port(uint16_t port_no) {

    /* Check that it's a valid physical port or special port */
    if (port_no < OFPP_MAX) {
        return true;
    }
    
    /* check if it's a valid special port */
    switch (port_no) {
        case OFPP_IN_PORT:
        case OFPP_TABLE:
        case OFPP_NORMAL:
        case OFPP_FLOOD:
        case OFPP_ALL:
        case OFPP_CONTROLLER:
        case OFPP_LOCAL:
            return true;
            
        default:
            return false;
    }
}

/*
 * Determines if a port is a trunk port by checking if it's part of any link
 * between switches in the topology.
 */
bool is_trunk_port(struct switch_info * sw, uint64_t dpid, uint16_t port_no) {

    
    /* a port is a trunk port if it appears in any edge in the topology graph */
    // log_msg(sw, "MUTEX: Locking topology\n");
    pthread_mutex_lock(&topology.lock);
    for (igraph_integer_t i = 0; i < igraph_ecount(&topology.graph); i++) {
        uint64_t src_dpid = (uint64_t)EAN(&topology.graph, "src_dpid", i);
        uint64_t dst_dpid = (uint64_t)EAN(&topology.graph, "dst_dpid", i);
        uint16_t src_port = (uint16_t)EAN(&topology.graph, "src_port", i);
        uint16_t dst_port = (uint16_t)EAN(&topology.graph, "dst_port", i);
        
        /* if this port is used in this edge, it's a trunk port */
        if ((src_dpid == dpid && src_port == port_no) ||
            (dst_dpid == dpid && dst_port == port_no)) {
            
            pthread_mutex_unlock(&topology.lock);
            // log_msg(sw, "MUTEX: Unlocked topology\n");
            return true;
        }
    }
    
    pthread_mutex_unlock(&topology.lock);
    // log_msg(sw, "MUTEX: Unlocked topology\n");
    return false;
}

/* ---------------------------------------------------- MAC TABLE -------------------------------------------------- */

/* lock for the MAC table */
struct mac_entry *mac_table = NULL;
pthread_mutex_t mac_table_lock = PTHREAD_MUTEX_INITIALIZER;

/* add or update an entry */
void add_or_update_mac(struct switch_info *sw, uint8_t *mac, uint64_t dpid, uint16_t port_no, bool is_infrastructure) {
    /* first determine if this port is a trunk port */
    bool is_trunk = is_trunk_port(sw, dpid, port_no);

    log_msg(sw, "DEBUG: Adding or updating MAC %02x:%02x:%02x:%02x:%02x:%02x from switch %016" PRIx64 " port %d (is_trunk=%d, is_infrastructure=%d)\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], dpid, port_no, is_trunk, is_infrastructure);

    pthread_mutex_lock(&mac_table_lock);

    struct mac_entry *entry;
    
    /* look up existing entry */
    HASH_FIND(hh, mac_table, mac, MAC_ADDR_LEN, entry);
    
    /* no existing entry - always add new entry regardless of trunk status */
    if (entry == NULL) {
        entry = malloc(sizeof(struct mac_entry));
        if (!entry) {
            log_msg(sw, "ERROR: Failed to allocate memory for MAC entry\n");
            pthread_mutex_unlock(&mac_table_lock);
            return;
        }
        
        memcpy(entry->mac, mac, MAC_ADDR_LEN);
        entry->switch_dpid = dpid;
        entry->port_no = port_no;
        entry->last_seen = time(NULL);
        entry->is_trunk = is_trunk;
        entry->is_infrastructure = is_infrastructure;
        HASH_ADD(hh, mac_table, mac, MAC_ADDR_LEN, entry);
        
        log_msg(sw, "DEBUG: Added new MAC %02x:%02x:%02x:%02x:%02x:%02x to table for switch %016" PRIx64 " port %d (is_trunk=%d, is_infrastructure=%d)\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], dpid, port_no, is_trunk, is_infrastructure);
    }
    /* existing entry - need to decide whether to update */
    else {
        bool should_update = false;
        
        /* never update infrastructure entries with non-infrastructure entries */
        if (entry->is_infrastructure && !is_infrastructure) {
            log_msg(sw, "DEBUG: Not updating - existing entry is infrastructure, new is not\n");
        }
        /* for infrastructure entries, always update with newer infrastructure info */
        else if (is_infrastructure) {
            should_update = true;
            log_msg(sw, "DEBUG: Updating with new infrastructure info\n");
        }
        /* Ffor non-infrastructure entries, use the existing trunk port logic */
        else {
            /* new info is from non-trunk port (direct connection) */
            if (!is_trunk) {
                /* Always prefer direct connections */
                should_update = true;
                log_msg(sw, "DEBUG: Updating MAC with direct connection (old is_trunk=%d, new is_trunk=%d)\n", 
                        entry->is_trunk, is_trunk);
            }
            /* new info is from trunk port, existing entry is from trunk port */
            else if (entry->is_trunk) {
                /* update if the existing trunk entry is old or if trunk port has changed */
                time_t current_time = time(NULL);
                
                if ((current_time - entry->last_seen > 5) || 
                    (entry->switch_dpid != dpid || entry->port_no != port_no)) {
                    should_update = true;
                    log_msg(sw, "DEBUG: Updating trunk info with newer trunk info (old port=%d, new port=%d)\n",
                            entry->port_no, port_no);
                } else {
                    log_msg(sw, "DEBUG: Not updating - recent trunk info exists and hasn't changed\n");
                }
            }
            /* new info is from trunk port, existing entry is from non-trunk port */
            else {
                /* never overwrite direct connection with trunk info */
                log_msg(sw, "DEBUG: Not updating - existing direct connection preferred over trunk info\n");
            }
        }
        
        /* update the entry if our logic determined we should */
        if (should_update) {
            log_msg(sw, "DEBUG: Updating MAC %02x:%02x:%02x:%02x:%02x:%02x from switch %016" PRIx64 " port %d to switch %016" PRIx64 " port %d\n",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 
                   entry->switch_dpid, entry->port_no, dpid, port_no);
                   
            entry->switch_dpid = dpid;
            entry->port_no = port_no;
            entry->last_seen = time(NULL);
            entry->is_trunk = is_trunk;
            
            /* only update the infrastructure flag if we're explicitly setting it to true */
            if (is_infrastructure) {
                entry->is_infrastructure = true;
            }
        }
    }

    pthread_mutex_unlock(&mac_table_lock);
}

/* find an entry */
struct mac_entry *find_mac(uint8_t *mac) {

    // printf("MUTEX: Locking MAC table\n");
    pthread_mutex_lock(&mac_table_lock);

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

    pthread_mutex_unlock(&mac_table_lock);
    // printf("MUTEX: Unlocked MAC table\n");
    return entry;
}

/* fnction to clean up the MAC table */
void cleanup_mac_table() {
    struct mac_entry *current, *tmp;
    
    pthread_mutex_lock(&mac_table_lock);
    HASH_ITER(hh, mac_table, current, tmp) {
        HASH_DEL(mac_table, current);
        free(current);
    }
    pthread_mutex_unlock(&mac_table_lock);
}

/* remove MAC entries older than MAC_ENTRY_TIMEOUT seconds */
void prune_mac_table() {
    struct mac_entry *current, *tmp;
    time_t current_time = time(NULL);
    
    pthread_mutex_lock(&mac_table_lock);
    HASH_ITER(hh, mac_table, current, tmp) {
        /* Skip infrastructure entries which are permanent */
        if (!current->is_infrastructure && 
            (current_time - current->last_seen > MAC_ENTRY_TIMEOUT)) {
            HASH_DEL(mac_table, current);
            free(current);
        }
    }
    pthread_mutex_unlock(&mac_table_lock);
}

/* ---------------------------------------------------- HELPERS ---------------------------------------------------- */

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

    /* get current time with microsecond precision */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = localtime(&tv.tv_sec);
    
    /* print timestamp in HH:MM:SS.microseconds format */
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
        
        /* free port information */
        if (sw->ports) {
            free(sw->ports);
            sw->ports = NULL;
        }
        sw->num_ports = 0;
        sw->hello_received = 0;
        sw->features_received = 0;
    }

    pthread_mutex_unlock(&sw->lock);
    
    /* Ccean up message queue */
    pthread_mutex_lock(&sw->queue_lock);
    struct pending_message *current = sw->outgoing_queue;
    while (current) {
        struct pending_message *next = current->next;
        free(current->data);
        free(current);
        current = next;
    }
    sw->outgoing_queue = NULL;
    pthread_mutex_unlock(&sw->queue_lock);
    pthread_mutex_destroy(&sw->queue_lock);

    /* clean up flow table - properly free all entries */
    pthread_mutex_lock(&sw->flow_table_lock);
    /* no need to free individual entries since we're freeing the whole table */
    free(sw->flow_table);
    sw->flow_table = NULL;
    sw->num_flows = 0;
    pthread_mutex_unlock(&sw->flow_table_lock);
    pthread_mutex_destroy(&sw->flow_table_lock);
    
    /* remove this switch's MAC entries */
    remove_switch_mac_entries(sw->datapath_id);
}

/* function to remove MAC entries for a specific switch */
void remove_switch_mac_entries(uint64_t dpid) {
    struct mac_entry *current, *tmp;
    
    pthread_mutex_lock(&mac_table_lock);
    HASH_ITER(hh, mac_table, current, tmp) {
        if (current->switch_dpid == dpid) {
            HASH_DEL(mac_table, current);
            free(current);
        }
    }
    pthread_mutex_unlock(&mac_table_lock);
}

/* ------------------------------------------------------ MAIN ----------------------------------------------------- */

/* main controller function */
int main(int argc, char *argv[]) {
    int port = DEF_PORT;
    
    /* handle command line args for port number */
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    /* set up signal handling */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("OpenFlow Controller starting on port %d...\n", port);
    
    /* initialize controller */
    init_controller(port);
    
    /* Add periodic maintenance tasks */
    time_t last_maintenance = time(NULL);
    
    /* Main loop - wait for shutdown signal or perform maintenance */
    while (running) {
        time_t now = time(NULL);
        
        /* Perform maintenance every 60 seconds */
        if (now - last_maintenance > 60) {
            prune_mac_table();
            last_maintenance = now;
        }
        
        sleep(1);
    }
    
    /* Cleanup threads and switches */
    int i;
    for (i = 0; i < MAX_SWITCHES; i++) {
        if (switches[i].active) {
            switches[i].active = 0;
            close(switches[i].socket);
            cleanup_switch(&switches[i]);
        }
        pthread_mutex_destroy(&switches[i].lock);
    }

    /* Clean global topology structure */
    cleanup_topology();
    
    /* Clean up MAC table */
    cleanup_mac_table();
    
    /* Close server socket */
    close(server_socket);
    
    /* Destroy global mutex */
    pthread_mutex_destroy(&switches_lock);
    pthread_mutex_destroy(&mac_table_lock);
    
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
        
        /* initialize flow table */
        struct flow_entry *flow_table = malloc(MAX_FLOWS * sizeof(struct flow_entry));
        memset(flow_table, 0, MAX_FLOWS * sizeof(struct flow_entry));
        switches[i].flow_table = flow_table;
        pthread_mutex_init(&switches[i].flow_table_lock, NULL);

        /* initialize queue lock */
        pthread_mutex_init(&switches[i].queue_lock, NULL);

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

    /* create lock for mac table */
    pthread_mutex_init(&mac_table_lock, NULL);
    printf("MAC table lock initialized\n");

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

        /* set socket to non-blocking */
        int flags = fcntl(client, F_GETFL, 0);
        fcntl(client, F_SETFL, flags | O_NONBLOCK);
        
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

        /* configure TCP socket options for robustness */
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
        // printf("MUTEX: Locking switches array\n");
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
        // printf("MUTEX: Unlocked switches array\n");

        
        if (i == MAX_SWITCHES) {
            printf("Maximum number of switches reached, rejecting connection\n");
            close(client);
        }
    }
    printf("Accept handler exiting\n");
    return NULL;
}

ssize_t read_complete_message(int socket, uint8_t *buffer, size_t max_size) {
    struct ofp_header header;
    ssize_t total_bytes = 0;
    ssize_t bytes_read;
    
    /* first read just the header */
    bytes_read = recv(socket, &header, sizeof(header), MSG_PEEK);
    if (bytes_read < sizeof(header)) {
        return bytes_read;
    }
    
    /* determine message length from the header */
    uint16_t msg_length = ntohs(header.length);
    if (msg_length > max_size) {
        return -1; /* too largee */
    }
    
    /* now read the complete message */
    while (total_bytes < msg_length) {
        bytes_read = recv(socket, buffer + total_bytes, msg_length - total_bytes, 0);
        if (bytes_read <= 0) {
            return bytes_read; /* error or connection closed */
        }
        total_bytes += bytes_read;
    }
    
    return total_bytes;
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

    /* initialize message queue */
    sw->outgoing_queue = NULL;
    
    /* initialize flow table */
    switches->num_flows = 0;
    
    /* start OpenFlow handshake */
    send_hello(sw);
    
    /* message handling loop */
    
    while (sw->active && running) {
        /* switch while loop */
        struct timeval tv;
        tv.tv_sec = 1; 
        tv.tv_usec = 0;
        
        fd_set readfds;
        fd_set writefds;
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_SET(sw->socket, &readfds);

        if (sw->outgoing_queue) {
            FD_SET(sw->socket, &writefds);
        }

        /* pull from the socket */
        int ret = select(sw->socket + 1, &readfds, 
                (sw->outgoing_queue ? &writefds : NULL), 
                NULL, &tv);
        
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
            len = read_complete_message(sw->socket, buf, sizeof(buf));
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

        if (ret > 0 && FD_ISSET(sw->socket, &writefds)) {
            process_outgoing_queue(sw);
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
                log_msg(sw, "ERROR: Received OpenFlow error from switch: type=%d, code=%d\n", 
                        ntohs(err->type), ntohs(err->code));
                
                if (ntohs(err->type) == OFPET_FLOW_MOD_FAILED) {
                    log_msg(sw, "ERROR: Flow modification failed: ");
                    switch(ntohs(err->code)) {
                        case OFPFMFC_ALL_TABLES_FULL:
                            log_msg(sw, "All tables full\n");
                            break;
                        case OFPFMFC_OVERLAP:
                            log_msg(sw, "Overlapping entry\n");
                            break;
                        case OFPFMFC_EPERM:
                            log_msg(sw, "Permissions error\n");
                            break;
                        case OFPFMFC_BAD_EMERG_TIMEOUT:
                            log_msg(sw, "Bad emergency timeout\n");
                            break;
                        case OFPFMFC_BAD_COMMAND:
                            log_msg(sw, "Bad command\n");
                            break;
                        case OFPFMFC_UNSUPPORTED:
                            log_msg(sw, "Unsupported action list\n");
                            break;
                        default:
                            log_msg(sw, "Unknown code: %d\n", ntohs(err->code));
                    }
                } else if (ntohs(err->type) == OFPET_BAD_ACTION) {
                    log_msg(sw, "ERROR: Bad action: ");
                    switch(ntohs(err->code)) {
                        case OFPBAC_BAD_TYPE:
                            log_msg(sw, "Bad action type\n");
                            break;
                        case OFPBAC_BAD_LEN:
                            log_msg(sw, "Bad action length\n");
                            break;
                        case OFPBAC_BAD_OUT_PORT:
                            log_msg(sw, "Bad output port\n");
                            break;
                        default:
                            log_msg(sw, "Other error: %d\n", ntohs(err->code));
                    }
                }
                
                /* Print the first 16 bytes of the error data if available */
                size_t data_len = ntohs(oh->length) - sizeof(struct ofp_error_msg);
                if (data_len > 0) {
                    log_msg(sw, "ERROR data (%zu bytes): ", data_len);
                    for (size_t i = 0; i < data_len && i < 16; i++) {
                        printf("%02x ", err->data[i]);
                    }
                    printf("\n");
                }
            }
            break;
            
        default:
            log_msg(sw, "ERROR: Unhandled message type: %d\n", oh->type);
    }
}

/* ------------------------------------------------- MESSAGE QUEUE ------------------------------------------------- */

/* Add this to controller.h */
#define MESSAGE_QUEUE_TIMEOUT 5  /* 5 seconds timeout for queued messages */

/* Improve process_outgoing_queue to handle timeouts */
void process_outgoing_queue(struct switch_info *sw) {
    pthread_mutex_lock(&sw->queue_lock);
    
    time_t current_time = time(NULL);
    struct pending_message *msg = sw->outgoing_queue;
    struct pending_message *prev = NULL;
    
    while (msg) {
        struct pending_message *next = msg->next;
        
        /* Check if message has timed out */
        if (current_time - msg->creation_time > MESSAGE_QUEUE_TIMEOUT) {
            /* Remove timed out message */
            if (prev) {
                prev->next = next;
            } else {
                sw->outgoing_queue = next;
            }
            free(msg->data);
            free(msg);
            msg = next;
            continue;
        }
        
        if (sw->active) {
            ssize_t sent = send(sw->socket, 
                             (char*)msg->data + msg->sent, 
                             msg->length - msg->sent, 
                             MSG_DONTWAIT);
            
            if (sent > 0) {
                msg->sent += sent;
                
                /* Message fully sent */
                if (msg->sent >= msg->length) {
                    if (prev) {
                        prev->next = next;
                    } else {
                        sw->outgoing_queue = next;
                    }
                    free(msg->data);
                    free(msg);
                    msg = next;
                    continue;
                }
            } else if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                log_msg(sw, "ERROR: Failed to send message: %s\n", strerror(errno));
                sw->active = 0;  /* Mark for disconnection */
                break;
            }
        }
        
        prev = msg;
        msg = next;
    }

    pthread_mutex_unlock(&sw->queue_lock);
}

/* Update the queue_openflow_msg function to add creation time */
void queue_openflow_msg(struct switch_info *sw, void *msg, size_t len) {
    struct pending_message *new_msg = malloc(sizeof(struct pending_message));
    if (!new_msg) {
        log_msg(sw, "ERROR: Failed to allocate memory for message queue\n");
        return;
    }
    
    /* Make a copy of the message data */
    new_msg->data = malloc(len);
    if (!new_msg->data) {
        free(new_msg);
        log_msg(sw, "ERROR: Failed to allocate memory for message data\n");
        return;
    }
    
    memcpy(new_msg->data, msg, len);
    new_msg->length = len;
    new_msg->sent = 0;
    new_msg->creation_time = time(NULL);  /* Add creation timestamp */
    new_msg->next = NULL;
    
    /* Add to queue */
    pthread_mutex_lock(&sw->queue_lock);
    
    if (!sw->outgoing_queue) {
        sw->outgoing_queue = new_msg;
    } else {
        struct pending_message *last = sw->outgoing_queue;
        while (last->next) {
            last = last->next;
        }
        last->next = new_msg;
    }

    pthread_mutex_unlock(&sw->queue_lock);
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
    queue_openflow_msg(sw, &hello, sizeof(hello));

    log_msg(sw, "Sent HELLO to switch\n");
}

/* handle HELLO message */
void handle_hello(struct switch_info *sw, struct ofp_header *oh) {

    // log_msg(sw, "MUTEX: Locking switch\n");
    pthread_mutex_lock(&sw->lock);
    sw->version = oh->version;
    sw->hello_received = 1;  /* mark HELLO as received */

    pthread_mutex_unlock(&sw->lock);
   // log_msg(sw, "MUTEX: Unlocked switch\n");


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
        queue_openflow_msg(sw, &error, sizeof(error));
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
    
    queue_openflow_msg(sw, &freq, sizeof(freq));
}

/* handle features reply */
void handle_features_reply(struct switch_info *sw, struct ofp_switch_features *features) {

    // log_msg(sw, "MUTEX: locking switch\n");
    pthread_mutex_lock(&sw->lock);

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

    log_msg(sw, "  Number of ports: %d\n", num_ports);

    pthread_mutex_unlock(&sw->lock);
    // log_msg(sw, "MUTEX: Unlocked switch\n");

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
        

        sw->last_echo = time(NULL);

        
        // Use queue instead of direct send
        queue_openflow_msg(sw, &echo, sizeof(echo));
        
        return true;  // Return success since we've queued the message
    }
    log_msg(sw, "Echo request already pending for switch\n");
    return false;
}

/* handle echo reply messages */
void handle_echo_reply(struct switch_info *sw, struct ofp_header *oh) {
    

    // log_msg(sw, "MUTEX: Locking switch\n");
    pthread_mutex_lock(&sw->lock);
    /* update both last reply and last echo time */
    sw->last_echo_reply = time(NULL);
    sw->echo_pending = false;  /* Mark that anothe echo can be send, meaning echos have vbeen recienved */

    pthread_mutex_unlock(&sw->lock);
    // log_msg(sw, "MUTEX: Unlocked switch\n");
    
}

/* handle echo requests */
void handle_echo_request(struct switch_info *sw, struct ofp_header *oh) {
    struct ofp_header echo;
    echo.version = OFP_VERSION;
    echo.type = OFPT_ECHO_REPLY;
    echo.length = htons(sizeof(echo));
    echo.xid = oh->xid;  /* use the same XID as the request */
    
    queue_openflow_msg(sw, &echo, sizeof(echo));
}

/* ------------------------------------------------ SWITCH MESSAGING ----------------------------------------------- */

/* handle port status changes */
void handle_port_status(struct switch_info *sw, struct ofp_port_status *ps) {
    if (!ps) {
        log_msg(sw, "ERROR: Null port_status message\n");
        return;
    }


    // log_msg(sw, "MUTEX: Locking switch\n");
    pthread_mutex_lock(&sw->lock);

    
    /* increment port change counter */
    sw->port_changes++;

    pthread_mutex_unlock(&sw->lock);
    // log_msg(sw, "MUTEX: Unlocked switch\n");
   
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

}

/* handle incoming packets from the switch */
void handle_packet_in(struct switch_info *sw, struct ofp_packet_in *pi) {
    if (!pi) {
        log_msg(sw, "ERROR: Null packet_in message\n");
        return;
    }

    log_msg(sw, "Packet in details: reason=%d, port=%d, buffer_id=%u, data_len=%u\n", 
       pi->reason, ntohs(pi->in_port), ntohl(pi->buffer_id), ntohs(pi->total_len));
    
    log_msg(sw, "DEBUG: Packet inspection - ethertype=0x%04x, first 14 bytes: %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x\n",
        ntohs(*(uint16_t*)(pi->data + ETH_ETHERTYPE_OFFSET)),
        pi->data[0], pi->data[1], pi->data[2], pi->data[3], 
        pi->data[4], pi->data[5], pi->data[6], pi->data[7],
        pi->data[8], pi->data[9], pi->data[10], pi->data[11], 
        pi->data[12], pi->data[13]);

    /* lock switch for thread safety while accessing switch info */
    // log_msg(sw, "MUTEX: Locking switch\n");
    pthread_mutex_lock(&sw->lock);
    /* increment packet counter */
    sw->packet_in_count++;
    pthread_mutex_unlock(&sw->lock);
    // log_msg(sw, "MUTEX: Unlocked switch\n");

    /* first check if its a topology discovery packet */
    if(is_topology_discovery_packet(pi->data, ntohs(pi->total_len))) {
        handle_discovery_packet(sw, pi);

        return; /* return succesfully */
    }
    
    /* extract basic packet information */
    uint16_t in_port = ntohs(pi->in_port);

    /* extract information used for the flow resulting from this packet */
    uint8_t *eth_frame = pi->data;
    uint8_t *dst_mac = eth_frame + ETH_DST_OFFSET;
    uint8_t *src_mac = eth_frame + ETH_SRC_OFFSET;


    log_msg(sw, "Learning MAC %02x:%02x:%02x:%02x:%02x:%02x on switch port %d\n",
        src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], in_port);

    /* add or update source mac to mac table */
    // When learning a MAC address
   

    struct mac_entry *existing = find_mac(src_mac);

    if (!existing) {
        // This MAC wasn't pre-populated, so it's likely a host
        add_or_update_mac(sw, src_mac, sw->datapath_id, in_port, false);
        log_msg(sw, "Learned new host MAC %02x:%02x:%02x:%02x:%02x:%02x on switch %016" PRIx64 " port %d\n",
                src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], 
                sw->datapath_id, in_port);
    } else if (!existing->is_infrastructure) {
        // Update existing host entry
        add_or_update_mac(sw, src_mac, sw->datapath_id, in_port, false);
    }
    pthread_mutex_unlock(&mac_table_lock);

    /* case for OFPR_ACTION */
    static const uint8_t BROADCAST_MAC[MAC_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    log_msg(sw, "DEBUG: MAC comparison result=%d (0=match), dst_mac=%02x:%02x:%02x:%02x:%02x:%02x, BROADCAST=%02x:%02x:%02x:%02x:%02x:%02x\n",
        memcmp(dst_mac, BROADCAST_MAC, MAC_ADDR_LEN),
        dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
        BROADCAST_MAC[0], BROADCAST_MAC[1], BROADCAST_MAC[2], 
        BROADCAST_MAC[3], BROADCAST_MAC[4], BROADCAST_MAC[5]);

    /* check if it's a broadcast OR multicast (first bit of first byte is 1) */
    if (memcmp(dst_mac, BROADCAST_MAC, MAC_ADDR_LEN) == 0 || (dst_mac[0] & 0x01)) {

        log_msg(sw, "Broadcast or multicast packet detected (dst_mac=%02x:%02x:%02x:%02x:%02x:%02x)\n",
                dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
        handle_broadcast_packet(sw, pi, find_mac(src_mac));
    } else {

        /* unicast packet */
        struct mac_entry *dst_entry = find_mac(dst_mac);
        if (dst_entry) {
            log_msg(sw, "Destination MAC found in table, using unicast forwarding\n");
            handle_unicast_packet(sw, pi, dst_entry);
        } else {
            log_msg(sw, "Destination MAC not found in table, flooding with broadcast\n");
            handle_broadcast_packet(sw, pi, find_mac(src_mac));
        }
    }

}

/* --------------------------------------------- ROUTING/FLOW INSTALLATION ----------------------------------------- */
/*
 * Validates that a path is valid before installing flows.
 * Returns true if the path is valid, false otherwise.
 */
bool validate_path(uint64_t src_dpid, uint16_t src_port, 
                   uint64_t dst_dpid, uint16_t dst_port,
                   uint64_t *switch_dpids, uint16_t *ingress_ports, 
                   uint16_t *egress_ports, int num_hops, struct switch_info *sw) {
    
    /* validate source/destination ports aren't the same on the same switch */
    if (src_dpid == dst_dpid && src_port == dst_port) {
        log_msg(NULL, "ERROR: Path validation failed - same in/out port (%d) on switch %016" PRIx64 "\n", 
                src_port, src_dpid);
        return false;
    }
    
    /* Validate first switch is source and last is destination */
    if (switch_dpids[0] != src_dpid || switch_dpids[num_hops] != dst_dpid) {
        log_msg(NULL, "ERROR: Path validation failed - endpoints don't match expected source/destination\n");
        log_msg(NULL, "       Expected: [%016" PRIx64 ", ..., %016" PRIx64 "]\n", 
            src_dpid, dst_dpid);
        log_msg(NULL, "       Got: [%016" PRIx64 ", ..., %016" PRIx64 "]\n", 
            switch_dpids[0], switch_dpids[num_hops]);
        return false;
        }
    
    // Check for loops in the path
    for (int i = 0; i < num_hops; i++) {
        // Validate that in_port != out_port for each switch (no hairpinning)
        if (ingress_ports[i] == egress_ports[i]) {
            log_msg(NULL, "ERROR: Path validation failed - switch %016" PRIx64 " has same in/out port\n", 
                    switch_dpids[i]);
            return false;
        }
        
        // Check for repeated switches in path (except for the first and last)
        for (int j = i+1; j < num_hops; j++) {
            if (switch_dpids[i] == switch_dpids[j] && !(i == 0 && j == num_hops)) {
                log_msg(NULL, "ERROR: Path validation failed - switch %016" PRIx64 " appears multiple times\n", 
                        switch_dpids[i]);
                return false;
            }
        }
    }
    
    // Validate connectivity between adjacent switches
    pthread_mutex_lock(&topology.lock);
    for (int i = 0; i < num_hops; i++) {
        igraph_integer_t v1 = find_vertexid(sw, switch_dpids[i]);
        igraph_integer_t v2 = find_vertexid(sw, switch_dpids[i+1]);
        
        if (v1 < 0 || v2 < 0) {
            pthread_mutex_unlock(&topology.lock);
            log_msg(NULL, "ERROR: Path validation failed - switch not found in topology\n");
            return false;
        }
        
        igraph_integer_t eid;
        igraph_get_eid(&topology.graph, &eid, v1, v2, IGRAPH_ALL, 0);
        if (eid < 0) {
            pthread_mutex_unlock(&topology.lock);
            log_msg(NULL, "ERROR: Path validation failed - no link between switches %016" PRIx64 " and %016" PRIx64 "\n", 
                    switch_dpids[i], switch_dpids[i+1]);
            return false;
        }
    }
    pthread_mutex_unlock(&topology.lock);
    
    return true; // Path is valid
}

void handle_unicast_packet(struct switch_info *sw, struct ofp_packet_in *pi, struct mac_entry *dst) {
    uint16_t in_port = ntohs(pi->in_port);
    
    // Extract source MAC for reverse path
    uint8_t *eth_frame = pi->data;
    uint8_t *src_mac = eth_frame + ETH_SRC_OFFSET;
    
    // Find source MAC entry for reverse path installation
    struct mac_entry *src_entry = find_mac(src_mac);
    if (!src_entry) {
        log_msg(sw, "WARNING: Source MAC entry not found, cannot install reverse path\n");
        // Continue with one-way path installation
    }
    
    // Same switch case
    pthread_mutex_lock(&sw->lock);
    if (sw->datapath_id == dst->switch_dpid) {
        pthread_mutex_unlock(&sw->lock);
        
        // NEW: Check if destination port equals ingress port (special case)
        if (in_port == dst->port_no) {
            log_msg(sw, "INFO: Source and destination are on the same port (%d). No flow needed.\n", in_port);
            // Just send the packet without installing any flows
            send_packet_out(sw, in_port, dst->port_no, ntohl(pi->buffer_id), pi->data, ntohs(pi->total_len));
            return;
        }
        
        // Install forward flow
        install_flow(sw, in_port, dst->port_no, ntohl(pi->buffer_id), dst);
        
        // If we have the source entry, install reverse flow too
        if (src_entry) {
            install_flow(sw, dst->port_no, in_port, 0xFFFFFFFF, src_entry);
            log_msg(sw, "Installed reverse flow on same switch: out_port=%d -> in_port=%d\n", 
                   dst->port_no, in_port);
        }
        
        send_packet_out(sw, in_port, dst->port_no, pi->buffer_id, pi->data, ntohs(pi->total_len));
        return;
    }
    pthread_mutex_unlock(&sw->lock);
    
    // Different switch - calculate shortest path
    igraph_integer_t src_vertex = find_vertexid(sw, sw->datapath_id);
    igraph_integer_t dst_vertex = find_vertexid(sw, dst->switch_dpid);
    
    if (src_vertex < 0 || dst_vertex < 0) {
        log_msg(sw, "ERROR: Can't find vertices for path calculation\n");
        return;
    }
    
    // Find the shortest path
    pthread_mutex_lock(&topology.lock);
    igraph_vector_int_t path;
    igraph_vector_int_init(&path, 0);
    
    // NEW: Create and initialize weight vector for consistent path selection
    igraph_vector_t weights;
    igraph_vector_init(&weights, igraph_ecount(&topology.graph));
    
    // Fill weights vector from edge attributes
    for (igraph_integer_t i = 0; i < igraph_ecount(&topology.graph); i++) {
        VECTOR(weights)[i] = EAN(&topology.graph, "weight", i);
        log_msg(sw, "DEBUG: Edge %lld weight: %f\n", i, VECTOR(weights)[i]);
    }
    
    // Use weights in the Dijkstra call
    if (igraph_get_shortest_path_dijkstra(&topology.graph, &path, NULL, 
                                         src_vertex, dst_vertex, 
                                         &weights, IGRAPH_ALL) != IGRAPH_SUCCESS) {
        log_msg(sw, "ERROR: Failed to calculate path\n");
        igraph_vector_destroy(&weights);
        igraph_vector_int_destroy(&path);
        pthread_mutex_unlock(&topology.lock);
        return;
    }
    
    igraph_vector_destroy(&weights);
    pthread_mutex_unlock(&topology.lock);
    
    // Path should have at least 2 vertices (src and dst)
    if (igraph_vector_int_size(&path) < 2) {
        log_msg(sw, "ERROR: Path too short\n");
        igraph_vector_int_destroy(&path);
        return;
    }
    
    // Store the path information for validation and reverse path installation
    int path_length = igraph_vector_int_size(&path);
    uint64_t switch_dpids[path_length];
    uint16_t ingress_ports[path_length];
    uint16_t egress_ports[path_length];
    
    log_msg(sw, "Installing flows along path with %d switches\n", path_length);
    
    // At the first switch (source), use the ingress port from the packet_in
    uint16_t current_in_port = in_port;
    
    // For each pair of switches in the path, store DPID and port info
    for (int i = 0; i < path_length; i++) {
        igraph_integer_t current_vertex = VECTOR(path)[i];
        switch_dpids[i] = vertex_to_dpid(current_vertex, sw);
        
        if (i == 0) {
            // First switch ingress comes from the packet_in
            ingress_ports[i] = current_in_port;
        }
        else if (i < path_length - 1) {
            // Find ingress port on internal switches
            ingress_ports[i] = find_ingress_port(sw, switch_dpids[i], switch_dpids[i-1]);
        }
        
        if (i < path_length - 1) {
            // Find egress port for all but the last switch
            egress_ports[i] = find_port_to_next_hop(sw, switch_dpids[i], switch_dpids[i+1]);
        }
    }
    
    // For the last switch, egress is to the destination host
    egress_ports[path_length-1] = dst->port_no;
    
    // NEW: Validate the path before installing flows
    if (!validate_path(sw->datapath_id, in_port, dst->switch_dpid, dst->port_no,
                      switch_dpids, ingress_ports, egress_ports, path_length-1, sw)) {
        log_msg(sw, "ERROR: Path validation failed, not installing flows\n");
        igraph_vector_int_destroy(&path);
        return;
    }
    
    // For each pair of switches in the path - Forward direction
    for (int i = 0; i < path_length - 1; i++) {
        igraph_integer_t current_vertex = VECTOR(path)[i];
        igraph_integer_t next_vertex = VECTOR(path)[i+1];
        
        uint64_t current_dpid = vertex_to_dpid(current_vertex, sw);
        uint64_t next_dpid = vertex_to_dpid(next_vertex, sw);
        
        // Find the port from current switch to next switch
        uint16_t out_port = find_port_to_next_hop(sw, current_dpid, next_dpid);
        
        if (out_port == OFPP_NONE) {
            log_msg(sw, "ERROR: Can't find port from switch %016" PRIx64 " to switch %016" PRIx64 "\n", 
                   current_dpid, next_dpid);
            igraph_vector_int_destroy(&path);
            return;
        }
        
        // Find the switch_info structure for the current switch
        struct switch_info *current_sw = find_switch_by_dpid(current_dpid);
        
        if (current_sw) {
            // Install forward flow
            log_msg(sw, "Installing flow at switch %016" PRIx64 ": in_port=%d -> out_port=%d for dst_mac=%02x:%02x:%02x:%02x:%02x:%02x\n", 
                   current_dpid, current_in_port, out_port,
                   dst->mac[0], dst->mac[1], dst->mac[2], dst->mac[3], dst->mac[4], dst->mac[5]);
            
            // If this is the source switch, use the buffer_id for packet_out
            uint32_t buffer = (i == 0) ? ntohl(pi->buffer_id) : 0xFFFFFFFF;
            
            install_flow(current_sw, current_in_port, out_port, buffer, dst);
            
            // Only send the packet_out from the source switch
            if (i == 0) {
                send_packet_out(current_sw, current_in_port, out_port, pi->buffer_id, pi->data, ntohs(pi->total_len));
            }
        } else {
            log_msg(sw, "WARNING: Could not find switch %016" PRIx64 " to install flow\n", current_dpid);
        }
        
        // If not the last iteration, find the in_port for the next switch
        if (i < path_length - 2) {
            // Find ingress port on the next switch from the current switch
            current_in_port = find_ingress_port(sw, next_dpid, current_dpid);
            
            if (current_in_port == 0) {
                log_msg(sw, "ERROR: Can't find ingress port on switch %016" PRIx64 " from switch %016" PRIx64 "\n", 
                       next_dpid, current_dpid);
                igraph_vector_int_destroy(&path);
                return;
            }
        }
    }
    
    // Handle the last switch (destination switch)
    igraph_integer_t last_vertex = VECTOR(path)[path_length - 1];
    uint64_t last_dpid = vertex_to_dpid(last_vertex, sw);
    
    // Find the switch_info structure for the destination switch
    struct switch_info *dst_sw = find_switch_by_dpid(last_dpid);
    
    if (dst_sw) {
        log_msg(sw, "Installing final flow at destination switch %016" PRIx64 ": in_port=%d -> out_port=%d for dst_mac=%02x:%02x:%02x:%02x:%02x:%02x\n", 
               last_dpid, current_in_port, dst->port_no,
               dst->mac[0], dst->mac[1], dst->mac[2], dst->mac[3], dst->mac[4], dst->mac[5]);
        
        // Double check we're not creating a looping flow
        if (current_in_port != dst->port_no) {
            install_flow(dst_sw, current_in_port, dst->port_no, 0xFFFFFFFF, dst);
        } else {
            log_msg(sw, "WARNING: Avoided installing looping flow on destination switch\n");
        }
    } else {
        log_msg(sw, "WARNING: Could not find destination switch %016" PRIx64 " to install flow\n", last_dpid);
    }
    
    // Now install reverse path flows if we have the source entry
    if (src_entry) {
        log_msg(sw, "Installing reverse path flows\n");
        
        // Install flows in reverse order
        for (int i = path_length - 1; i > 0; i--) {
            struct switch_info *current_sw = find_switch_by_dpid(switch_dpids[i]);
            if (current_sw) {
                // For the destination switch, the in_port is the host port and out_port is the trunk
                // For intermediate switches, both are trunk ports
                uint16_t rev_in_port = (i == path_length - 1) ? dst->port_no : egress_ports[i];
                uint16_t rev_out_port = ingress_ports[i];
                
                // Double check we're not creating a looping flow
                if (rev_in_port != rev_out_port) {
                    log_msg(sw, "Installing reverse flow at switch %016" PRIx64 ": in_port=%d -> out_port=%d for src_mac=%02x:%02x:%02x:%02x:%02x:%02x\n", 
                           switch_dpids[i], rev_in_port, rev_out_port,
                           src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
                    
                    install_flow(current_sw, rev_in_port, rev_out_port, 0xFFFFFFFF, src_entry);
                } else {
                    log_msg(sw, "WARNING: Avoided installing looping reverse flow on switch %016" PRIx64 "\n", 
                           switch_dpids[i]);
                }
            }
        }
        
        // Finally, install the last reverse flow at the source switch
        struct switch_info *src_sw = find_switch_by_dpid(switch_dpids[0]);
        if (src_sw) {
            uint16_t rev_in_port = egress_ports[0];
            uint16_t rev_out_port = ingress_ports[0];
            
            // Double check we're not creating a looping flow
            if (rev_in_port != rev_out_port) {
                log_msg(sw, "Installing final reverse flow at source switch %016" PRIx64 ": in_port=%d -> out_port=%d for src_mac=%02x:%02x:%02x:%02x:%02x:%02x\n", 
                       switch_dpids[0], rev_in_port, rev_out_port,
                       src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
                
                install_flow(src_sw, rev_in_port, rev_out_port, 0xFFFFFFFF, src_entry);
            } else {
                log_msg(sw, "WARNING: Avoided installing looping reverse flow on source switch %016" PRIx64 "\n", 
                       switch_dpids[0]);
            }
        }
    }
    
    igraph_vector_int_destroy(&path);
}

uint16_t find_port_to_next_hop(struct switch_info *sw, uint64_t src_dpid, uint64_t dst_dpid) {

    /* find the port on src_dpid that connects to dst_dpid */
    /* iterate through all edges in the graph */
    log_msg(sw, "Finding port to next hop: src=%016" PRIx64 ", dst=%016" PRIx64 "\n", src_dpid, dst_dpid);

    // log_msg(sw, "MUTEX: Locking topology\n");
    pthread_mutex_lock(&topology.lock);
    for (igraph_integer_t i = 0; i < igraph_ecount(&topology.graph); i++) {
        uint64_t edge_src_dpid = (uint64_t)EAN(&topology.graph, "src_dpid", i);
        uint64_t edge_dst_dpid = (uint64_t)EAN(&topology.graph, "dst_dpid", i);
        
        if (edge_src_dpid == src_dpid && edge_dst_dpid == dst_dpid) {
            uint16_t port = (uint16_t)EAN(&topology.graph, "src_port", i);

            pthread_mutex_unlock(&topology.lock);
            // log_msg(sw, "MUTEX: Unlocked topology\n");
            return port;
        }
        
        if (edge_dst_dpid == src_dpid && edge_src_dpid == dst_dpid) {
            uint16_t port = (uint16_t)EAN(&topology.graph, "dst_port", i);

            pthread_mutex_unlock(&topology.lock);
            // log_msg(sw, "MUTEX: Unlocked topology\n");
            return port;
        }
    }
    pthread_mutex_unlock(&topology.lock);
    // log_msg(sw, "MUTEX: Unlocked topology\n");
    

    return OFPP_NONE;  /* not found */
}

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

uint16_t find_ingress_port(struct switch_info *sw, uint64_t dpid, uint64_t from_dpid) {
    pthread_mutex_lock(&topology.lock);
    for (igraph_integer_t i = 0; i < igraph_ecount(&topology.graph); i++) {
        uint64_t src_dpid = (uint64_t)EAN(&topology.graph, "src_dpid", i);
        uint64_t dst_dpid = (uint64_t)EAN(&topology.graph, "dst_dpid", i);
        
        if (src_dpid == from_dpid && dst_dpid == dpid) {
            uint16_t port = (uint16_t)EAN(&topology.graph, "dst_port", i);
            pthread_mutex_unlock(&topology.lock);
            return port;
        }
        
        if (dst_dpid == from_dpid && src_dpid == dpid) {
            uint16_t port = (uint16_t)EAN(&topology.graph, "src_port", i);
            pthread_mutex_unlock(&topology.lock);
            return port;
        }
    }
    pthread_mutex_unlock(&topology.lock);
    
    return 0;  /* not found */
}

void handle_broadcast_packet(struct switch_info *sw, struct ofp_packet_in *pi, struct mac_entry *src) {
    uint16_t in_port = ntohs(pi->in_port);
    uint64_t switch_dpid = sw->datapath_id;
    
    /* calculate MST (keep this part since it's required) */
    // log_msg(sw, "MUTEX: Locking topology\n");
    pthread_mutex_lock(&topology.lock);
    igraph_vector_int_t mst_edges;
    igraph_vector_int_init(&mst_edges, 0);
    igraph_error_t result = igraph_minimum_spanning_tree(&topology.graph, &mst_edges, NULL);
    if (result != IGRAPH_SUCCESS) {
        log_msg(sw, "ERROR: Failed to calculate MST\n");
        igraph_vector_int_destroy(&mst_edges);
        pthread_mutex_unlock(&topology.lock);
        // log_msg(sw, "MUTEX: Unlocked topology\n");
        return;
    }
    pthread_mutex_unlock(&topology.lock);
    // log_msg(sw, "MUTEX: Unlocked topology\n");
    
    /* collect all output ports in a single pass */
    uint16_t out_ports[MAX_PORTS_PER_SWITCH];
    int num_out_ports = 0;
    
    /* for each port on this switch */
    for (int i = 0; i < sw->num_ports; i++) {
        uint16_t port_no = ntohs(sw->ports[i].port_no);
        
        /* skip the incoming port */
        if (port_no == in_port || port_no >= OFPP_MAX) {
            continue;
        }
        
        /* port validation */
        bool is_mst_port = is_port_in_mst(sw, switch_dpid, port_no, &mst_edges);
        bool is_trunk = is_trunk_port(sw, switch_dpid, port_no);
        
        /* add the port to out_ports if: */
        /* - It's a trunk port that's part of the MST, or 
         * - It's a non-trunk port (i.e., an access port)
        */
        if ((is_trunk && is_mst_port) || !is_trunk) {
            out_ports[num_out_ports++] = port_no;
        }
    }
    
    /* create broadcast MAC entry */
    struct mac_entry bcast_entry;
    memset(&bcast_entry, 0, sizeof(struct mac_entry));
    memset(bcast_entry.mac, 0xFF, MAC_ADDR_LEN);
    
    /* install flows and send packets */
    for (int i = 0; i < num_out_ports; i++) {

        /* install flow for this input/output port pair */
        install_flow(sw, in_port, out_ports[i], 0xFFFFFFFF, &bcast_entry);
        
        /* send the current packet */
        send_packet_out(sw, in_port, out_ports[i], 
                (i == 0) ? ntohl(pi->buffer_id) : 0xFFFFFFFF,
                pi->data, ntohs(pi->total_len));
    }
    

    igraph_vector_int_destroy(&mst_edges);
}

bool is_port_in_mst(struct switch_info * sw, uint64_t dpid, uint16_t port_no, igraph_vector_int_t *mst_edges) {
    log_msg(sw, "Checking if port %d is in MST\n", port_no);
    igraph_integer_t num_edges = igraph_vector_int_size(mst_edges);
    
    // Log MST size for debugging
    log_msg(sw, "DEBUG: MST has %lld edges\n", num_edges);
    
    pthread_mutex_lock(&topology.lock);
    for (igraph_integer_t i = 0; i < num_edges; i++) {
        igraph_integer_t edge_id = VECTOR(*mst_edges)[i];
        
        uint64_t src_dpid = (uint64_t)EAN(&topology.graph, "src_dpid", edge_id);
        uint64_t dst_dpid = (uint64_t)EAN(&topology.graph, "dst_dpid", edge_id);
        uint16_t src_port = (uint16_t)EAN(&topology.graph, "src_port", edge_id);
        uint16_t dst_port = (uint16_t)EAN(&topology.graph, "dst_port", edge_id);
        
        // Enhanced logging
        log_msg(sw, "DEBUG: Checking MST edge %lld: %016" PRIx64 ":%d -> %016" PRIx64 ":%d\n",
                i, src_dpid, src_port, dst_dpid, dst_port);
        
        if ((src_dpid == dpid && src_port == port_no) ||
            (dst_dpid == dpid && dst_port == port_no)) {
            pthread_mutex_unlock(&topology.lock);
            log_msg(sw, "DEBUG: Port %d on switch %016" PRIx64 " is in MST\n", 
                   port_no, dpid);
            return true;
        }
    }
    pthread_mutex_unlock(&topology.lock);
    
    log_msg(sw, "DEBUG: Port %d on switch %016" PRIx64 " is NOT in MST\n", 
            port_no, dpid);
    return false;
}

/* function for installing a flow to a switch once links have been discovered */
void install_flow(struct switch_info *sw, uint16_t in_port, uint16_t dst_port, uint32_t buff_id, struct mac_entry *dst){
    
    /* Validate port numbers */
    if(!is_valid_port(in_port)) {
        log_msg(sw, "ERROR: Invalid in_port number %d in attempted flow install\n", in_port);
        return;
    }
    
    if(!is_valid_port(dst_port)) {
        log_msg(sw, "ERROR: Invalid dst_port number %d in attempted flow install\n", dst_port);
        return;
    }

    if(dst_port < 0 || in_port < 0){
        log_msg(sw, "ERROR: Invalid port number in attempeted flow install\n");
        return;
    }

    if (in_port == dst_port) {
        log_msg(sw, "ERROR: Attempted to install looping flow (in_port = out_port = %d). Aborting.\n", in_port);
        return;
    }

    /* Check if this flow already exists */
    if (flow_exists(sw, sw->datapath_id, in_port, dst->mac, dst_port)) {
        log_msg(sw, "DEBUG: Flow already exists, skipping installation: in_port=%d -> out_port=%d, dst_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                in_port, dst_port, 
                dst->mac[0], dst->mac[1], dst->mac[2], dst->mac[3], dst->mac[4], dst->mac[5]);
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


    log_msg(sw, "DEBUG: Flow mod header - version=%d, type=%d, length=%d, xid=%u\n", 
            fm->header.version, fm->header.type, ntohs(fm->header.length), ntohl(fm->header.xid));

    log_msg(sw, "DEBUG: Flow mod match - wildcards=0x%08x, in_port=%d\n", 
            ntohl(fm->match.wildcards), ntohs(fm->match.in_port));
            
    log_msg(sw, "DEBUG: Flow mod match dst_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
            fm->match.dl_dst[0], fm->match.dl_dst[1], fm->match.dl_dst[2], 
            fm->match.dl_dst[3], fm->match.dl_dst[4], fm->match.dl_dst[5]);
            
    log_msg(sw, "DEBUG: Flow mod params - cmd=%d, idle_timeout=%d, hard_timeout=%d, priority=%d, buffer_id=0x%08x\n",
            ntohs(fm->command), ntohs(fm->idle_timeout), ntohs(fm->hard_timeout), 
            ntohs(fm->priority), ntohl(fm->buffer_id));
            
    log_msg(sw, "DEBUG: Flow details: wildcards=0x%x, match.in_port=%d, action.port=%d\n",
           ntohl(fm->match.wildcards), ntohs(fm->match.in_port), ntohs(action->port));


    /* send the flow_mod message to the switch */
    queue_openflow_msg(sw, fm, total_len);
    int error = 0;
    socklen_t errlen = sizeof(error);
    if (getsockopt(sw->socket, SOL_SOCKET, SO_ERROR, &error, &errlen) == 0) {
        if (error != 0) {
            log_msg(sw, "ERROR: Socket error after flow mod: %d (%s)\n", 
                    error, strerror(error));
        }
    }

    log_msg(sw, "DEBUG: Flow installation complete for switch, buffer ID: %u\n", 
           sw->datapath_id, buff_id);

    free(fm);

    /* Add the flow to our tracking table */
    add_flow_entry(sw, sw->datapath_id, in_port, dst->mac, dst_port);
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

    queue_openflow_msg(sw, po, total_len);

    log_msg(sw, "Packet out sent to switch %016" PRIx64 ": in_port=%d, out_port=%d, buffer_id=%s\n", 
           sw->datapath_id, in_port, out_port, 
           (buffer_id == 0xFFFFFFFF) ? "NO_BUFFER" : "BUFFERED");

    free(po);
}