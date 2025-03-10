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
#include "controller.h"



struct mac_entry *mac_table = NULL;

/* add or update an entry */
void add_mac(uint8_t *mac, uint64_t dpid, uint16_t port) {
    struct mac_entry *entry;
    
    HASH_FIND(hh, mac_table, mac, MAC_ADDR_LEN, entry);
    if (entry == NULL) {
        entry = malloc(sizeof(struct mac_entry));
        memcpy(entry->mac, mac, MAC_ADDR_LEN);
        HASH_ADD(hh, mac_table, mac, MAC_ADDR_LEN, entry);
    }
    
    /* add other values of update values if already exists */
    entry->switch_dpid = dpid;
    entry->port = port;
    entry->last_seen = time(NULL);
}

/* find an entry */
struct mac_entry *find_mac(uint8_t *mac) {
    struct mac_entry *entry;
    HASH_FIND(hh, mac_table, mac, MAC_ADDR_LEN, entry);
    return entry;
}

#define DEF_PORT 6653
#define DEBUG

/* global variables defined*/
struct switch_info switches[MAX_SWITCHES];
pthread_mutex_t switches_lock = PTHREAD_MUTEX_INITIALIZER;
int server_socket;
volatile int running = 1; /* for controller clean up and running */

/* milestone 2 globals */
struct network_topology global_topology;
pthread_t topology_thread;


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
    printf("Supported OpenFlow version: 0x%02x\n", OFP_VERSION);
    
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

    init_topology();
}

/* -------------------------------------------------- Initialize Threads ------------------------------------------------------- */

/* accept incoming switch connections, spawns new threads for each connection */
void *accept_handler(void *arg) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    
    printf("Accept handler thread started\n");
    
    while (running) {
        printf("Waiting for connection on port %d...\n", DEF_PORT);
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

    if (!initialize_switch(sw)) {
        cleanup_switch(sw);
        return NULL;
    }
    
    /* main message handling loop */
    while (sw->active && running) {
        if (!process_switch_messages(sw)) {

            handle_switch_disconnection(sw);
            break;
        }
        
        handle_switch_periodic_tasks(sw);
    }
    
    cleanup_switch(sw);
    return NULL;
}

/* initialize a new switch connection */
bool initialize_switch(struct switch_info *sw) {
    sw->hello_received = 0;
    sw->features_received = 0;
    sw->last_echo_xid = 0;
    sw->echo_pending = false;

    /* initialize modified ports */
    sw->modified_ports = NULL;
    sw->num_modified_ports = 0;
    sw->modified_ports_capacity = 0;
    pthread_mutex_init(&sw->modified_ports_lock, NULL);
    
    /* start OpenFlow handshake */
    send_hello(sw);
    
    return true;
}

/* process incoming messages from a switch */
bool process_switch_messages(struct switch_info *sw) {
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sw->socket, &readfds);
    
    int ret = select(sw->socket + 1, &readfds, NULL, NULL, &tv);
    
    if (ret < 0) {
        if (errno == EINTR) {
            return true; /* interrupted, but continue */
        }
        log_msg("Error in select for switch %016" PRIx64 ": %s\n", 
               sw->datapath_id, strerror(errno));
        return false;
    }
    
    if (ret > 0 && FD_ISSET(sw->socket, &readfds)) {
        uint8_t buf[OFP_MAX_MSG_SIZE];
        ssize_t len = recv(sw->socket, buf, sizeof(buf), 0);
        
        if (len == 0) {
            log_msg("Connection closed cleanly by switch %016" PRIx64 "\n", 
                   sw->datapath_id);
            return false;
        } else if (len < 0) {
            if (errno == EINTR) {
                return true; /* interrupted, but continue */
            } else if (errno == ECONNRESET) {
                log_msg("Connection reset by switch %016" PRIx64 "\n", 
                       sw->datapath_id);
            } else {
                log_msg("Receive error on switch %016" PRIx64 ": %s\n",
                       sw->datapath_id, strerror(errno));
            }
            return false;
        }
        
        
        handle_switch_message(sw, buf, len);
    }
    
    return true;
}

/* function to handle periodic tasks for a switch */
void handle_switch_periodic_tasks(struct switch_info *sw) {
    time_t now = time(NULL);
    
    /* handle echo requests */
    if (sw->features_received) {
        static time_t next_echo = 0;
        
        if (next_echo == 0) {
            next_echo = now + ECHO_INTERVAL;
        }
        
        if (sw->echo_pending && (now - sw->last_echo) > ECHO_TIMEOUT) {
            sw->echo_pending = false;
            
            /* handle disconnection if echo timeout */
            if (sw->last_echo_reply < sw->last_echo - ECHO_TIMEOUT) {
                log_msg("Switch %016" PRIx64 " not responding to echo requests\n", 
                       sw->datapath_id);
                handle_switch_disconnection(sw);
                sw->active = 0; /* signal the main loop to exit */
            }
        }
        
        if (!sw->echo_pending && now >= next_echo) {
            if (send_echo_request(sw)) {
                next_echo = now + ECHO_INTERVAL;
            }
        }
    }
}

/* function to handle switch disconnection */
void handle_switch_disconnection(struct switch_info *sw) {
    
    log_msg("Switch %016" PRIx64 " disconnected, cleaning up resources\n", sw->datapath_id);
    
    
    pthread_mutex_lock(&sw->lock);
    sw->active = 0;
    pthread_mutex_unlock(&sw->lock);
    
    
    pthread_mutex_lock(&global_topology.lock);
    struct topology_node *node = global_topology.nodes;
    struct topology_node *prev = NULL;
    
    /* find and remove the node for this switch */
    while (node != NULL) {
        if (node->dpid == sw->datapath_id) {
            /* remove all links */
            while (node->links != NULL) {
                struct topology_link *link = node->links;
                node->links = link->next;
                free(link);
            }
            
            /* remove node from list */
            if (prev == NULL) {
                global_topology.nodes = node->next;
            } else {
                prev->next = node->next;
            }
            
            global_topology.num_nodes--;
            free(node);
            break;
        }
        prev = node;
        node = node->next;
    }
    
    
    node = global_topology.nodes;
    while (node != NULL) {
        struct topology_link *link = node->links;
        struct topology_link *prev_link = NULL;
        
        while (link != NULL) {
            if (link->linked_dpid == sw->datapath_id) {
                /* remove this link */
                if (prev_link == NULL) {
                    node->links = link->next;
                } else {
                    prev_link->next = link->next;
                }
                
                struct topology_link *to_free = link;
                link = link->next;
                free(to_free);
                node->num_links--;
                global_topology.num_links--;
            } else {
                prev_link = link;
                link = link->next;
            }
        }
        
        node = node->next;
    }
    pthread_mutex_unlock(&global_topology.lock);
    
    
    struct mac_entry *entry, *tmp;
    HASH_ITER(hh, mac_table, entry, tmp) {
        if (entry->switch_dpid == sw->datapath_id) {
            HASH_DEL(mac_table, entry);
            free(entry);
        }
    }
    
    
    close(sw->socket);
    free(sw->ports);
    sw->ports = NULL;
    sw->num_ports = 0;
    
    /* notify the controller about topology change */
    log_msg("Topology updated after switch %016" PRIx64 " disconnection\n", 
            sw->datapath_id);
}

/* function to mark a port (number) as needing to be explored due to modification */
void mark_port_modified(struct switch_info *sw, uint16_t port_no) {
    pthread_mutex_lock(&sw->modified_ports_lock);
    
    /* check if port is already in the list */
    int i;
    for (i = 0; i < sw->num_modified_ports; i++) {
        if (sw->modified_ports[i] == port_no) {
            pthread_mutex_unlock(&sw->modified_ports_lock);
            return;  // Port already marked, nothing to do
        }
    }
    
    /* need to add the port - check if we need to expand the array */
    if (sw->num_modified_ports >= sw->modified_ports_capacity) {
        int new_capacity = (sw->modified_ports_capacity == 0) ? 8 : sw->modified_ports_capacity * 2;
        uint16_t *new_array = realloc(sw->modified_ports, new_capacity * sizeof(uint16_t));
        
        if (!new_array) {
            log_msg("Failed to allocate memory for modified ports list\n");
            pthread_mutex_unlock(&sw->modified_ports_lock);
            return;
        }
        
        sw->modified_ports = new_array;
        sw->modified_ports_capacity = new_capacity;
    }
    
    /* add the port to the list */
    sw->modified_ports[sw->num_modified_ports++] = port_no;
    
    pthread_mutex_unlock(&sw->modified_ports_lock);
}