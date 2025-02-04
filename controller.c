/* OpenFlow Controller - Milestone 1 
 * CPE 465 - Winter 2025
 * 
 * This controller implements basic OpenFlow connectivity:
 * - OpenFlow session establishment
 * - Switch information reporting
 * - PACKET_IN event monitoring
 * - Link state change monitoring
 * 
 * Can be tested with Mininet using:
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

/* OpenFlow constants from spec */
#define OFP_VERSION   0x04        /* OpenFlow 1.3 */
#define OFP_MAX_PORT_NAME_LEN 16
#define OFP_ETH_ALEN 6
#define MAX_SWITCHES 16
#define OFP_DEFAULT_PORT 6653

/* OpenFlow message types we care about for Milestone 1 */
enum ofp_type {
    OFPT_HELLO = 0,              /* Initial handshake */
    OFPT_ERROR = 1,              /* Error reporting */
    OFPT_ECHO_REQUEST = 2,       /* Connection keepalive */
    OFPT_ECHO_REPLY = 3,         /* Connection keepalive */
    OFPT_FEATURES_REQUEST = 5,   /* Request switch info */
    OFPT_FEATURES_REPLY = 6,     /* Switch info */
    OFPT_PACKET_IN = 10,         /* Packet arrived */
    OFPT_PORT_STATUS = 12,       /* Port status change */
};

/* Port status change reasons */
enum ofp_port_reason {
    OFPPR_ADD = 0,    /* The port was added */
    OFPPR_DELETE = 1, /* The port was removed */
    OFPPR_MODIFY = 2, /* Some attribute of the port has changed */
};

/* OpenFlow message header */
struct ofp_header {
    uint8_t version;              /* OFP_VERSION */
    uint8_t type;                /* Message type */
    uint16_t length;             /* Length including header */
    uint32_t xid;                /* Transaction id */
};

/* Switch features reply */
struct ofp_switch_features {
    struct ofp_header header;
    uint64_t datapath_id;        /* Switch identifier */
    uint32_t n_buffers;         /* Max packets buffered */
    uint8_t n_tables;           /* Number of flow tables */
    uint8_t auxiliary_id;       /* Auxiliary connections */
    uint8_t pad[2];            /* Alignment */
    uint32_t capabilities;      /* Supported capabilities */
    uint32_t reserved;
};

/* Port description */
struct ofp_port {
    uint32_t port_no;
    uint8_t pad[4];
    uint8_t hw_addr[OFP_ETH_ALEN];
    uint8_t pad2[2];
    char name[OFP_MAX_PORT_NAME_LEN];
    uint32_t config;        /* Port config flags */
    uint32_t state;         /* Port state flags */
    /* Rest of fields omitted for brevity */
};

/* Port status message */
struct ofp_port_status {
    struct ofp_header header;
    uint8_t reason;        /* One of OFPPR_* */
    uint8_t pad[7];        /* Alignment */
    struct ofp_port desc;  /* Port description */
};

/* Packet in message (simplified) */
struct ofp_packet_in {
    struct ofp_header header;
    uint32_t buffer_id;     /* ID assigned by datapath */
    uint16_t total_len;     /* Full length of frame */
    uint8_t reason;         /* Reason packet is being sent */
    uint8_t table_id;       /* ID of table that was looked up */
    uint64_t cookie;        /* Cookie of the flow entry */
    /* Rest of fields omitted for brevity */
};

/* Structure to track connected switches */
struct switch_info {
    int socket;                  /* Connection socket */
    pthread_t thread;           /* Handler thread */
    int active;                 /* Connection status */
    
    /* Switch identification */
    uint64_t datapath_id;       /* Switch identifier */
    uint8_t version;           /* OpenFlow version */
    uint8_t n_tables;          /* Number of tables */
    
    /* Port tracking */
    struct ofp_port *ports;     /* Array of ports */
    int num_ports;             /* Number of ports */
    
    /* Statistics/Monitoring */
    uint32_t packet_in_count;  /* Number of packet-ins */
    uint32_t port_changes;     /* Number of port changes */
    
    pthread_mutex_t lock;      /* Thread safety */
};

/* Global variables */
struct switch_info switches[MAX_SWITCHES];
pthread_mutex_t switches_lock = PTHREAD_MUTEX_INITIALIZER;
int server_socket;
volatile int running = 1;

/* Function prototypes */
void init_controller(int port);
void *switch_handler(void *arg);
void handle_switch_message(struct switch_info *sw, uint8_t *msg, size_t len);
void send_hello(struct switch_info *sw);
void send_features_request(struct switch_info *sw);
void handle_hello(struct switch_info *sw, struct ofp_header *oh);
void handle_features_reply(struct switch_info *sw, struct ofp_switch_features *features);
void handle_packet_in(struct switch_info *sw, struct ofp_packet_in *pi);
void handle_port_status(struct switch_info *sw, struct ofp_port_status *ps);
void print_switch_info(struct switch_info *sw);
void cleanup(void);

/* Signal handler */
void signal_handler(int signum) {
    printf("\nShutdown signal received, cleaning up...\n");
    running = 0;
}

/* Thread-safe logging function */
void log_msg(const char *format, ...) {
    va_list args;
    va_start(args, format);
    pthread_mutex_lock(&switches_lock);
    vprintf(format, args);
    fflush(stdout);
    pthread_mutex_unlock(&switches_lock);
    va_end(args);
}

/* Main controller function */
int main(int argc, char *argv[]) {
    int port = OFP_DEFAULT_PORT;
    
    /* Handle command line args for port number */
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    /* Set up signal handling */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("OpenFlow Controller starting on port %d...\n", port);
    printf("Supported OpenFlow version: 0x%02x\n", OFP_VERSION);
    
    /* Initialize controller */
    init_controller(port);
    
    /* Main loop - just wait for shutdown signal */
    while (running) {
        sleep(1);
    }
    
    /* Cleanup */
    cleanup();
    return 0;
}

/* Initialize controller */
void init_controller(int port) {
    struct sockaddr_in addr;
    int i, opt = 1;
    
    /* Initialize switch array */
    for (i = 0; i < MAX_SWITCHES; i++) {
        memset(&switches[i], 0, sizeof(struct switch_info));
        pthread_mutex_init(&switches[i].lock, NULL);
    }
    
    /* Create server socket */
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Failed to create socket");
        exit(1);
    }
    
    /* Set socket options */
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    /* Bind to port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(server_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Failed to bind");
        exit(1);
    }
    
    /* Listen for connections */
    if (listen(server_socket, 5) < 0) {
        perror("Failed to listen");
        exit(1);
    }
    
    /* Start accept thread */
    pthread_t accept_thread;
    if (pthread_create(&accept_thread, NULL, accept_handler, NULL) != 0) {
        perror("Failed to create accept thread");
        exit(1);
    }
}

/* Accept incoming connections */
void *accept_handler(void *arg) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    
    while (running) {
        /* Accept new connection */
        int client = accept(server_socket, (struct sockaddr *)&addr, &addr_len);
        if (client < 0) {
            if (errno == EINTR && !running) break;
            perror("Accept failed");
            continue;
        }
        
        /* Find free switch slot */
        pthread_mutex_lock(&switches_lock);
        int i;
        for (i = 0; i < MAX_SWITCHES; i++) {
            if (!switches[i].active) {
                switches[i].socket = client;
                switches[i].active = 1;
                
                /* Create handler thread */
                if (pthread_create(&switches[i].thread, NULL, switch_handler, &switches[i]) != 0) {
                    perror("Failed to create switch handler thread");
                    close(client);
                    switches[i].active = 0;
                } else {
                    log_msg("New switch connection from %s:%d\n", 
                           inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
                }
                break;
            }
        }
        pthread_mutex_unlock(&switches_lock);
        
        if (i == MAX_SWITCHES) {
            log_msg("Maximum number of switches reached, rejecting connection\n");
            close(client);
        }
    }
    return NULL;
}

/* Handler for each connected switch */
void *switch_handler(void *arg) {
    struct switch_info *sw = (struct switch_info *)arg;
    uint8_t buf[65535];
    
    /* Start OpenFlow handshake */
    send_hello(sw);
    
    /* Message handling loop */
    while (sw->active && running) {
        /* Receive message */
        ssize_t len = recv(sw->socket, buf, sizeof(buf), 0);
        if (len <= 0) {
            if (len < 0) perror("Receive failed");
            break;
        }
        
        /* Process message */
        handle_switch_message(sw, buf, len);
    }
    
    /* Clean up connection */
    pthread_mutex_lock(&sw->lock);
    if (sw->active) {
        sw->active = 0;
        close(sw->socket);
        free(sw->ports);
    }
    pthread_mutex_unlock(&sw->lock);
    
    return NULL;
}

/* Send OpenFlow message */
void send_openflow_msg(struct switch_info *sw, void *msg, size_t len) {
    pthread_mutex_lock(&sw->lock);
    if (sw->active) {
        if (send(sw->socket, msg, len, 0) < 0) {
            perror("Failed to send message");
        }
    }
    pthread_mutex_unlock(&sw->lock);
}

/* Handle incoming OpenFlow message */
void handle_switch_message(struct switch_info *sw, uint8_t *msg, size_t len) {
    struct ofp_header *oh = (struct ofp_header *)msg;
    
    /* Verify message length */
    if (len < sizeof(*oh)) {
        log_msg("Message too short\n");
        return;
    }
    
    /* Handle based on message type */
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

/* Send HELLO message */
void send_hello(struct switch_info *sw) {
    struct ofp_header hello;
    
    hello.version = OFP_VERSION;
    hello.type = OFPT_HELLO;
    hello.length = htons(sizeof(hello));
    hello.xid = htonl(0);
    
    send_openflow_msg(sw, &hello, sizeof(hello));
}

/* Handle HELLO message */
void handle_hello(struct switch_info *sw, struct ofp_header *oh) {
    sw->version = oh->version;
    log_msg("Switch hello received, version 0x%02x\n", sw->version);
    
    /* Request switch features */
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
void handle_features_reply(struct switch_info *sw, struct ofp_switch_features *features) {
    sw->datapath_id = be64toh(features->datapath_id);
    sw->n_tables = features->n_tables;
    
    log_msg("\nSwitch features:\n");
    log_msg("  Datapath ID: %016 PRIx64 \n", sw->datapath_id);
    log_msg("  OpenFlow version: 0x%02x\n", sw->version);
    log_msg("  Number of tables: %d\n", sw->n_tables);
    log_msg("  Number of buffers: %d\n", ntohl(features->n_buffers));
    
    /* Additional capabilities could be printed here */
}