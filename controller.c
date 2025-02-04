/* OpenFlow Controller - Milestone 1 with Threading Support
 * CPE 465 - Winter 2025
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

/* OpenFlow protocol defines */
#define OFP_VERSION 0x04  /* OpenFlow 1.3 */
#define OFP_PORT 6653     /* Default OpenFlow port */
#define OFP_MAX_PACKET_SIZE 65535
#define OFP_ETH_ALEN 6    /* Length of Ethernet address in bytes */
#define MAX_SWITCHES 256  /* Maximum number of connected switches */

/* OpenFlow message types we'll need to handle */
#define OFPT_HELLO 0
#define OFPT_ERROR 1
#define OFPT_ECHO_REQUEST 2
#define OFPT_ECHO_REPLY 3
#define OFPT_FEATURES_REQUEST 5
#define OFPT_FEATURES_REPLY 6
#define OFPT_PACKET_IN 10
#define OFPT_PORT_STATUS 12

/* Structure to represent a connected switch */
struct switch_info {
    int socket;                     /* Connection socket */
    uint64_t datapath_id;          /* Switch identifier */
    uint8_t version;               /* OpenFlow version */
    int num_ports;                 /* Number of ports */
    pthread_t thread;              /* Thread handling this switch */
    pthread_mutex_t lock;          /* Lock for thread-safe access */
    int active;                    /* Flag to indicate if connection is active */
};

/* Structure for OpenFlow packet header */
struct ofp_header {
    uint8_t version;               /* OFP_VERSION */
    uint8_t type;                  /* One of OFPT_ values */
    uint16_t length;              /* Length including this header */
    uint32_t xid;                 /* Transaction id */
};

/* Global variables */
struct switch_info switches[MAX_SWITCHES];  /* Array of switch connections */
pthread_mutex_t switches_lock;              /* Lock for switch array access */
int server_socket;                          /* Main listening socket */
volatile int running = 1;                   /* Control flag for main loop */

/* Function prototypes */
void init_controller(void);
void *switch_handler_thread(void *arg);
void *accept_connections_thread(void *arg);
void process_openflow_message(struct switch_info *sw, uint8_t *msg, size_t length);
void send_hello(struct switch_info *sw);
void send_features_request(struct switch_info *sw);
void handle_features_reply(struct switch_info *sw, uint8_t *msg);
void handle_packet_in(struct switch_info *sw, uint8_t *msg);
void handle_port_status(struct switch_info *sw, uint8_t *msg);
void cleanup(void);

/* Signal handler for graceful shutdown */
void signal_handler(int signum) {
    running = 0;
}

/* Thread-safe message sending function */
int send_message(struct switch_info *sw, void *msg, size_t length) {
    int result;
    pthread_mutex_lock(&sw->lock);
    result = send(sw->socket, msg, length, 0);
    pthread_mutex_unlock(&sw->lock);
    return result;
}

/* Main switch message handling thread */
void *switch_handler_thread(void *arg) {
    struct switch_info *sw = (struct switch_info *)arg;
    uint8_t buffer[OFP_MAX_PACKET_SIZE];
    ssize_t bytes_read;

    /* Send initial HELLO message */
    send_hello(sw);

    /* Main message processing loop for this switch */
    while (running && sw->active) {
        bytes_read = recv(sw->socket, buffer, sizeof(buffer), 0);
        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                printf("Switch connection closed\n");
            } else {
                perror("Error reading from switch");
            }
            break;
        }

        /* Process the received message */
        process_openflow_message(sw, buffer, bytes_read);
    }

    /* Clean up switch connection */
    pthread_mutex_lock(&sw->lock);
    sw->active = 0;
    close(sw->socket);
    pthread_mutex_unlock(&sw->lock);

    return NULL;
}

/* Thread that accepts new connections */
void *accept_connections_thread(void *arg) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int i;

    while (running) {
        int client_sock = accept(server_socket, (struct sockaddr *)&addr, &addr_len);
        if (client_sock < 0) {
            if (errno == EINTR && !running) {
                break;  /* Shutdown in progress */
            }
            perror("Failed to accept connection");
            continue;
        }

        /* Find free switch slot */
        pthread_mutex_lock(&switches_lock);
        for (i = 0; i < MAX_SWITCHES; i++) {
            if (!switches[i].active) {
                /* Initialize switch info */
                switches[i].socket = client_sock;
                switches[i].active = 1;
                pthread_mutex_init(&switches[i].lock, NULL);

                /* Create handler thread for this switch */
                if (pthread_create(&switches[i].thread, NULL, 
                                 switch_handler_thread, &switches[i]) != 0) {
                    perror("Failed to create switch handler thread");
                    close(client_sock);
                    switches[i].active = 0;
                    pthread_mutex_destroy(&switches[i].lock);
                } else {
                    printf("New switch connected from %s:%d\n", 
                           inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
                }
                break;
            }
        }
        pthread_mutex_unlock(&switches_lock);

        if (i == MAX_SWITCHES) {
            printf("Maximum number of switches reached, rejecting connection\n");
            close(client_sock);
        }
    }

    return NULL;
}

int main(void) {
    pthread_t accept_thread;

    /* Set up signal handling */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize mutexes */
    pthread_mutex_init(&switches_lock, NULL);

    /* Initialize the controller */
    init_controller();

    printf("OpenFlow controller starting...\n");

    /* Create accept thread */
    if (pthread_create(&accept_thread, NULL, accept_connections_thread, NULL) != 0) {
        perror("Failed to create accept thread");
        exit(1);
    }

    /* Wait for shutdown signal */
    pthread_join(accept_thread, NULL);

    /* Cleanup when done */
    cleanup();
    return 0;
}

/* Initialize the controller and create listening socket */
void init_controller(void) {
    struct sockaddr_in addr;
    int opt = 1;
    int i;

    /* Initialize switch array */
    for (i = 0; i < MAX_SWITCHES; i++) {
        memset(&switches[i], 0, sizeof(struct switch_info));
    }

    /* Create TCP socket */
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Failed to create socket");
        exit(1);
    }

    /* Set socket options */
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Bind to OpenFlow port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(OFP_PORT);

    if (bind(server_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Failed to bind");
        exit(1);
    }

    /* Listen for connections */
    if (listen(server_socket, 5) < 0) {
        perror("Failed to listen");
        exit(1);
    }
}

/* Send OpenFlow HELLO message */
void send_hello(struct switch_info *sw) {
    struct ofp_header hello;
    
    hello.version = OFP_VERSION;
    hello.type = OFPT_HELLO;
    hello.length = htons(sizeof(hello));
    hello.xid = htonl(0);

    if (send_message(sw, &hello, sizeof(hello)) < 0) {
        perror("Failed to send HELLO");
    }
}

/* Clean up resources */
void cleanup(void) {
    int i;

    /* Close all switch connections and destroy their mutexes */
    pthread_mutex_lock(&switches_lock);
    for (i = 0; i < MAX_SWITCHES; i++) {
        if (switches[i].active) {
            switches[i].active = 0;
            close(switches[i].socket);
            pthread_join(switches[i].thread, NULL);
            pthread_mutex_destroy(&switches[i].lock);
        }
    }
    pthread_mutex_unlock(&switches_lock);

    /* Destroy global mutex */
    pthread_mutex_destroy(&switches_lock);

    /* Close server socket */
    close(server_socket);
}

/* Process OpenFlow messages - to be implemented */
void process_openflow_message(struct switch_info *sw, uint8_t *msg, size_t length) {
    struct ofp_header *header = (struct ofp_header *)msg;

    switch (header->type) {
        case OFPT_HELLO:
            /* Send features request */
            send_features_request(sw);
            break;

        case OFPT_FEATURES_REPLY:
            handle_features_reply(sw, msg);
            break;

        case OFPT_PACKET_IN:
            handle_packet_in(sw, msg);
            break;

        case OFPT_PORT_STATUS:
            handle_port_status(sw, msg);
            break;

        default:
            printf("Unhandled message type: %d\n", header->type);
    }
}

/* These functions need to be implemented */
void send_features_request(struct switch_info *sw) {
    /* TODO: Implement */
}

void handle_features_reply(struct switch_info *sw, uint8_t *msg) {
    /* TODO: Implement */
}

void handle_packet_in(struct switch_info *sw, uint8_t *msg) {
    /* TODO: Implement */
}

void handle_port_status(struct switch_info *sw, uint8_t *msg) {
    /* TODO: Implement */
}