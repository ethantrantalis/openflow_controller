#ifndef CONTROLLER_H
#define CONTROLLER_H

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
#include "openflow.h"

#define MAX_SWITCHES 16
#define OFP_MAX_MSG_SIZE   65535

/* structure to track connected switches */
struct switch_info {
    int socket;                  /* connection socket */
    pthread_t thread;           /* handler thread */
    int active;                 /* connection status */
    
    /* switch identification */
    uint64_t datapath_id;       /* switch identifier */
    uint8_t version;           /* openFlow version */
    uint8_t n_tables;          /* number of tables */
    
    /* port tracking */
    struct ofp_phy_port *ports;     /* array of ports */
    int num_ports;             /* number of ports */
    
    /* Statistics/Monitoring */
    uint32_t packet_in_count;  /* number of packet-ins */
    uint32_t port_changes;     /* Number of port changes */
    
    pthread_mutex_t lock;      /* thread safety */
};

/* global variables */
struct switch_info switches[MAX_SWITCHES];
pthread_mutex_t switches_lock = PTHREAD_MUTEX_INITIALIZER;
int server_socket;
volatile int running = 1; /* for controller clean up and running */

/* function prototypes */
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


#endif