#ifndef CONTROLLER_H
#define CONTROLLER_H

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
#include <stdbool.h>
#include "openflow.h"

#define MAX_SWITCHES 16
#define OFP_MAX_MSG_SIZE   65535
#define ECHO_INTERVAL       5    /* Send echo request every 5 seconds */
#define ECHO_TIMEOUT       15    /* Connection is dead if no reply for 15 seconds */
#define CLEANUP_INTERVAL   30

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
    
    /* statistics/Monitoring */
    uint32_t packet_in_count;  /* number of packet-ins */
    uint32_t port_changes;     /* Number of port changes */
    
    pthread_mutex_t lock;      /* thread safety */
    int hello_received;     /* track if HELLO was received */
    bool features_received;  /* track FEATURES_REPLY receipt */
    bool ports_initialized;
    time_t last_echo;      /* last echo request sent */
    time_t last_echo_reply; /* last echo reply received */
    uint32_t echo_xid; 
    uint32_t last_echo_xid;     /* last XID sent */
    bool echo_pending;          /* whether we're waiting for a reply */
    
};

/* global variables */
struct switch_info switches[MAX_SWITCHES];
pthread_mutex_t switches_lock = PTHREAD_MUTEX_INITIALIZER;
int server_socket;
volatile int running = 1; /* for controller clean up and running */

/* function prototypes */
void signal_handler(int signum); 
void log_msg(const char *format, ...); 
int main(int argc, char *argv[]);
void init_controller(int port); 
void *accept_handler(void *arg); 
void *switch_handler(void *arg); 
void send_hello(struct switch_info *sw);
void send_openflow_msg(struct switch_info *sw, void *msg, size_t len);
void handle_switch_message(struct switch_info *sw, uint8_t *msg, size_t len);
void handle_hello(struct switch_info *sw, struct ofp_header *oh);
void send_features_request(struct switch_info *sw);
void handle_features_reply(struct switch_info *sw, struct ofp_switch_features *features); 
void handle_packet_in(struct switch_info *sw, struct ofp_packet_in *pi);
void handle_echo_request(struct switch_info *sw, struct ofp_header *oh);
bool send_echo_request(struct switch_info *sw);
void handle_echo_reply(struct switch_info *sw, struct ofp_header *oh);
void handle_port_status(struct switch_info *sw, struct ofp_port_status *ps);
void cleanup_switch(struct switch_info *sw);
#endif