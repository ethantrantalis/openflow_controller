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
#include </opt/homebrew/Cellar/igraph/0.10.15_1/include/igraph/igraph.h>
#include "openflow.h"
#include "uthash.h"

#define MAX_SWITCHES 16
#define OFP_MAX_MSG_SIZE   65535
#define HELLO_TIMEOUT      5    /* wait for HELLO for 5 seconds */
#define FEATURES_TIMEOUT      5    /* wait for HELLO for 5 seconds */
#define ECHO_INTERVAL       5    /* send echo request every 5 seconds */
#define ECHO_TIMEOUT       15    /* connection is dead if no reply for 15 seconds */
#define CLEANUP_INTERVAL   30
#define MAC_ADDR_LEN 6


/* structure to track connected switches */
struct switch_info {
    int socket; /* connection socket */
    pthread_t thread; /* handler thread */
    int active; /* connection status */
    
    /* switch identification */
    uint64_t datapath_id; /* switch identifier */
    uint8_t version; /* openFlow version */
    uint8_t n_tables; /* number of tables */
    
    /* port tracking */
    struct ofp_phy_port *ports; /* array of ports */
    int num_ports; /* number of ports */
    
    /* connection initialization */
    bool hello_received; /* track if HELLO was received */
    bool features_received; /* track FEATURES_REPLY receipt */

    /* connection maintainance */
    time_t last_echo; /* last echo request sent */
    bool echo_pending; /* echo request pending */
    time_t last_echo_reply; /* last echo reply received */
    uint32_t last_echo_xid; /* last echo request XID */

    pthread_mutex_t lock; /* thread safety */
};

struct mac_entry {
    uint8_t mac[MAC_ADDR_LEN]; /* key */
    uint64_t switch_dpid;
    time_t last_seen;
    UT_hash_handle hh; /* makes this structure hashable */
};

/* global variables */
struct switch_info switches[MAX_SWITCHES];
pthread_mutex_t switches_lock = PTHREAD_MUTEX_INITIALIZER;
int server_socket;
volatile int running = 1; /* for controller clean up and running */

/* function prototypes */
void add_mac(uint8_t *mac, uint64_t dpid);
struct mac_entry *find_mac(uint8_t *mac);

void signal_handler(int signum); 
void log_msg(const char *format, ...); 

void init_controller(int port); 
void *accept_handler(void *arg); 
void *switch_handler(void *arg); 

int send_openflow_msg(struct switch_info *sw, void *msg, size_t len, char * type);

int send_hello(struct switch_info *sw);
int handle_hello(struct switch_info *sw, struct ofp_header *oh);

int send_features_request(struct switch_info *sw);
void handle_features_reply(struct switch_info *sw, struct ofp_switch_features *features);

int send_echo_request(struct switch_info *sw);
void handle_echo_request(struct switch_info *sw, struct ofp_header *oh);
void handle_echo_reply(struct switch_info *sw, struct ofp_header *oh);

void handle_switch_message(struct switch_info *sw, uint8_t *msg, size_t len);
void handle_packet_in(struct switch_info *sw, struct ofp_packet_in *pi);
void handle_port_status(struct switch_info *sw, struct ofp_port_status *ps);
void cleanup_switch(struct switch_info *sw);


#endif