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
#include <inttypes.h>
#include <stdarg.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#include <limits.h>
#include "uthash.h"
#include "openflow.h"

#define MAX_SWITCHES 16
#define OFP_MAX_MSG_SIZE   65535
#define ECHO_INTERVAL       5    /* Send echo request every 5 seconds */
#define ECHO_TIMEOUT       15    /* Connection is dead if no reply for 15 seconds */
#define CLEANUP_INTERVAL   30
#define MAC_ADDR_LEN 6
#define MAX_SWITCH_PORTS 64
#define DEBUG

#if defined(__linux__)
    #include <endian.h>
#elif defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
    #define be64toh(x) OSSwapBigToHostInt64(x)
#endif

/* mac table stuff */
struct mac_entry {
    uint8_t mac[MAC_ADDR_LEN];           /* key */
    uint64_t switch_dpid;
    uint16_t port;
    time_t last_seen;
    UT_hash_handle hh;        /* makes this structure hashable */
};

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
    
    /* port modication tracking */
    uint16_t * modified_ports;  /* array of modified ports */
    int num_modified_ports;     /* number of modified ports */
    int modified_ports_capacity;  /* capacity of modified ports array */
    pthread_mutex_t modified_ports_lock;  /* lock for modified ports */

    /* Statistics/Monitoring */
    uint32_t packet_in_count;  /* number of packet-ins */
    uint32_t port_changes;     /* Number of port changes */
    
    pthread_mutex_t lock;      /* thread safety */
    int hello_received;     /* track if HELLO was received */
    int features_received;  
    time_t last_echo;      
    time_t last_echo_reply;
    uint32_t echo_xid; 
    uint32_t last_echo_xid;     /* Last XID sent */
    bool echo_pending;          /* whether we're waiting for a reply */
};

/* forward declaration of topology structure */
struct network_topology;

/* global variables defined in controller.c */
extern struct switch_info switches[MAX_SWITCHES];
extern pthread_mutex_t switches_lock;
extern int server_socket;
extern volatile int running;

/* milestone 2 globals */
extern struct network_topology global_topology;
extern pthread_t topology_thread;


void signal_handler(int signum);
void log_msg(const char *format, ...);
int main(int argc, char *argv[]);
void init_controller(int port);
void *accept_handler(void *arg);
void *switch_handler(void *arg);
bool initialize_switch(struct switch_info *sw);
bool process_switch_messages(struct switch_info *sw);
void handle_switch_periodic_tasks(struct switch_info *sw);
void cleanup_switch(struct switch_info *sw);
void handle_switch_disconnection(struct switch_info *sw);
void mark_port_modified(struct switch_info *sw, uint16_t port_no);
/* mac table functions */
struct mac_entry *find_mac(uint8_t *mac);
void add_mac(uint8_t *mac, uint64_t dpid, uint16_t port);

#include "topology.h"
#include "communication.h"

#endif