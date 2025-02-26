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
#include "openflow.h"

#define MAX_SWITCHES 16
#define OFP_MAX_MSG_SIZE   65535
#define ECHO_INTERVAL       5    /* Send echo request every 5 seconds */
#define ECHO_TIMEOUT       15    /* Connection is dead if no reply for 15 seconds */
#define CLEANUP_INTERVAL   30

#if defined(__linux__)
    #include <endian.h>
#elif defined(__APPLE__)
    #include <libkern/OSByteOrder.h>
    #define be64toh(x) OSSwapBigToHostInt64(x)
#endif

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
    int hello_received;     /* track if HELLO was received */
    int features_received;  
    time_t last_echo;      
    time_t last_echo_reply;
    uint32_t echo_xid; 
    uint32_t last_echo_xid;     /* Last XID sent */
    bool echo_pending;          /* whether we're waiting for a reply */
};



/* global variables */
struct switch_info switches[MAX_SWITCHES];
pthread_mutex_t switches_lock = PTHREAD_MUTEX_INITIALIZER;
int server_socket;
volatile int running = 1; /* for controller clean up and running */

/* milestone 2 globals */
struct network_topology topology;
pthread_t topology_thread;

/* function prototypes */
void signal_handler(int signum); 
void log_msg(const char *format, ...); 
int main(int argc, char *argv[]);
void init_controller(int port); 
void *accept_handler(void *arg); 
void *switch_handler(void *arg); 
void cleanup_switch(struct switch_info *sw);


#endif