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
#define ECHO_INTERVAL       5    /* send echo request every 5 seconds */
#define ECHO_TIMEOUT       15    /* connection is dead if no reply for 15 seconds */
#define CLEANUP_INTERVAL   30
#define MAC_ADDR_LEN 6

/* lldp packet strcutre offsets */
#define LLDP_DST_MAC_OFFSET 0
#define LLDP_SRC_MAC_OFFSET 6
#define LLDP_ETHERTYPE_OFFSET 12
#define LLDP_MAGIC_OFFSET 14
#define LLDP_TYPE_OFFSET 18
#define LLDP_SRC_DPID_OFFSET 19
#define LLDP_SRC_PORT_OFFSET 27

/* ethernet packet structure offsets */
#define ETH_DST_OFFSET 0
#define ETH_SRC_OFFSET 6
#define ETH_ETHERTYPE_OFFSET 12

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
    
    /* state tracking */
    int hello_received;     /* track if HELLO was received */
    int features_received;  /* track FEATURES_REPLY receipt */

    /* echoe for connections */
    time_t last_echo;      /* last echo request sent */
    time_t last_echo_reply; /* last echo reply received */
    uint32_t echo_xid; 
    uint32_t last_echo_xid;     /* last XID sent */
    bool echo_pending;          /* whether we're waiting for a reply */

    pthread_mutex_t lock;      /* thread safety */
};

struct mac_entry {
    uint8_t mac[MAC_ADDR_LEN]; /* key */
    uint64_t switch_dpid;
    uint16_t port_no;
    time_t last_seen;
    UT_hash_handle hh; /* makes this structure hashable */
}; 

struct network_topology {
    igraph_t graph;                /* iGraph object representing the network */
    pthread_mutex_t lock;          /* lock for thread safety */
    
    igraph_vector_t dpid_to_vertex;  /* map datapath IDs to vertex IDs */
};

/* global variables */
extern struct switch_info switches[MAX_SWITCHES];
extern pthread_mutex_t switches_lock;
extern int server_socket;
extern volatile int running; /* for controller clean up and running */
extern struct network_topology topology;

/* function prototypes */
void signal_handler(int signum); 
void log_msg(const char *format, ...);
void cleanup_switch(struct switch_info *sw);

void add_or_update_mac(uint8_t *mac, uint64_t dpid, uint16_t port_no);
struct mac_entry *find_mac(uint8_t *mac);

int main(int argc, char *argv[]);
void init_controller(int port); 
void *accept_handler(void *arg); 
void *switch_handler(void *arg);
 
/* messaging */
void send_hello(struct switch_info *sw);
void handle_hello(struct switch_info *sw, struct ofp_header *oh);

void send_openflow_msg(struct switch_info *sw, void *msg, size_t len);
void handle_switch_message(struct switch_info *sw, uint8_t *msg, size_t len);

void send_features_request(struct switch_info *sw);
void handle_features_reply(struct switch_info *sw, struct ofp_switch_features *features); 

void handle_echo_request(struct switch_info *sw, struct ofp_header *oh);
bool send_echo_request(struct switch_info *sw);
void handle_echo_reply(struct switch_info *sw, struct ofp_header *oh);

/* flows */
void handle_packet_in(struct switch_info *sw, struct ofp_packet_in *pi);
void handle_port_status(struct switch_info *sw, struct ofp_port_status *ps);

/* topology */
void init_topology();
void handle_switch_join(struct switch_info *sw);
void handle_switch_disconnect(struct switch_info *sw); 
void handle_port_change(struct switch_info *sw, uint16_t src_port_no, bool is_up); 

void add_or_update_link(uint64_t src_dpid, uint16_t src_port, uint64_t dst_dpid, uint16_t dst_port);
void add_vertex(uint64_t dpid); 
void remove_links_for_port(uint64_t dpid, uint16_t src_port_no);
void remove_all_switch_links(uint64_t dpid);
uint64_t vertex_to_dpid(igraph_integer_t vertex_id);

void send_topology_discovery_packet(struct switch_info *sw, uint16_t port_no);
bool is_topology_discovery_packet(uint8_t *data, size_t len);
bool extract_discovery_packet_info(uint8_t *data, size_t len, uint64_t *src_dpid, uint16_t *src_port);
void handle_discovery_packet(struct switch_info *sw, struct ofp_packet_in *pi);

/* flows */
void handle_unicast_packet(struct switch_info *sw, struct ofp_packet_in *pi, struct mac_entry *dst);
void handle_broadcast_packet(struct switch_info *sw, struct ofp_packet_in *pi, struct mac_entry *src);
void install_flow(struct switch_info *sw, uint16_t in_port, uint16_t dst_port, uint32_t buff_id, struct mac_entry *dst);
void send_packet_out(struct switch_info *sw, uint16_t in_port, uint16_t out_port, uint32_t buff_id, uint8_t *data, size_t len);

#endif