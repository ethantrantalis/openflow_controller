#ifndef TOPOLOGY_H
#define TOPOLOGY_H

#include "controller.h"

/* milestone 2 strutcts and goodies */
#define LLDP_ETHERTYPE 0x88CC
#define LLDP_MULTICAST_ADDR "\x01\x80\xC2\x00\x00\x0E"
#define LLDP_PACKET_SIZE 32
#define TOPOLOGY_DISCOVERY_INTERVAL 10  /* seconds */
#define LINK_TIMEOUT 30                 /* seconds */
#define ETHERNET_ADDR_LEN 6

struct link {
    uint64_t src_dpid;       /* source switch datapath ID */
    uint16_t src_port;       /* aource port number */
    uint64_t dst_dpid;       /* destination switch datapath ID */
    uint16_t dst_port;       /* destination port number */
    time_t last_seen;        /* last time this link was discovered */
};

struct network_topology {
    struct link *links;      /* array of network links */
    int num_links;           /* number of links in the network */
    int capacity;            /* capacity of links array */
    pthread_mutex_t lock;    /* for thread safety */
};

/* milestone 2 prototypes */
void init_topology();
void *topology_discovery_loop(void *arg);
void send_lldp_packet(struct switch_info *sw, uint16_t port_no);
bool is_lldp_packet(uint8_t *data);
void handle_lldp_packet(struct switch_info *sw, struct ofp_packet_in *pi);
void topology_add_link(uint64_t src_dpid, uint16_t src_port, 
                       uint64_t dst_dpid, uint16_t dst_port);
void topology_cleanup_stale_links();

#endif