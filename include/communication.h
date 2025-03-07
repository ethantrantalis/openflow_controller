#ifndef COMMUNICATION_H
#define COMMUNICATION_H

#include "controller.h"

void send_hello(struct switch_info *sw);
int send_openflow_msg(struct switch_info *sw, void *msg, size_t len);
void handle_switch_message(struct switch_info *sw, uint8_t *msg, size_t len);
void handle_hello(struct switch_info *sw, struct ofp_header *oh);
void send_features_request(struct switch_info *sw);
void handle_features_reply(struct switch_info *sw, struct ofp_switch_features *features); 
void handle_packet_in(struct switch_info *sw, struct ofp_packet_in *pi);
void handle_echo_request(struct switch_info *sw, struct ofp_header *oh);
bool send_echo_request(struct switch_info *sw);
void handle_echo_reply(struct switch_info *sw, struct ofp_header *oh);
void handle_port_status(struct switch_info *sw, struct ofp_port_status *ps);

/* flow installation */
void send_packet_out(struct switch_info *sw, uint8_t *data, size_t data_len, uint16_t out_port);
void send_flow_mod(struct switch_info *sw, uint8_t *dst_mac, uint16_t output_port); 
#endif