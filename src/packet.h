#ifndef WRAITH_PACKET_H
#define WRAITH_PACKET_H

#include <stdint.h>
#include <netinet/in.h>
#include <time.h>

#define MAX_PACKET_SIZE 65536
#define MAX_FLAGS_STR 32
#define MAX_HOSTNAME 256

enum protocol {
    PROTO_TCP = 6,
    PROTO_UDP = 17,
    PROTO_ICMP = 1,
    PROTO_OTHER = 255
};

struct packet_info {
    struct timespec timestamp;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint16_t total_len;
    uint16_t payload_len;
    uint8_t ttl;
    uint8_t tcp_flags;
    char flags_str[MAX_FLAGS_STR];
    char src_host[MAX_HOSTNAME];
    char dst_host[MAX_HOSTNAME];
    uint8_t icmp_type;
    uint8_t icmp_code;
};

int parse_packet(const uint8_t *raw, int len, struct packet_info *info);
void tcp_flags_to_str(uint8_t flags, char *buf, int buflen);
const char *protocol_name(uint8_t proto);

#endif
