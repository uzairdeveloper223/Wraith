#ifndef WRAITH_BUFFER_H
#define WRAITH_BUFFER_H

#include <pthread.h>
#include "packet.h"

#define BUFFER_CAPACITY 4096

struct packet_buffer {
    struct packet_info packets[BUFFER_CAPACITY];
    int count;
    int head;
    int total_tcp;
    int total_udp;
    int total_icmp;
    int total_other;
    pthread_mutex_t lock;
};

void buffer_init(struct packet_buffer *buf);
void buffer_push(struct packet_buffer *buf, const struct packet_info *pkt);
int buffer_count(struct packet_buffer *buf);
int buffer_get(struct packet_buffer *buf, int index, struct packet_info *out);
void buffer_stats(struct packet_buffer *buf, int *tcp, int *udp, int *icmp, int *other);
void buffer_destroy(struct packet_buffer *buf);

#endif
