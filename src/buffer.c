#include "buffer.h"
#include <string.h>

void buffer_init(struct packet_buffer *buf)
{
    memset(buf, 0, sizeof(*buf));
    pthread_mutex_init(&buf->lock, NULL);
}

void buffer_push(struct packet_buffer *buf, const struct packet_info *pkt)
{
    pthread_mutex_lock(&buf->lock);

    buf->packets[buf->head] = *pkt;
    buf->head = (buf->head + 1) % BUFFER_CAPACITY;
    if (buf->count < BUFFER_CAPACITY)
        buf->count++;

    switch (pkt->protocol) {
    case PROTO_TCP:  buf->total_tcp++; break;
    case PROTO_UDP:  buf->total_udp++; break;
    case PROTO_ICMP: buf->total_icmp++; break;
    default:         buf->total_other++; break;
    }

    pthread_mutex_unlock(&buf->lock);
}

int buffer_count(struct packet_buffer *buf)
{
    pthread_mutex_lock(&buf->lock);
    int c = buf->count;
    pthread_mutex_unlock(&buf->lock);
    return c;
}

int buffer_get(struct packet_buffer *buf, int index, struct packet_info *out)
{
    int ok = 0;
    pthread_mutex_lock(&buf->lock);
    if (index >= 0 && index < buf->count) {
        int real = (buf->head - buf->count + index + BUFFER_CAPACITY) % BUFFER_CAPACITY;
        *out = buf->packets[real];
        ok = 1;
    }
    pthread_mutex_unlock(&buf->lock);
    return ok;
}

void buffer_stats(struct packet_buffer *buf, int *tcp, int *udp, int *icmp, int *other)
{
    pthread_mutex_lock(&buf->lock);
    *tcp = buf->total_tcp;
    *udp = buf->total_udp;
    *icmp = buf->total_icmp;
    *other = buf->total_other;
    pthread_mutex_unlock(&buf->lock);
}

void buffer_destroy(struct packet_buffer *buf)
{
    pthread_mutex_destroy(&buf->lock);
}
