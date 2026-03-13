#ifndef WRAITH_CAPTURE_H
#define WRAITH_CAPTURE_H

#include "buffer.h"

struct capture_ctx {
    struct packet_buffer *buf;
    volatile int running;
    int sockfd;
};

int capture_init(struct capture_ctx *ctx, struct packet_buffer *buf);
void *capture_thread(void *arg);
void capture_stop(struct capture_ctx *ctx);

#endif
