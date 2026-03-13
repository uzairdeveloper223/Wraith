#include "capture.h"
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <string.h>

int capture_init(struct capture_ctx *ctx, struct packet_buffer *buf)
{
    ctx->buf = buf;
    ctx->running = 1;
    ctx->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ctx->sockfd < 0)
        return -1;

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    setsockopt(ctx->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return 0;
}

void *capture_thread(void *arg)
{
    struct capture_ctx *ctx = (struct capture_ctx *)arg;
    uint8_t raw[MAX_PACKET_SIZE];

    while (ctx->running) {
        ssize_t n = recvfrom(ctx->sockfd, raw, sizeof(raw), 0, NULL, NULL);
        if (n <= 0)
            continue;

        struct packet_info pkt;
        if (parse_packet(raw, (int)n, &pkt) == 0)
            buffer_push(ctx->buf, &pkt);
    }

    return NULL;
}

void capture_stop(struct capture_ctx *ctx)
{
    ctx->running = 0;
    if (ctx->sockfd >= 0) {
        close(ctx->sockfd);
        ctx->sockfd = -1;
    }
}
