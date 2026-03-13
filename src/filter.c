#include "filter.h"
#include <string.h>
#include <arpa/inet.h>

void filter_init(struct filter_rule *f)
{
    memset(f, 0, sizeof(*f));
    f->port = -1;
    f->protocol = -1;
    f->active = 0;
}

int filter_match(const struct filter_rule *f, const struct packet_info *pkt)
{
    if (!f->active)
        return 1;

    if (f->ip[0] != '\0') {
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &pkt->src_ip, src, sizeof(src));
        inet_ntop(AF_INET, &pkt->dst_ip, dst, sizeof(dst));
        if (strcmp(f->ip, src) != 0 && strcmp(f->ip, dst) != 0)
            return 0;
    }

    if (f->port >= 0 && (pkt->protocol == PROTO_TCP || pkt->protocol == PROTO_UDP)) {
        if (pkt->src_port != f->port && pkt->dst_port != f->port)
            return 0;
    }

    if (f->protocol >= 0) {
        if (pkt->protocol != f->protocol)
            return 0;
    }

    return 1;
}
