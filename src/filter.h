#ifndef WRAITH_FILTER_H
#define WRAITH_FILTER_H

#include "packet.h"

struct filter_rule {
    char ip[64];
    int port;
    int protocol;
    int active;
};

void filter_init(struct filter_rule *f);
int filter_match(const struct filter_rule *f, const struct packet_info *pkt);

#endif
