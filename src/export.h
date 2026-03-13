#ifndef WRAITH_EXPORT_H
#define WRAITH_EXPORT_H

#include "buffer.h"
#include "filter.h"

int export_packets(const char *filename, struct packet_buffer *buf, const struct filter_rule *f);

#endif
