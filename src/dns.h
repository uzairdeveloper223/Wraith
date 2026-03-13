#ifndef WRAITH_DNS_H
#define WRAITH_DNS_H

#include <netinet/in.h>

int dns_resolve(struct in_addr addr, char *host, int hostlen);

#endif
