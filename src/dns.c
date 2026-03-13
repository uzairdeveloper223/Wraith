#include "dns.h"
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>

int dns_resolve(struct in_addr addr, char *host, int hostlen)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr = addr;

    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                    host, hostlen, NULL, 0, NI_NAMEREQD) != 0)
        return -1;

    return 0;
}
