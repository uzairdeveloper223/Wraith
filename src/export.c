#include "export.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>

int export_packets(const char *filename, struct packet_buffer *buf, const struct filter_rule *f)
{
    FILE *fp = fopen(filename, "w");
    if (!fp)
        return -1;

    fprintf(fp, "%-8s %-12s %-15s %-6s %-15s %-6s %-6s %-5s %-7s %s\n",
            "No.", "Time", "Source", "SPort", "Destination", "DPort",
            "Proto", "Len", "Payload", "Flags");
    fprintf(fp, "-------- ------------ --------------- ------ "
            "--------------- ------ ------ ----- ------- ----------\n");

    int count = buffer_count(buf);
    for (int i = 0; i < count; i++) {
        struct packet_info pkt = {0};
        if (!buffer_get(buf, i, &pkt))
            continue;

        if (!filter_match(f, &pkt))
            continue;

        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &pkt.src_ip, src, sizeof(src));
        inet_ntop(AF_INET, &pkt.dst_ip, dst, sizeof(dst));

        struct tm tm;
        localtime_r(&pkt.timestamp.tv_sec, &tm);
        char timestr[32];
        snprintf(timestr, sizeof(timestr), "%02d:%02d:%02d.%03ld",
                 tm.tm_hour, tm.tm_min, tm.tm_sec,
                 pkt.timestamp.tv_nsec / 1000000);

        fprintf(fp, "%-8d %-12s %-15s %-6u %-15s %-6u %-6s %-5u %-7u %s\n",
                i + 1, timestr, src, pkt.src_port, dst, pkt.dst_port,
                protocol_name(pkt.protocol), pkt.total_len,
                pkt.payload_len, pkt.flags_str);
    }

    fclose(fp);
    return 0;
}
