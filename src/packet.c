#include "packet.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

const char *protocol_name(uint8_t proto)
{
    switch (proto) {
    case PROTO_TCP:  return "TCP";
    case PROTO_UDP:  return "UDP";
    case PROTO_ICMP: return "ICMP";
    default:         return "OTHER";
    }
}

void tcp_flags_to_str(uint8_t flags, char *buf, int buflen)
{
    if (buflen <= 0)
        return;

    int pos = 0;
    buf[0] = '\0';

    const char *names[] = {"SYN ", "ACK ", "FIN ", "RST ", "PSH ", "URG "};
    const uint8_t bits[] = {TH_SYN, TH_ACK, TH_FIN, TH_RST, TH_PUSH, TH_URG};

    for (int i = 0; i < 6; i++) {
        if (flags & bits[i]) {
            int n = snprintf(buf + pos, buflen - pos, "%s", names[i]);
            if (n < 0 || pos + n >= buflen)
                break;
            pos += n;
        }
    }

    if (pos > 0 && buf[pos - 1] == ' ')
        buf[pos - 1] = '\0';
}

int parse_packet(const uint8_t *raw, int len, struct packet_info *info)
{
    memset(info, 0, sizeof(*info));
    clock_gettime(CLOCK_REALTIME, &info->timestamp);

    if (len < (int)sizeof(struct ether_header))
        return -1;

    const struct ether_header *eth = (const struct ether_header *)raw;
    memcpy(info->src_mac, eth->ether_shost, 6);
    memcpy(info->dst_mac, eth->ether_dhost, 6);

    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return -1;

    const uint8_t *ip_data = raw + sizeof(struct ether_header);
    int ip_len = len - sizeof(struct ether_header);

    if (ip_len < (int)sizeof(struct iphdr))
        return -1;

    const struct iphdr *iph = (const struct iphdr *)ip_data;
    int ip_hdr_len = iph->ihl * 4;

    if (ip_hdr_len < 20 || ip_len < ip_hdr_len)
        return -1;

    info->src_ip.s_addr = iph->saddr;
    info->dst_ip.s_addr = iph->daddr;
    info->protocol = iph->protocol;
    info->total_len = ntohs(iph->tot_len);
    info->ttl = iph->ttl;

    const uint8_t *transport = ip_data + ip_hdr_len;
    int transport_len = ip_len - ip_hdr_len;

    switch (iph->protocol) {
    case IPPROTO_TCP: {
        if (transport_len < (int)sizeof(struct tcphdr))
            return -1;
        const struct tcphdr *tcph = (const struct tcphdr *)transport;
        info->src_port = ntohs(tcph->source);
        info->dst_port = ntohs(tcph->dest);
        info->tcp_flags = tcph->th_flags;
        int tcp_hdr_len = tcph->doff * 4;
        if (tcp_hdr_len < (int)sizeof(struct tcphdr) || tcp_hdr_len > transport_len)
            info->payload_len = 0;
        else
            info->payload_len = transport_len - tcp_hdr_len;
        tcp_flags_to_str(info->tcp_flags, info->flags_str, sizeof(info->flags_str));
        break;
    }
    case IPPROTO_UDP: {
        if (transport_len < (int)sizeof(struct udphdr))
            return -1;
        const struct udphdr *udph = (const struct udphdr *)transport;
        info->src_port = ntohs(udph->source);
        info->dst_port = ntohs(udph->dest);
        uint16_t udp_len = ntohs(udph->len);
        if (udp_len < sizeof(struct udphdr))
            info->payload_len = 0;
        else
            info->payload_len = udp_len - sizeof(struct udphdr);
        break;
    }
    case IPPROTO_ICMP: {
        if (transport_len < (int)sizeof(struct icmphdr))
            return -1;
        const struct icmphdr *icmph = (const struct icmphdr *)transport;
        info->icmp_type = icmph->type;
        info->icmp_code = icmph->code;
        info->payload_len = transport_len - sizeof(struct icmphdr);
        break;
    }
    default:
        info->payload_len = transport_len;
        break;
    }

    return 0;
}
