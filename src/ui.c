#include "ui.h"
#include "export.h"
#include "dns.h"
#include <ncurses.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#define COLOR_TCP   1
#define COLOR_UDP   2
#define COLOR_ICMP  3
#define COLOR_OTHER 4
#define COLOR_HEADER 5
#define COLOR_STATUS 6
#define COLOR_FILTER 7

static void draw_header(WINDOW *win, int width)
{
    wattron(win, COLOR_PAIR(COLOR_HEADER) | A_BOLD);
    mvwhline(win, 0, 0, ' ', width);
    mvwprintw(win, 0, 2, " WRAITH ");
    mvwprintw(win, 0, 12, "| Silent Packet Sniffer");
    wattroff(win, COLOR_PAIR(COLOR_HEADER) | A_BOLD);
}

static int color_for_proto(uint8_t proto)
{
    switch (proto) {
    case PROTO_TCP:  return COLOR_TCP;
    case PROTO_UDP:  return COLOR_UDP;
    case PROTO_ICMP: return COLOR_ICMP;
    default:         return COLOR_OTHER;
    }
}

static void draw_stats(WINDOW *win, struct packet_buffer *buf, int y, int width __attribute__((unused)))
{
    int tcp, udp, icmp, other;
    buffer_stats(buf, &tcp, &udp, &icmp, &other);
    int total = tcp + udp + icmp + other;

    wattron(win, A_BOLD);
    mvwprintw(win, y, 2, "Packets: %d", total);
    wattroff(win, A_BOLD);

    wattron(win, COLOR_PAIR(COLOR_TCP));
    mvwprintw(win, y, 20, "TCP: %d", tcp);
    wattroff(win, COLOR_PAIR(COLOR_TCP));

    wattron(win, COLOR_PAIR(COLOR_UDP));
    mvwprintw(win, y, 34, "UDP: %d", udp);
    wattroff(win, COLOR_PAIR(COLOR_UDP));

    wattron(win, COLOR_PAIR(COLOR_ICMP));
    mvwprintw(win, y, 48, "ICMP: %d", icmp);
    wattroff(win, COLOR_PAIR(COLOR_ICMP));

    wattron(win, COLOR_PAIR(COLOR_OTHER));
    mvwprintw(win, y, 62, "Other: %d", other);
    wattroff(win, COLOR_PAIR(COLOR_OTHER));
}

static void draw_filter_bar(WINDOW *win, const struct filter_rule *f, int y, int width)
{
    wattron(win, COLOR_PAIR(COLOR_FILTER));
    mvwhline(win, y, 0, ' ', width);
    if (f->active) {
        mvwprintw(win, y, 2, "FILTER:");
        int x = 10;
        if (f->ip[0]) {
            mvwprintw(win, y, x, "IP=%s", f->ip);
            x += strlen(f->ip) + 5;
        }
        if (f->port >= 0) {
            mvwprintw(win, y, x, "Port=%d", f->port);
            x += 12;
        }
        if (f->protocol >= 0) {
            mvwprintw(win, y, x, "Proto=%s", protocol_name(f->protocol));
        }
    } else {
        mvwprintw(win, y, 2, "No filter active | 'f' to set filter");
    }
    wattroff(win, COLOR_PAIR(COLOR_FILTER));
}

static void draw_column_header(WINDOW *win, int y)
{
    wattron(win, A_BOLD | A_UNDERLINE);
    mvwprintw(win, y, 1,
              "%-5s %-12s %-15s %-6s %-15s %-6s %-5s %-5s %-7s %s",
              "No.", "Time", "Source", "SPort", "Destination", "DPort",
              "Proto", "Len", "Payload", "Flags/Info");
    wattroff(win, A_BOLD | A_UNDERLINE);
}

static void draw_packet_row(WINDOW *win, int y, int idx, const struct packet_info *pkt, int width, int selected)
{
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pkt->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &pkt->dst_ip, dst, sizeof(dst));

    struct tm tm;
    localtime_r(&pkt->timestamp.tv_sec, &tm);
    char timestr[32];
    snprintf(timestr, sizeof(timestr), "%02d:%02d:%02d.%03ld",
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             pkt->timestamp.tv_nsec / 1000000);

    char info[64] = "";
    if (pkt->protocol == PROTO_TCP && pkt->flags_str[0]) {
        snprintf(info, sizeof(info), "[%s]", pkt->flags_str);
    } else if (pkt->protocol == PROTO_ICMP) {
        snprintf(info, sizeof(info), "type=%d code=%d", pkt->icmp_type, pkt->icmp_code);
    }

    if (selected)
        wattron(win, A_REVERSE);

    wattron(win, COLOR_PAIR(color_for_proto(pkt->protocol)));
    mvwhline(win, y, 0, ' ', width);
    mvwprintw(win, y, 1,
              "%-5d %-12s %-15s %-6u %-15s %-6u %-5s %-5u %-7u %s",
              idx + 1, timestr, src, pkt->src_port, dst, pkt->dst_port,
              protocol_name(pkt->protocol), pkt->total_len,
              pkt->payload_len, info);
    wattroff(win, COLOR_PAIR(color_for_proto(pkt->protocol)));

    if (selected)
        wattroff(win, A_REVERSE);
}

static void draw_help(WINDOW *win, int y, int width)
{
    wattron(win, COLOR_PAIR(COLOR_STATUS));
    mvwhline(win, y, 0, ' ', width);
    mvwprintw(win, y, 2,
              "q:Quit  f:Filter  c:Clear filter  e:Export  d:DNS lookup  "
              "Up/Down:Scroll  PgUp/PgDn:Page");
    wattroff(win, COLOR_PAIR(COLOR_STATUS));
}

static void prompt_filter(WINDOW *win, struct filter_rule *f, int y, int width)
{
    echo();
    curs_set(1);
    nodelay(win, FALSE);
    char input[128];

    wattron(win, COLOR_PAIR(COLOR_FILTER));
    mvwhline(win, y, 0, ' ', width);
    mvwprintw(win, y, 2, "Filter IP (empty=any): ");
    wattroff(win, COLOR_PAIR(COLOR_FILTER));
    wrefresh(win);

    wgetnstr(win, input, sizeof(input) - 1);
    strncpy(f->ip, input, sizeof(f->ip) - 1);
    f->ip[sizeof(f->ip) - 1] = '\0';

    mvwhline(win, y, 0, ' ', width);
    wattron(win, COLOR_PAIR(COLOR_FILTER));
    mvwprintw(win, y, 2, "Filter Port (-1=any): ");
    wattroff(win, COLOR_PAIR(COLOR_FILTER));
    wrefresh(win);

    wgetnstr(win, input, sizeof(input) - 1);
    if (input[0] == '\0' || input[0] == '\n') {
        f->port = -1;
    } else {
        long p = strtol(input, NULL, 10);
        f->port = (p >= 0 && p <= 65535) ? (int)p : -1;
    }

    mvwhline(win, y, 0, ' ', width);
    wattron(win, COLOR_PAIR(COLOR_FILTER));
    mvwprintw(win, y, 2, "Filter Protocol (tcp/udp/icmp/empty=any): ");
    wattroff(win, COLOR_PAIR(COLOR_FILTER));
    wrefresh(win);

    wgetnstr(win, input, sizeof(input) - 1);
    f->protocol = -1;
    if (strcasecmp(input, "tcp") == 0) f->protocol = PROTO_TCP;
    else if (strcasecmp(input, "udp") == 0) f->protocol = PROTO_UDP;
    else if (strcasecmp(input, "icmp") == 0) f->protocol = PROTO_ICMP;

    f->active = (f->ip[0] || f->port >= 0 || f->protocol >= 0);

    noecho();
    curs_set(0);
    nodelay(win, TRUE);
}

static void prompt_export(WINDOW *win, struct packet_buffer *buf,
                          const struct filter_rule *f, int y, int width)
{
    echo();
    curs_set(1);
    nodelay(win, FALSE);
    char filename[256];

    wattron(win, COLOR_PAIR(COLOR_FILTER));
    mvwhline(win, y, 0, ' ', width);
    mvwprintw(win, y, 2, "Export filename: ");
    wattroff(win, COLOR_PAIR(COLOR_FILTER));
    wrefresh(win);

    wgetnstr(win, filename, sizeof(filename) - 1);
    noecho();
    curs_set(0);
    nodelay(win, TRUE);

    if (filename[0] == '\0')
        return;

    if (export_packets(filename, buf, f) == 0) {
        wattron(win, COLOR_PAIR(COLOR_STATUS));
        mvwhline(win, y, 0, ' ', width);
        mvwprintw(win, y, 2, "Exported to %s", filename);
        wattroff(win, COLOR_PAIR(COLOR_STATUS));
        wrefresh(win);
        napms(1500);
    }
}

static void show_dns_detail(WINDOW *win, const struct packet_info *pkt, int y, int width)
{
    char src_host[MAX_HOSTNAME], dst_host[MAX_HOSTNAME];
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &pkt->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &pkt->dst_ip, dst, sizeof(dst));

    if (dns_resolve(pkt->src_ip, src_host, sizeof(src_host)) != 0) {
        strncpy(src_host, src, sizeof(src_host) - 1);
        src_host[sizeof(src_host) - 1] = '\0';
    }
    if (dns_resolve(pkt->dst_ip, dst_host, sizeof(dst_host)) != 0) {
        strncpy(dst_host, dst, sizeof(dst_host) - 1);
        dst_host[sizeof(dst_host) - 1] = '\0';
    }

    wattron(win, COLOR_PAIR(COLOR_STATUS) | A_BOLD);
    mvwhline(win, y, 0, ' ', width);
    mvwprintw(win, y, 2, "DNS: %s -> %s", src_host, dst_host);
    wattroff(win, COLOR_PAIR(COLOR_STATUS) | A_BOLD);
    wrefresh(win);
    napms(3000);
}

int ui_run(struct packet_buffer *buf, struct capture_ctx *cap)
{
    initscr();
    start_color();
    use_default_colors();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);

    init_pair(COLOR_TCP, COLOR_GREEN, -1);
    init_pair(COLOR_UDP, COLOR_CYAN, -1);
    init_pair(COLOR_ICMP, COLOR_YELLOW, -1);
    init_pair(COLOR_OTHER, COLOR_WHITE, -1);
    init_pair(COLOR_HEADER, COLOR_BLACK, COLOR_WHITE);
    init_pair(COLOR_STATUS, COLOR_BLACK, COLOR_GREEN);
    init_pair(COLOR_FILTER, COLOR_BLACK, COLOR_CYAN);

    struct filter_rule filter;
    filter_init(&filter);

    int scroll_pos = 0;
    int selected = 0;
    int last_count = 0;
    int autoscroll = 1;

    while (cap->running) {
        int height, width;
        getmaxyx(stdscr, height, width);

        int stats_y = 1;
        int filter_y = 2;
        int colhdr_y = 3;
        int list_start = 4;
        int list_end = height - 2;
        int help_y = height - 1;
        int visible = list_end - list_start;

        if (visible < 1)
            visible = 1;

        erase();

        draw_header(stdscr, width);
        draw_stats(stdscr, buf, stats_y, width);
        draw_filter_bar(stdscr, &filter, filter_y, width);
        draw_column_header(stdscr, colhdr_y);
        draw_help(stdscr, help_y, width);

        int count = buffer_count(buf);

        int filtered_indices[BUFFER_CAPACITY];
        int filtered_count = 0;
        for (int i = 0; i < count && filtered_count < BUFFER_CAPACITY; i++) {
            struct packet_info pkt = {0};
            if (!buffer_get(buf, i, &pkt))
                continue;
            if (filter_match(&filter, &pkt))
                filtered_indices[filtered_count++] = i;
        }

        if (autoscroll && filtered_count > last_count) {
            if (filtered_count > visible) {
                scroll_pos = filtered_count - visible;
                selected = filtered_count - 1;
            }
        }
        last_count = filtered_count;

        if (scroll_pos > filtered_count - visible)
            scroll_pos = filtered_count - visible;
        if (scroll_pos < 0)
            scroll_pos = 0;

        for (int i = 0; i < visible && (scroll_pos + i) < filtered_count; i++) {
            int idx = filtered_indices[scroll_pos + i];
            struct packet_info pkt = {0};
            if (!buffer_get(buf, idx, &pkt))
                continue;
            draw_packet_row(stdscr, list_start + i, idx,
                            &pkt, width, (scroll_pos + i) == selected);
        }

        refresh();

        int ch = getch();
        switch (ch) {
        case 'q':
        case 'Q':
            capture_stop(cap);
            break;
        case KEY_UP:
        case 'k':
            autoscroll = 0;
            if (selected > 0) selected--;
            if (selected < scroll_pos) scroll_pos = selected;
            break;
        case KEY_DOWN:
        case 'j':
            autoscroll = 0;
            if (selected < filtered_count - 1) selected++;
            if (selected >= scroll_pos + visible)
                scroll_pos = selected - visible + 1;
            break;
        case KEY_PPAGE:
            autoscroll = 0;
            selected -= visible;
            if (selected < 0) selected = 0;
            scroll_pos -= visible;
            if (scroll_pos < 0) scroll_pos = 0;
            break;
        case KEY_NPAGE:
            autoscroll = 0;
            selected += visible;
            if (selected >= filtered_count) selected = filtered_count - 1;
            if (selected < 0) selected = 0;
            scroll_pos += visible;
            if (scroll_pos > filtered_count - visible)
                scroll_pos = filtered_count - visible;
            if (scroll_pos < 0) scroll_pos = 0;
            break;
        case 'G':
            autoscroll = 1;
            break;
        case 'f':
        case 'F':
            prompt_filter(stdscr, &filter, filter_y, width);
            scroll_pos = 0;
            selected = 0;
            break;
        case 'c':
        case 'C':
            filter_init(&filter);
            scroll_pos = 0;
            selected = 0;
            autoscroll = 1;
            break;
        case 'e':
        case 'E':
            prompt_export(stdscr, buf, &filter, filter_y, width);
            break;
        case 'd':
        case 'D':
            if (selected >= 0 && selected < filtered_count) {
                struct packet_info pkt = {0};
                if (buffer_get(buf, filtered_indices[selected], &pkt))
                    show_dns_detail(stdscr, &pkt, filter_y, width);
            }
            break;
        default:
            break;
        }

        napms(50);
    }

    endwin();
    return 0;
}