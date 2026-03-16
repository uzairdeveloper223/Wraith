#include "ui.h"
#include "export.h"
#include "dns.h"
#include "geo.h"
#include "map.h"
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
#define COLOR_MAP_BASE 8

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

static void draw_help(WINDOW *win, int y, int width, int map_enabled)
{
    wattron(win, COLOR_PAIR(COLOR_STATUS));
    mvwhline(win, y, 0, ' ', width);
    if (map_enabled) {
        mvwprintw(win, y, 2,
                  "q:Quit  m:Toggle map  f:Filter  c:Clear  e:Export  d:DNS  "
                  "Up/Down:Scroll");
    } else {
        mvwprintw(win, y, 2,
                  "q:Quit  m:Toggle map  f:Filter  c:Clear  e:Export  d:DNS  "
                  "Up/Down:Scroll  PgUp/PgDn:Page");
    }
    wattroff(win, COLOR_PAIR(COLOR_STATUS));
}

static void draw_map_header(WINDOW *win, int y, int width, struct map_ctx *map_ctx, struct geo_ctx *geo_ctx __attribute__((unused)))
{
    int unique_countries = 0;
    char seen_countries[MAP_POINTS_MAX][GEO_COUNTRY_LEN];
    int seen_count = 0;
    
    for (int i = 0; i < map_ctx->count; i++) {
        int idx = (map_ctx->head - map_ctx->count + i + MAP_POINTS_MAX) % MAP_POINTS_MAX;
        struct map_point *pt = &map_ctx->points[idx];
        if (!pt->active || !pt->geo.country[0])
            continue;
        
        int found = 0;
        for (int j = 0; j < seen_count; j++) {
            if (strcmp(seen_countries[j], pt->geo.country) == 0) {
                found = 1;
                break;
            }
        }
        if (!found && seen_count < MAP_POINTS_MAX) {
            strncpy(seen_countries[seen_count], pt->geo.country, GEO_COUNTRY_LEN - 1);
            seen_countries[seen_count][GEO_COUNTRY_LEN - 1] = '\0';
            seen_count++;
        }
    }
    unique_countries = seen_count;
    
    wattron(win, COLOR_PAIR(COLOR_HEADER) | A_BOLD);
    mvwhline(win, y, 0, ' ', width);
    mvwprintw(win, y, 2, "LIVE TRAFFIC MAP | %d countries | %d located",
              unique_countries, map_ctx->total_packets);
    wattroff(win, COLOR_PAIR(COLOR_HEADER) | A_BOLD);
}

static void draw_map_ticker(WINDOW *win, int y, int width, struct map_ctx *map_ctx, int ticker_offset)
{
    wattron(win, COLOR_PAIR(COLOR_STATUS));
    mvwhline(win, y, 0, ' ', width);
    
    char ticker[2048] = "";
    int ticker_len = 0;
    int display_count = map_ctx->count < 5 ? map_ctx->count : 5;
    
    for (int i = 0; i < display_count; i++) {
        int idx = (map_ctx->head - 1 - i + MAP_POINTS_MAX) % MAP_POINTS_MAX;
        if (idx < 0)
            continue;
        struct map_point *pt = &map_ctx->points[idx];
        if (!pt->active)
            continue;
        
        char entry[256];
        snprintf(entry, sizeof(entry), " [--:--:--] %s, %s (%s)  ",
                 pt->geo.city[0] ? pt->geo.city : "Unknown",
                 pt->geo.country[0] ? pt->geo.country : "Unknown",
                 pt->geo.isp[0] ? pt->geo.isp : "Unknown");
        
        int entry_len = strlen(entry);
        if (ticker_len + entry_len < (int)sizeof(ticker) - 1) {
            strcat(ticker, entry);
            ticker_len += entry_len;
        }
    }
    
    if (ticker_len > 0) {
        int visible_width = width - 4;
        int start_pos = ticker_offset % ticker_len;
        
        int x = 2;
        for (int i = 0; i < visible_width && i < ticker_len; i++) {
            int pos = (start_pos + i) % ticker_len;
            mvwaddch(win, y, x + i, ticker[pos]);
        }
    }
    
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
    init_pair(COLOR_MAP_BASE, COLOR_WHITE, -1);

    struct filter_rule filter;
    filter_init(&filter);

    struct geo_ctx geo;
    if (geo_init(&geo) != 0) {
        endwin();
        return -1;
    }

    struct map_ctx map;
    map_init(&map);

    int scroll_pos = 0;
    int selected = 0;
    int last_count = 0;
    int autoscroll = 1;
    int map_enabled = 0;
    int ticker_offset = 0;
    int last_processed = 0;

    while (cap->running) {
        int height, width;
        getmaxyx(stdscr, height, width);

        int stats_y = 1;
        int filter_y = 2;
        int colhdr_y = 3;
        int list_start = 4;
        int list_end = height - 2;
        int help_y = height - 1;
        
        int map_header_y = 0;
        int map_start_y = 0;
        int map_ticker_y = 0;

        if (map_enabled) {
            int map_panel_height = (height * 40) / 100;
            if (map_panel_height < MAP_HEIGHT + 3)
                map_panel_height = MAP_HEIGHT + 3;
            
            list_end = height - map_panel_height - 1;
            map_header_y = list_end;
            map_start_y = map_header_y + 1;
            map_ticker_y = map_start_y + MAP_HEIGHT;
        }

        int visible = list_end - list_start;
        if (visible < 1)
            visible = 1;

        erase();

        draw_header(stdscr, width);
        draw_stats(stdscr, buf, stats_y, width);
        draw_filter_bar(stdscr, &filter, filter_y, width);
        draw_column_header(stdscr, colhdr_y);
        draw_help(stdscr, help_y, width, map_enabled);

        int count = buffer_count(buf);

        for (int i = last_processed; i < count; i++) {
            struct packet_info pkt = {0};
            if (!buffer_get(buf, i, &pkt))
                continue;
            
            geo_enqueue(&geo, pkt.dst_ip);
            
            struct geo_result geo_result = {0};
            if (geo_lookup(&geo, pkt.dst_ip, &geo_result) == 0) {
                map_add_point(&map, &geo_result, pkt.protocol);
            }
        }
        last_processed = count;

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

        if (map_enabled) {
            draw_map_header(stdscr, map_header_y, width, &map, &geo);
            
            int map_x_offset = (width - MAP_WIDTH) / 2;
            if (map_x_offset < 0)
                map_x_offset = 0;
            
            map_draw(stdscr, map_start_y, map_x_offset, &map);
            
            draw_map_ticker(stdscr, map_ticker_y, width, &map, ticker_offset);
            ticker_offset++;
        }

        refresh();

        int ch = getch();
        switch (ch) {
        case 'q':
        case 'Q':
            capture_stop(cap);
            break;
        case 'm':
        case 'M':
            map_enabled = !map_enabled;
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

    geo_destroy(&geo);
    endwin();
    return 0;
}
