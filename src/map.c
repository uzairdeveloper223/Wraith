#include "map.h"
#include "packet.h"
#include <string.h>
#include <time.h>

#define COLOR_MAP_BASE 8
#define COLOR_MAP_TCP 1
#define COLOR_MAP_UDP 2
#define COLOR_MAP_ICMP 3
#define COLOR_MAP_OTHER 4

static const char *map_rows[MAP_HEIGHT] = {
    "                                                                        ",
    "             #    ##  ##########       ##                               ",
    "   ##### ### ##### # ##  ######         ###     ########################",
    "   ##############   ##    #          ## ###########################  ## ",
    "         ################         ## ############################  #    ",
    "           #############            ## ### ## ################# #       ",
    "            #########              # #  # #### ############# # #        ",
    "              ###  #              ##########################            ",
    "               ## #              ########## ####   ##  ##               ",
    "                                 ############      #    ##              ",
    "                     #####            ########         ##  #            ",
    "                    ########          ######            #   #  ##       ",
    "                     #######           #####                  # #       ",
    "                      ######           ####  #              ######      ",
    "                      ####             ###                 ########     ",
    "                     ##                                       ##      ",
    "                     ##                                              #  ",
    "                     #                                                  ",
    "                                                                        ",
    "                      #                   ######## #################    ",
    "    #################        ########################################   ",
    "                                                                        ",
};
void map_init(struct map_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

void map_add_point(struct map_ctx *ctx, const struct geo_result *geo, uint8_t protocol)
{
    if (!geo || !geo->valid)
        return;
    
    ctx->points[ctx->head].geo = *geo;
    ctx->points[ctx->head].protocol = protocol;
    ctx->points[ctx->head].active = 1;
    
    ctx->head = (ctx->head + 1) % MAP_POINTS_MAX;
    if (ctx->count < MAP_POINTS_MAX)
        ctx->count++;
    
    ctx->total_packets++;
}

void map_latlon_to_xy(float lat, float lon, int map_w, int map_h, int *x, int *y)
{
    float norm_x = (lon + 180.0f) / 360.0f;
    float norm_y = (90.0f - lat) / 180.0f;
    
    *x = (int)(norm_x * map_w);
    *y = (int)(norm_y * map_h);
    
    if (*x < 0) *x = 0;
    if (*x >= map_w) *x = map_w - 1;
    if (*y < 0) *y = 0;
    if (*y >= map_h) *y = map_h - 1;
}

static int color_for_proto(uint8_t proto)
{
    switch (proto) {
    case PROTO_TCP:  return COLOR_MAP_TCP;
    case PROTO_UDP:  return COLOR_MAP_UDP;
    case PROTO_ICMP: return COLOR_MAP_ICMP;
    default:         return COLOR_MAP_OTHER;
    }
}

void map_draw(WINDOW *win, int y_offset, int x_offset, struct map_ctx *ctx)
{
    char display[MAP_HEIGHT][MAP_WIDTH + 1];
    int colors[MAP_HEIGHT][MAP_WIDTH];
    int blink[MAP_HEIGHT][MAP_WIDTH];

    for (int y = 0; y < MAP_HEIGHT; y++) {
        memcpy(display[y], map_rows[y], MAP_WIDTH);
        display[y][MAP_WIDTH] = '\0';
        for (int x = 0; x < MAP_WIDTH; x++) {
            colors[y][x] = COLOR_MAP_BASE;
            blink[y][x] = 0;
        }
    }

    int hit_count[MAP_HEIGHT][MAP_WIDTH];
    memset(hit_count, 0, sizeof(hit_count));

    int most_recent_idx = (ctx->head - 1 + MAP_POINTS_MAX) % MAP_POINTS_MAX;

    for (int i = 0; i < ctx->count; i++) {
        int idx = (ctx->head - ctx->count + i + MAP_POINTS_MAX) % MAP_POINTS_MAX;
        struct map_point *pt = &ctx->points[idx];

        if (!pt->active)
            continue;

        int x, y;
        map_latlon_to_xy(pt->geo.lat, pt->geo.lon, MAP_WIDTH, MAP_HEIGHT, &x, &y);

        hit_count[y][x]++;
        colors[y][x] = color_for_proto(pt->protocol);

        if (idx == most_recent_idx && ctx->count > 0)
            blink[y][x] = 1;
    }

    for (int y = 0; y < MAP_HEIGHT; y++) {
        for (int x = 0; x < MAP_WIDTH; x++) {
            if (hit_count[y][x] > 0) {
                if (hit_count[y][x] == 1)
                    display[y][x] = '*';
                else if (hit_count[y][x] < 5)
                    display[y][x] = '+';
                else
                    display[y][x] = '@';
            }
        }
    }

    for (int y = 0; y < MAP_HEIGHT; y++) {
        wmove(win, y_offset + y, x_offset);
        for (int x = 0; x < MAP_WIDTH; x++) {
            int attr = COLOR_PAIR(colors[y][x]);
            if (blink[y][x] && hit_count[y][x] > 0)
                attr |= A_BLINK | A_BOLD;
            else if (hit_count[y][x] > 0)
                attr |= A_BOLD;

            wattron(win, attr);
            waddch(win, display[y][x]);
            wattroff(win, attr);
        }
    }
}
