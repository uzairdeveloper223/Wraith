#ifndef WRAITH_MAP_H
#define WRAITH_MAP_H

#include <ncurses.h>
#include "geo.h"

#define MAP_WIDTH 72
#define MAP_HEIGHT 22
#define MAP_POINTS_MAX 128

struct map_point {
    struct geo_result geo;
    uint8_t protocol;
    int active;
};

struct map_ctx {
    struct map_point points[MAP_POINTS_MAX];
    int head;
    int count;
    int total_packets;
};

void map_init(struct map_ctx *ctx);
void map_add_point(struct map_ctx *ctx, const struct geo_result *geo, uint8_t protocol);
void map_latlon_to_xy(float lat, float lon, int map_w, int map_h, int *x, int *y);
void map_draw(WINDOW *win, int y_offset, int x_offset, struct map_ctx *ctx);

#endif
