#ifndef WRAITH_GEO_H
#define WRAITH_GEO_H

#include <netinet/in.h>
#include <pthread.h>

#define GEO_CACHE_SIZE 256
#define GEO_QUEUE_SIZE 64
#define GEO_COUNTRY_LEN 64
#define GEO_CITY_LEN 64
#define GEO_ISP_LEN 128

struct geo_result {
    float lat;
    float lon;
    char country[GEO_COUNTRY_LEN];
    char city[GEO_CITY_LEN];
    char isp[GEO_ISP_LEN];
    int valid;
};

struct geo_cache_entry {
    struct in_addr ip;
    struct geo_result result;
    struct geo_cache_entry *next;
    int occupied;
};

struct geo_queue_entry {
    struct in_addr ip;
    int valid;
};

struct geo_ctx {
    struct geo_cache_entry cache[GEO_CACHE_SIZE];
    struct geo_queue_entry queue[GEO_QUEUE_SIZE];
    int queue_head;
    int queue_tail;
    pthread_mutex_t lock;
    pthread_t worker;
    int running;
};

int geo_init(struct geo_ctx *ctx);
void geo_destroy(struct geo_ctx *ctx);
int geo_lookup(struct geo_ctx *ctx, struct in_addr ip, struct geo_result *out);
void geo_enqueue(struct geo_ctx *ctx, struct in_addr ip);

#endif
