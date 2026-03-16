#include "geo.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <curl/curl.h>
#include <arpa/inet.h>

#define API_URL_FMT "http://ip-api.com/json/%s?fields=country,city,isp,lat,lon,status"
#define API_RESPONSE_MAX 4096

struct curl_response {
    char *data;
    size_t size;
};

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct curl_response *resp = (struct curl_response *)userp;
    
    char *ptr = realloc(resp->data, resp->size + realsize + 1);
    if (!ptr)
        return 0;
    
    resp->data = ptr;
    memcpy(&(resp->data[resp->size]), contents, realsize);
    resp->size += realsize;
    resp->data[resp->size] = 0;
    
    return realsize;
}

static int is_private_ip(struct in_addr ip)
{
    uint32_t addr = ntohl(ip.s_addr);
    uint8_t a = (addr >> 24) & 0xFF;
    uint8_t b = (addr >> 16) & 0xFF;
    
    if (a == 10) return 1;
    if (a == 172 && b >= 16 && b <= 31) return 1;
    if (a == 192 && b == 168) return 1;
    if (a == 127) return 1;
    if (a == 0) return 1;
    
    return 0;
}

static unsigned int hash_ip(struct in_addr ip)
{
    uint32_t addr = ntohl(ip.s_addr);
    uint8_t last = addr & 0xFF;
    uint8_t second = (addr >> 8) & 0xFF;
    return (last ^ second) % GEO_CACHE_SIZE;
}

static int cache_get(struct geo_ctx *ctx, struct in_addr ip, struct geo_result *out)
{
    unsigned int bucket = hash_ip(ip);
    struct geo_cache_entry *entry = &ctx->cache[bucket];

    while (entry) {
        if (entry->occupied && entry->ip.s_addr == ip.s_addr) {
            if (out)
                *out = entry->result;
            return entry->result.valid;
        }
        entry = entry->next;
    }

    return 0;
}

static void cache_put(struct geo_ctx *ctx, struct in_addr ip, const struct geo_result *result)
{
    unsigned int bucket = hash_ip(ip);
    struct geo_cache_entry *entry = &ctx->cache[bucket];

    if (!entry->occupied) {
        entry->ip = ip;
        entry->result = *result;
        entry->occupied = 1;
        entry->next = NULL;
        return;
    }

    while (entry) {
        if (entry->ip.s_addr == ip.s_addr) {
            entry->result = *result;
            return;
        }
        if (!entry->next) {
            struct geo_cache_entry *new_entry = calloc(1, sizeof(struct geo_cache_entry));
            if (!new_entry)
                return;
            new_entry->ip = ip;
            new_entry->result = *result;
            new_entry->occupied = 1;
            new_entry->next = NULL;
            entry->next = new_entry;
            return;
        }
        entry = entry->next;
    }
}

static void parse_json_response(const char *json, struct geo_result *result)
{
    memset(result, 0, sizeof(*result));
    result->valid = 0;
    
    const char *status = strstr(json, "\"status\"");
    if (status) {
        const char *success = strstr(status, "success");
        if (!success || success > status + 30)
            return;
    }
    
    const char *lat_key = strstr(json, "\"lat\"");
    if (lat_key) {
        const char *colon = strchr(lat_key, ':');
        if (colon)
            result->lat = strtof(colon + 1, NULL);
    }
    
    const char *lon_key = strstr(json, "\"lon\"");
    if (lon_key) {
        const char *colon = strchr(lon_key, ':');
        if (colon)
            result->lon = strtof(colon + 1, NULL);
    }
    
    const char *country_key = strstr(json, "\"country\"");
    if (country_key) {
        const char *colon = strchr(country_key, ':');
        if (colon) {
            const char *start = strchr(colon, '"');
            if (start) {
                start++;
                const char *end = strchr(start, '"');
                if (end) {
                    size_t len = end - start;
                    if (len >= GEO_COUNTRY_LEN)
                        len = GEO_COUNTRY_LEN - 1;
                    memcpy(result->country, start, len);
                    result->country[len] = '\0';
                }
            }
        }
    }
    
    const char *city_key = strstr(json, "\"city\"");
    if (city_key) {
        const char *colon = strchr(city_key, ':');
        if (colon) {
            const char *start = strchr(colon, '"');
            if (start) {
                start++;
                const char *end = strchr(start, '"');
                if (end) {
                    size_t len = end - start;
                    if (len >= GEO_CITY_LEN)
                        len = GEO_CITY_LEN - 1;
                    memcpy(result->city, start, len);
                    result->city[len] = '\0';
                }
            }
        }
    }
    
    const char *isp_key = strstr(json, "\"isp\"");
    if (isp_key) {
        const char *colon = strchr(isp_key, ':');
        if (colon) {
            const char *start = strchr(colon, '"');
            if (start) {
                start++;
                const char *end = strchr(start, '"');
                if (end) {
                    size_t len = end - start;
                    if (len >= GEO_ISP_LEN)
                        len = GEO_ISP_LEN - 1;
                    memcpy(result->isp, start, len);
                    result->isp[len] = '\0';
                }
            }
        }
    }
    
    result->valid = 1;
}

static int fetch_geo_data(struct in_addr ip, struct geo_result *result)
{
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
    
    char url[256];
    snprintf(url, sizeof(url), API_URL_FMT, ip_str);
    
    CURL *curl = curl_easy_init();
    if (!curl)
        return -1;
    
    struct curl_response resp = {0};
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    
    if (res != CURLE_OK) {
        free(resp.data);
        return -1;
    }
    
    if (resp.data) {
        parse_json_response(resp.data, result);
        free(resp.data);
        return result->valid ? 0 : -1;
    }
    
    return -1;
}

static void *geo_worker_thread(void *arg)
{
    struct geo_ctx *ctx = (struct geo_ctx *)arg;
    CURL *curl = curl_easy_init();
    if (!curl)
        return NULL;
    
    while (ctx->running) {
        struct in_addr ip = {0};
        int has_work = 0;
        
        pthread_mutex_lock(&ctx->lock);
        if (ctx->queue_head != ctx->queue_tail) {
            struct geo_queue_entry *entry = &ctx->queue[ctx->queue_head];
            if (entry->valid) {
                ip = entry->ip;
                has_work = 1;
                entry->valid = 0;
            }
            ctx->queue_head = (ctx->queue_head + 1) % GEO_QUEUE_SIZE;
        }
        pthread_mutex_unlock(&ctx->lock);
        
        if (!has_work) {
            usleep(100000);
            continue;
        }
        
        if (is_private_ip(ip))
            continue;
        
        pthread_mutex_lock(&ctx->lock);
        int cached = cache_get(ctx, ip, NULL);
        pthread_mutex_unlock(&ctx->lock);
        
        if (cached)
            continue;
        
        struct geo_result result = {0};
        if (fetch_geo_data(ip, &result) == 0) {
            pthread_mutex_lock(&ctx->lock);
            cache_put(ctx, ip, &result);
            pthread_mutex_unlock(&ctx->lock);
        }
    }
    
    curl_easy_cleanup(curl);
    return NULL;
}

int geo_init(struct geo_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    
    int ret = pthread_mutex_init(&ctx->lock, NULL);
    if (ret != 0)
        return -1;
    
    ctx->running = 1;
    ret = pthread_create(&ctx->worker, NULL, geo_worker_thread, ctx);
    if (ret != 0) {
        pthread_mutex_destroy(&ctx->lock);
        return -1;
    }
    
    return 0;
}

void geo_destroy(struct geo_ctx *ctx)
{
    ctx->running = 0;
    pthread_join(ctx->worker, NULL);

    for (int i = 0; i < GEO_CACHE_SIZE; i++) {
        struct geo_cache_entry *entry = ctx->cache[i].next;
        while (entry) {
            struct geo_cache_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        ctx->cache[i].next = NULL;
        ctx->cache[i].occupied = 0;
    }

    pthread_mutex_destroy(&ctx->lock);
}

int geo_lookup(struct geo_ctx *ctx, struct in_addr ip, struct geo_result *out)
{
    if (is_private_ip(ip))
        return -1;
    
    pthread_mutex_lock(&ctx->lock);
    int found = cache_get(ctx, ip, out);
    pthread_mutex_unlock(&ctx->lock);
    
    return found ? 0 : -1;
}

void geo_enqueue(struct geo_ctx *ctx, struct in_addr ip)
{
    if (is_private_ip(ip))
        return;

    pthread_mutex_lock(&ctx->lock);

    int cached = cache_get(ctx, ip, NULL);
    if (cached) {
        pthread_mutex_unlock(&ctx->lock);
        return;
    }

    int next_tail = (ctx->queue_tail + 1) % GEO_QUEUE_SIZE;
    if (next_tail != ctx->queue_head) {
        ctx->queue[ctx->queue_tail].ip = ip;
        ctx->queue[ctx->queue_tail].valid = 1;
        ctx->queue_tail = next_tail;
    }

    pthread_mutex_unlock(&ctx->lock);
}
