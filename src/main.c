#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "buffer.h"
#include "capture.h"
#include "ui.h"

int main(void)
{
    struct packet_buffer buf;
    buffer_init(&buf);

    struct capture_ctx cap;
    if (capture_init(&cap, &buf) < 0) {
        fprintf(stderr, "wraith: failed to create raw socket (run as root)\n");
        return 1;
    }

    pthread_t tid;
    if (pthread_create(&tid, NULL, capture_thread, &cap) != 0) {
        fprintf(stderr, "wraith: failed to start capture thread\n");
        capture_stop(&cap);
        buffer_destroy(&buf);
        return 1;
    }

    ui_run(&buf, &cap);

    capture_stop(&cap);
    pthread_join(tid, NULL);
    buffer_destroy(&buf);

    return 0;
}
