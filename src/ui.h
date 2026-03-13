#ifndef WRAITH_UI_H
#define WRAITH_UI_H

#include "buffer.h"
#include "filter.h"
#include "capture.h"

int ui_run(struct packet_buffer *buf, struct capture_ctx *cap);

#endif
