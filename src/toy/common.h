#pragma once

#include <stdint.h>

typedef struct x64_cpu_state {
    int64_t regs[16];
} x64_cpu_state_t;

int run();

extern char *ram_image;

extern int ram_base_offset;