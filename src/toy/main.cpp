#include <iostream>

#include <memory.h>

#include "binary_data.h"
#include "common.h"

char *ram_image;

int ram_amt = 64 * 1024 * 1024;

static const uint64_t host_stack_offset = 0x7fffffffde08 + 8;

static const uint64_t guest_text_base = ram_base_offset + sizeof(binary_data);

static const uint64_t guest_stack_base = guest_text_base + 2 * 1024 * 1024;

void dump_state(int64_t ip, x64_cpu_state_t *cpu) {
    //    return;
    x64_cpu_state_t cpu2 = *cpu;
    for (long &reg : cpu2.regs) {
        if (reg > guest_text_base + 0x100000 && reg < guest_stack_base) {
            reg += host_stack_offset - guest_stack_base;
        }
    }

    printf("0x%016lx:0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx\n",
           ip, cpu2.regs[0], cpu2.regs[1], cpu2.regs[2], cpu2.regs[3], cpu2.regs[4], cpu2.regs[5], cpu2.regs[6],
           cpu2.regs[7], cpu2.regs[8], cpu2.regs[9], cpu2.regs[10], cpu2.regs[11], cpu2.regs[12], cpu2.regs[13],
           cpu2.regs[14], cpu2.regs[15]);
    fflush(stdout);
}

void syscall(x64_cpu_state_t *cpu) {
    ssize_t ret;

    //    printf("0x404000: %d\n", MEMORY(int32_t, 0x404000));

    auto nr = REG_RAX(cpu);
    if (nr < 2) {
        int64_t rdi = REG_RDI(cpu);
        int64_t rsi = (int64_t) &MEMORY(int64_t, REG_RSI(cpu));
        int64_t rdx = REG_RDX(cpu);

        asm volatile("syscall"
                     : "=a"(ret)
                     //                 EDI      RSI       RDX
                     : "0"(nr), "D"(rdi), "S"(rsi), "d"(rdx));
    } else {
        int64_t rdi = REG_RDI(cpu);
        int64_t rsi = REG_RSI(cpu);
        int64_t rdx = REG_RDX(cpu);

        asm volatile("syscall"
                     : "=a"(ret)
                     //                 EDI      RSI       RDX
                     : "0"(nr), "D"(rdi), "S"(rsi), "d"(rdx));
    }

    REG_RAX(cpu) = ret;
}

int main(int argc, char *argv[]) {
    ram_image = new char[ram_amt];
    memcpy(ram_image, binary_data, sizeof(binary_data));

    x64_cpu_state_t state;
    auto cpu = &state;

    // Clear cpu state
    memset(cpu, 0, sizeof(x64_cpu_state_t));

    // Set initial registers
    REG_RSP(cpu) = (int64_t) guest_stack_base;

    run(cpu);

    std::cout << "Shouldn't reach here." << std::endl;

    return 0;
}