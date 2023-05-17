#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct x64_cpu_state {
    int64_t regs[16];
    char ccflags[6];
} x64_cpu_state_t;

int run(x64_cpu_state_t *cpu);

void error(const char *msg);

void syscall(x64_cpu_state_t *cpu);

void dump_state(int64_t ip, x64_cpu_state_t *cpu);

extern char *ram_image;

extern int ram_amt;

const int ram_base_offset = 0x401000;

#define REG_RAX(cpu) cpu->regs[0]
#define REG_RBX(cpu) cpu->regs[1]
#define REG_RCX(cpu) cpu->regs[2]
#define REG_RDX(cpu) cpu->regs[3]
#define REG_RSI(cpu) cpu->regs[4]
#define REG_RDI(cpu) cpu->regs[5]
#define REG_RBP(cpu) cpu->regs[6]
#define REG_RSP(cpu) cpu->regs[7]
#define REG_R8(cpu)  cpu->regs[8]
#define REG_R9(cpu)  cpu->regs[9]
#define REG_R10(cpu) cpu->regs[10]
#define REG_R11(cpu) cpu->regs[11]
#define REG_R12(cpu) cpu->regs[12]
#define REG_R13(cpu) cpu->regs[13]
#define REG_R14(cpu) cpu->regs[14]
#define REG_R15(cpu) cpu->regs[15]

#define REG_EAX(cpu)  *(int32_t *) (&cpu->regs[0])
#define REG_EBX(cpu)  *(int32_t *) (&cpu->regs[1])
#define REG_ECX(cpu)  *(int32_t *) (&cpu->regs[2])
#define REG_EDX(cpu)  *(int32_t *) (&cpu->regs[3])
#define REG_ESI(cpu)  *(int32_t *) (&cpu->regs[4])
#define REG_EDI(cpu)  *(int32_t *) (&cpu->regs[5])
#define REG_EBP(cpu)  *(int32_t *) (&cpu->regs[6])
#define REG_ESP(cpu)  *(int32_t *) (&cpu->regs[7])
#define REG_R8D(cpu)  *(int32_t *) (&cpu->regs[8])
#define REG_R9D(cpu)  *(int32_t *) (&cpu->regs[9])
#define REG_R10D(cpu) *(int32_t *) (&cpu->regs[10])
#define REG_R11D(cpu) *(int32_t *) (&cpu->regs[11])
#define REG_R12D(cpu) *(int32_t *) (&cpu->regs[12])
#define REG_R13D(cpu) *(int32_t *) (&cpu->regs[13])
#define REG_R14D(cpu) *(int32_t *) (&cpu->regs[14])
#define REG_R15D(cpu) *(int32_t *) (&cpu->regs[15])

#define REG_AX(cpu)   *(int16_t *) (&cpu->regs[0])
#define REG_BX(cpu)   *(int16_t *) (&cpu->regs[1])
#define REG_CX(cpu)   *(int16_t *) (&cpu->regs[2])
#define REG_DX(cpu)   *(int16_t *) (&cpu->regs[3])
#define REG_SI(cpu)   *(int16_t *) (&cpu->regs[4])
#define REG_DI(cpu)   *(int16_t *) (&cpu->regs[5])
#define REG_BP(cpu)   *(int16_t *) (&cpu->regs[6])
#define REG_SP(cpu)   *(int16_t *) (&cpu->regs[7])
#define REG_R8W(cpu)  *(int16_t *) (&cpu->regs[8])
#define REG_R9W(cpu)  *(int16_t *) (&cpu->regs[9])
#define REG_R10W(cpu) *(int16_t *) (&cpu->regs[10])
#define REG_R11W(cpu) *(int16_t *) (&cpu->regs[11])
#define REG_R12W(cpu) *(int16_t *) (&cpu->regs[12])
#define REG_R13W(cpu) *(int16_t *) (&cpu->regs[13])
#define REG_R14W(cpu) *(int16_t *) (&cpu->regs[14])
#define REG_R15W(cpu) *(int16_t *) (&cpu->regs[15])

#define REG_AL(cpu)   *(int8_t *) (&cpu->regs[0])
#define REG_BL(cpu)   *(int8_t *) (&cpu->regs[1])
#define REG_CL(cpu)   *(int8_t *) (&cpu->regs[2])
#define REG_DL(cpu)   *(int8_t *) (&cpu->regs[3])
#define REG_SIL(cpu)  *(int8_t *) (&cpu->regs[4])
#define REG_DIL(cpu)  *(int8_t *) (&cpu->regs[5])
#define REG_BPL(cpu)  *(int8_t *) (&cpu->regs[6])
#define REG_SPL(cpu)  *(int8_t *) (&cpu->regs[7])
#define REG_R8L(cpu)  *(int8_t *) (&cpu->regs[8])
#define REG_R9L(cpu)  *(int8_t *) (&cpu->regs[9])
#define REG_R10L(cpu) *(int8_t *) (&cpu->regs[10])
#define REG_R11L(cpu) *(int8_t *) (&cpu->regs[11])
#define REG_R12L(cpu) *(int8_t *) (&cpu->regs[12])
#define REG_R13L(cpu) *(int8_t *) (&cpu->regs[13])
#define REG_R14L(cpu) *(int8_t *) (&cpu->regs[14])
#define REG_R15L(cpu) *(int8_t *) (&cpu->regs[15])

#define CCFLAG_OF 0
#define CCFLAG_SF 1
#define CCFLAG_ZF 2
#define CCFLAG_AF 3
#define CCFLAG_CF 4
#define CCFLAG_PF 5

#define MEMORY(int_type, addr) *(int_type *) (ram_image + addr - ram_base_offset)

#define DEBUG(...) printf(__VA_ARGS__)

#ifdef __cplusplus
}
#endif