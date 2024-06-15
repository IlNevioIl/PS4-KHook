#pragma once
#ifndef HOOKING_H
#define HOOKING_H

#include <payload_utils.h>
#include <fw_defines.h>

#define KERNEL_BASE &((uint8_t *)__readmsr(0xC0000082))[-K505_XFAST_SYSCALL]

/* 9.00 */
#define KERNEL_PRINTF               KERNEL_BASE + 0x000B7A30
#define KERNEL_SNPRINTF             KERNEL_BASE + 0x000B7D30
#define KERNEL_DISPATCH_CODE_CAVE   KERNEL_BASE + 0x00093150 // hammer_time
#define KERNEL_MEMCPY               KERNEL_BASE + 0x002714B0
#define KERNEL_COPYIN               KERNEL_BASE + 0x002716A0
#define KERNEL_MAP                  KERNEL_BASE + 0x02268D48
#define KERNEL_KMEM_ALLOC           KERNEL_BASE + 0x0037BE70
#define KERNEL_KMEM_FREE            KERNEL_BASE + 0x0037C040
#define KERNEL_PAGEDAEMON_WAKEUP    KERNEL_BASE + 0x00107490
/* End of 9.00 */
#define KEXEC_ARGS_BUFFER           (void *)0xDEAD0000

#define CREATE_FMT_STR(BUF, STR) \
    for(int i = 0;;i++) {        \
        if(STR[i] == '\x00') {   \
            break;               \
        }                        \
        BUF[i] = STR[i];         \
    }

#define SAVE_REGISTERS      \
    asm(                    \
        "push %rbx\n\t"     \
        "push %r12\n\t"     \
        "push %r13\n\t"     \
        "push %r14\n\t"     \
        "push %r15\n\t"     \
        "push %rax\n\t"     \
        "push %rdi\n\t"     \
        "push %rsi\n\t"     \
        "push %rdx\n\t"     \
        "push %rcx\n\t"     \
        "push %r8\n\t"      \
        "push %r9\n\t"      \
        "push %r10\n\t"     \
        "push %r11\n\t"     \
    )

#define RESTORE_REGISTERS   \
    asm(                    \
        "pop %r11\n\t"      \
        "pop %r10\n\t"      \
        "pop %r9\n\t"       \
        "pop %r8\n\t"       \
        "pop %rcx\n\t"      \
        "pop %rdx\n\t"      \
        "pop %rsi\n\t"      \
        "pop %rdi\n\t"      \
        "pop %rax\n\t"      \
        "pop %r15\n\t"      \
        "pop %r14\n\t"      \
        "pop %r13\n\t"      \
        "pop %r12\n\t"      \
        "pop %rbx\n\t"      \
    )

struct hook_dispatch_entry
{
    void *payloadAddress;
    uint32_t payloadSize;
    uint32_t trampolineOffset;
};

struct dispatch_table
{
    char relayCode[0x20];
    struct hook_dispatch_entry entries[0x22];
};

struct install_hook_args
{
    uint16_t id;
    uint64_t *targetOffset;
    uint64_t trampolineSize;
    uint64_t *hookFunctionAddr;
    uint64_t hookFunctionSize;
};

struct uninstall_hook_args
{
    uint16_t id;
    uint64_t *targetOffset;
};

void kernel_initialize_dispatch(struct thread *td, void *argsUnused);
void kernel_install_hook(struct thread *td, void *argsUnused);
void kernel_uninstall_hook(struct thread *td, void *argsUnused);

#endif
