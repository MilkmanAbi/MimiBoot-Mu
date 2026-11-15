/*
 * MimiBoot - simulated port for host tests
 */
#ifndef MIMIBOOT_SIM_PORT_H
#define MIMIBOOT_SIM_PORT_H

#include "core/mimiboot.h"
#include <setjmp.h>

#define SIM_FLASH_SIZE  (2u << 20)
#define SIM_RAM_BASE    0x20000000u
#define SIM_RAM_SIZE    (512u << 10)
#define SIM_LOADER_RAM  0x20070000u     /* [this, end of RAM) is "the bootloader's own": off limits */

typedef enum {
    SIM_NONE, SIM_BOOTED, SIM_POWERCUT, SIM_REBOOT, SIM_ROM, SIM_CONSOLE_IDLE, SIM_RETURNED,
} sim_outcome_t;

typedef struct {
    jmp_buf* jmp;
    sim_outcome_t outcome;
    // flash accounting / fault injection
    uint32_t ops, cut_at;       /* cut the power at the cut_at-th erase/program (0 = never) */
    uint32_t erases, programs;
    bool fail_writes;           /* every erase/program returns an error */
    bool write_once;            /* like ECC flash: programming a page that isn't blank fails */
    bool floor_locked;          /* the protected floor store refuses writes (a chip whose lock blocks the loader too) */
    int fault_slot;             /* what the port's fault note says at the next power-on (-1: none) */
    bool launch_fails;
    // what happened
    int booted_slot;            /* -1 for a RAM image started from the console */
    bool booted_ram;            /* started from RAM */
    uint8_t booted_arch;        /* the architecture it was started on */
    uint32_t booted_off;
    mb_image_hdr_t booted_hdr;
    uint32_t watchdog_ms;
    // board
    bool button, console;
    int self_slot;
    int stage1_slot;            /* two-stage mode: the copy "running" (port->stage1_slot), -1 none */
    uint32_t reset_cause;       /* what the next power_on reports */
    uint8_t arch;               /* the architecture the "chip" runs the bootloader on */
    bool universal;             /* a bootloader half exists for both architectures */
    int arch_switches;
    uint32_t time_ms;
    // console script / capture
    char in[1 << 20];
    size_t in_len, in_pos;
    char out[1 << 16];
    size_t out_len;
} sim_t;

extern uint8_t sim_flash[SIM_FLASH_SIZE];
extern uint8_t sim_ram[SIM_RAM_SIZE];
extern sim_t sim;
extern mb_port_t sim_port;              /* tests flip require_signature / keys */
extern const uint8_t sim_test_secret[32], sim_test_public[32];

void sim_reset(void);
void sim_lms(const uint8_t* pub, const uint8_t* s1_pub);     /* LMS image / stage-1 keys (NULL: none) */
void sim_two_stage(bool on, const uint8_t s1_public[32]);   /* slots c, d -> s1a, s1b; NULL key: keep */
void sim_store_two(bool on);    /* the protected store as two 2 KB units that compact (sim_reset: one) */
void sim_input(const void* data, size_t len);
sim_outcome_t sim_power_on(void);
sim_outcome_t sim_guard(void (*fn)(void* ctx), void* ctx);

#endif
