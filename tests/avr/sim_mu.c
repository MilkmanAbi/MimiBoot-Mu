/*
 * Run a MimiBoot-Mu Lite bootloader ELF on a simulated megaAVR (simavr),
 * USART0 on a pty (/tmp/simavr-uart0) so the real avrdude can talk to it.
 * Time is throttled to wall-clock so the bootloader's timeouts mean what
 * they say. Starts at the boot section (BOOTRST programmed).
 *
 *   sim_mu <mcu> <hz> <boot.hex> <boot_start> <seconds>
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "sim_avr.h"
#include "sim_hex.h"
#include "avr_uart.h"
#include "parts/uart_pty.h"

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

int main(int argc, char** argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: sim_mu <mcu> <hz> <boot.hex> <boot_start> <seconds>\n");
        return 2;
    }
    avr_t* avr = avr_make_mcu_by_name(argv[1]);
    if (!avr) {
        fprintf(stderr, "unknown mcu %s\n", argv[1]);
        return 1;
    }
    avr_init(avr);
    avr->frequency = strtoul(argv[2], NULL, 0);
    ihex_chunk_p chunks = NULL;
    int n_chunks = read_ihex_chunks(argv[3], &chunks);
    if (n_chunks <= 0) {
        fprintf(stderr, "can't read %s\n", argv[3]);
        return 1;
    }
    for (int i = 0; i < n_chunks; i++)       /* every section at its own address (boot code, API table) */
        avr_loadcode(avr, chunks[i].data, chunks[i].size, chunks[i].baseaddr);
    for (int a = 6; a < argc; a++) {            /* extra .hex files preloaded into flash (an app) */
        ihex_chunk_p more = NULL;
        int nm = read_ihex_chunks(argv[a], &more);
        for (int i = 0; i < nm; i++) avr_loadcode(avr, more[i].data, more[i].size, more[i].baseaddr);
    }
    avr->reset_pc = strtoul(argv[4], NULL, 0);
    avr->pc = avr->reset_pc;
    double limit = atof(argv[5]);

    /* simavr sleeps the host on every UART status poll that finds nothing
     * (AVR_UART_FLAG_POLL_SLEEP): polling firmware then runs at ~1% speed and
     * every timeout is off. The throttle below keeps real time instead. */
    uint32_t uflags = 0;
    avr_ioctl(avr, AVR_IOCTL_UART_GET_FLAGS('0'), &uflags);
    uflags &= ~AVR_UART_FLAG_POLL_SLEEP;
    avr_ioctl(avr, AVR_IOCTL_UART_SET_FLAGS('0'), &uflags);

    uart_pty_t pty;
    uart_pty_init(avr, &pty);
    uart_pty_connect(&pty, '0');
    printf("SIM READY %s\n", pty.port[0].slavename);
    fflush(stdout);
    signal(SIGTERM, on_sig);
    signal(SIGINT, on_sig);

    double t0 = now();
    int state = cpu_Running;
    unsigned n = 0;
    while (!stop && state != cpu_Done && state != cpu_Crashed) {
        state = avr_run(avr);
        if (++n % 2000 == 0) {
            double sim = (double)avr->cycle / avr->frequency, wall = now() - t0;
            static double next_trace;
            if (getenv("MU_SIM_TRACE") && wall >= next_trace) {  /* where is it? (debugging) */
                fprintf(stderr, "wall=%.2f sim=%.3f pc=0x%05x state=%d mcusr=0x%02x\n", wall, sim, avr->pc, state, avr->data[0x54]);
                next_trace = wall + 0.5;
            }
            if (sim > wall + 0.002) usleep((useconds_t)((sim - wall) * 1e6));
            if (wall > limit) break;
        }
    }
    printf("SIM END state=%d pc=0x%x\n", state, avr->pc);
    uart_pty_stop(&pty);
    return state == cpu_Crashed ? 3 : 0;
}
