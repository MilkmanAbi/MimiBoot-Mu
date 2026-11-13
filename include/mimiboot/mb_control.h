#ifndef MIMIBOOT_CONTROL_H
#define MIMIBOOT_CONTROL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define MB_CONTROL_API_VERSION 1
#define MB_CAP_CONTROL (1u << 0)
#define MB_CAP_CONFIG (1u << 1)
#define MB_CAP_RAM (1u << 2)
#define MB_CAP_ARM (1u << 3)
#define MB_CAP_RISCV (1u << 4)
#define MB_CAP_MIXED (1u << 5)
#define MB_CAP_ARCH_SWITCH (1u << 6)
#define MB_CAP_XIP (1u << 7)
#define MB_HOFF_NIGHT 0x80000000u
/* Zero means image/same-as-core0. Values 1/2 match MB_ARCH_ARM/RISCV. */
typedef struct {
    uint8_t core0, core1;
    uint16_t reserved;
} mb_topology_t;
typedef enum {
    MB_CONTROL_RESTART,
    MB_CONTROL_MENU,
    MB_CONTROL_CONFIG,
    MB_CONTROL_ROM,
    MB_CONTROL_FLASH,
    MB_CONTROL_ENTRY,
    MB_CONTROL_SLOT
} mb_control_action_t;
typedef struct {
    uint16_t version, size;
    uint32_t action;
    mb_topology_t topology;
    uint8_t slot;
    uint8_t reserved[3];
    char entry[16];
    char args[96];
} mb_control_request_t;
struct mb_port;
uint32_t mb_control_caps(const struct mb_port *);
int mb_topology_validate(const struct mb_port *, mb_topology_t);
int mb_topology_resolve(const struct mb_port *, mb_topology_t, uint8_t image_arch, mb_topology_t *);
int mb_control_submit(const struct mb_port *, const mb_control_request_t *);
int mb_control_reboot(const struct mb_port *, const mb_control_request_t *);
#endif
