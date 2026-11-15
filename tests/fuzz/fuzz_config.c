/*
 * Fuzz target: the boot config parser (core/mb_config.c), and what the boot
 * decision does with whatever it parsed.
 */
#include "tests/sim_port.h"
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* d, size_t n) {
    static mb_config_t cfg;
    char err[96];
    if (n > MB_CFG_MAX) n = MB_CFG_MAX;
    mb_config_parse(&sim_port, (const char*)d, n, &cfg, err, sizeof(err));
    if (cfg.def >= 0 && cfg.def < cfg.n && cfg.n <= MB_MAX_ENTRIES) {
        // the decision over a parsed config, on an empty board: entries name slots and args
        static bool once;
        if (!once) { sim_reset(); once = true; }
        static mb_bcl_t log;
        static mb_slot_info_t info[MB_MAX_SLOTS];
        static mb_plan_t plan;
        mb_bcl_load(&log, &sim_port);
        mb_decide(&sim_port, &log, &cfg, info, 0, &plan);
        for (int e = 0; e < cfg.n; e++) mb_plan_entry(&sim_port, &log, &cfg, info, e, NULL, &plan);
    }
    return 0;
}
