#!/bin/sh
# Build and run the host tests (any C11 compiler: gcc, clang, MSYS2 ucrt64 gcc).
# Needs python for the signed test vectors (made with mbtool's own code).
set -e
cd "$(dirname "$0")/.."
CC=${CC:-gcc}
OUT=${OUT:-tests/mimiboot_tests}
python tests/gen_signed.py > tests/gen_signed.h
$CC -std=c11 -O1 -g -Wall -Wextra -Werror -I. -Iinclude \
    core/mb_hash.c core/mb_ed25519.c core/mb_image.c core/mb_bcl.c core/mb_config.c core/mb_policy.c \
    core/mb_recv.c core/mb_console.c core/mb_control.c core/mb_grub.c core/mb_formats.c client/mb_client.c \
    tests/sim_port.c tests/test_crypto.c tests/test_mimiboot.c -o "$OUT"
"./$OUT"
