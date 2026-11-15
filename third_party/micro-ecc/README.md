# micro-ecc (vendored)

https://github.com/kmackay/micro-ecc, tag v1.2 (commit 541b3a78026420a3e369c4c9281c396b5e531113,
November 2024, includes the mitigation for the "hcca" attack). BSD 2-clause, see LICENSE.txt.

Only the files the build needs are here, unmodified. MimiBoot compiles them through
`core/mb_ecdsa.c`, which picks the configuration: portable C (no assembly), the P-256
curve only, no compressed points, and no random-number source (only `uECC_verify` is
used; it needs none).
