/* Integer division without toolchain-specific multilib ISA extensions.
 * This also keeps Zcmp out of compiler helpers reachable from trap dispatch. */
#include <stdint.h>
#include <stdbool.h>
typedef uint64_t u64;
u64 mb_udiv64(u64 n, u64 d, u64 *rem)
{
    u64 q = 0, r = 0;
    if (!d) {
        if (rem)
            *rem = n;
        return UINT64_MAX;
    }
    for (int i = 63; i >= 0; i--) {
        bool carry = (r >> 63) != 0;
        r = (r << 1) | ((n >> i) & 1);
        if (carry || r >= d) {
            r -= d;
            q |= (u64)1 << i;
        }
    }
    if (rem)
        *rem = r;
    return q;
}
#ifdef __riscv
u64 __udivdi3(u64 n, u64 d)
{
    return mb_udiv64(n, d, 0);
}
u64 __umoddi3(u64 n, u64 d)
{
    u64 r;
    mb_udiv64(n, d, &r);
    return r;
}
u64 __udivmoddi4(u64 n, u64 d, u64 *r)
{
    return mb_udiv64(n, d, r);
}
#endif
