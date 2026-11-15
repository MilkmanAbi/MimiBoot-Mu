/* Compiler integer helpers, restricted to the declared RV32IMAC ISA. */
.option norelax
.section .text
.global __ashldi3
__ashldi3:
 andi a2,a2,63
 beqz a2,3f
 li t0,32
 bgeu a2,t0,2f
 sub t0,t0,a2
 srl t1,a0,t0
 sll a1,a1,a2
 or a1,a1,t1
 sll a0,a0,a2
 ret
2: addi a2,a2,-32
 sll a1,a0,a2
 li a0,0
3: ret
.global __lshrdi3
__lshrdi3:
 andi a2,a2,63
 beqz a2,3f
 li t0,32
 bgeu a2,t0,2f
 sub t0,t0,a2
 sll t1,a1,t0
 srl a0,a0,a2
 or a0,a0,t1
 srl a1,a1,a2
 ret
2: addi a2,a2,-32
 srl a0,a1,a2
 li a1,0
3: ret
.global __ashrdi3
__ashrdi3:
 andi a2,a2,63
 beqz a2,3f
 li t0,32
 bgeu a2,t0,2f
 sub t0,t0,a2
 sll t1,a1,t0
 srl a0,a0,a2
 or a0,a0,t1
 sra a1,a1,a2
 ret
2: addi a2,a2,-32
 sra a0,a1,a2
 srai a1,a1,31
3: ret
.global __clzsi2
__clzsi2:
 li t0,32
 beqz a0,2f
 li t0,0
1: bltz a0,2f
 slli a0,a0,1
 addi t0,t0,1
 j 1b
2: mv a0,t0
 ret
.global __ctzsi2
__ctzsi2:
 li t0,32
 beqz a0,2f
 li t0,0
1: andi t1,a0,1
 bnez t1,2f
 srli a0,a0,1
 addi t0,t0,1
 j 1b
2: mv a0,t0
 ret
.global __popcountsi2
__popcountsi2:
 li t0,0
1: beqz a0,2f
 andi t1,a0,1
 add t0,t0,t1
 srli a0,a0,1
 j 1b
2: mv a0,t0
 ret
.global __bswapsi2
__bswapsi2:
 li t0,4
 li t1,0
1: andi t2,a0,255
 slli t1,t1,8
 or t1,t1,t2
 srli a0,a0,8
 addi t0,t0,-1
 bnez t0,1b
 mv a0,t1
 ret
.global __muldi3
__muldi3:
 mulhu t0,a0,a2
 mul t1,a1,a2
 mul t2,a0,a3
 add a1,t0,t1
 add a1,a1,t2
 mul a0,a0,a2
 ret
