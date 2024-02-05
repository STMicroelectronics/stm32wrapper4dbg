/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause */
/*
 * Copyright (c) 2019-2023, STMicroelectronics - All Rights Reserved
 * Author: Antonio Borneo <antonio.borneo@foss.st.com>
 */

/*
 * The assembly code below has been obtained by manual editing the result
 * of compiling this C code fragment, with the command:
 *   arm-none-eabi-gcc -mcpu=cortex-a7 -Os -mthumb -S wrapper.c
 * Use this C code as reference to easily read the assembly and/or to
 * experiment changes to the assembly code.
 * Please keep aligned assembly and C code.
 *
 - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - -

#include <stdint.h>

#define BSEC_DENABLE	0x5c005014
#define BSEC_DENABLE_NI	0x45f
#define BSEC_DENABLE_I	0x47f
#define DBG_CLAIM_0	(1UL << 0)
#define DELAY_SECONDS	2

void __attribute__((noreturn)) (*fsbl)(int a, int b, int c, int d);

static inline void write_bsec_denable(uint32_t v)
{
	*(volatile uint32_t *)BSEC_DENABLE = v;
}

static inline uint32_t get_dbg_claimclr(void)
{
	uint32_t val;

	asm volatile("mrc\tp14, 0, %0, c7, c9, 6" : "=r" (val));
	return val;
}

static inline void set_dbg_claimclr(uint32_t val)
{
	asm volatile("mcr\tp14, 0, %0, c7, c9, 6" : : "r" (val));
}

static inline uint32_t arch_timer_get_cntfrq(void)
{
	uint32_t val;

	asm volatile("mrc\tp15, 0, %0, c14, c0, 0" : "=r" (val));
	return val;
}

static inline uint64_t arch_counter_get_cntpct(void)
{
	uint64_t val;

	asm volatile("mrrc\tp15, 0, %Q0, %R0, c14" : "=r" (val));
	return val;
}

void __attribute__((noreturn)) wrapper(int a, int b, int c, int d)
{
	uint32_t denable_val;
	uint32_t t0, t1, delay, deadline;
	int64_t dt64;
	int32_t dt;

	denable_val = BSEC_DENABLE_NI;
	write_bsec_denable(denable_val);

	delay = DELAY_SECONDS * arch_timer_get_cntfrq();
	t0 = (uint32_t)arch_counter_get_cntpct();
	deadline = t0 + delay;

	do {
		t1 = (uint32_t)arch_counter_get_cntpct();
		dt64 = ((int64_t)t1) - ((int64_t)deadline);
		dt = (int32_t)dt64;
		if (dt >= 0)
			goto timeout;

	} while ((get_dbg_claimclr() & DBG_CLAIM_0) == 0);

	set_dbg_claimclr(DBG_CLAIM_0);

timeout:
	denable_val += (BSEC_DENABLE_I - BSEC_DENABLE_NI);
	write_bsec_denable(denable_val);
	fsbl(a, b, c, d);
}

 - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - -
 */

#define BSEC_DENABLE	0x5c005014
#define BSEC_DENABLE_NI	0x45f
#define BSEC_DENABLE_I	0x47f

	.cpu cortex-a7
	.text
	.align	1
	.global	_start
	.arch armv7ve
	.syntax unified
	.thumb
	.thumb_func
_start:
	ldr	r4, .bsec_denable
	movw	r5, #BSEC_DENABLE_NI
	str	r5, [r4]

	dsb	sy

	mrc	p15, 0, r6, c14, c0, 0
	mrrc	p15, 0, r7, r8, c14
	add	r6, r7, r6, lsl #1

.L1:
	mrrc	p15, 0, r7, r8, c14
	subs	r7, r7, r6
	bpl	.L2

	mrc	p14, 0, r7, c7, c9, 6
	ands	r7, r7, #1
	beq	.L1

	mcr	p14, 0, r7, c7, c9, 6

.L2:
	ldr	r6, fsbl_ptr

	adds	r5, #(BSEC_DENABLE_I - BSEC_DENABLE_NI)
	isb
	str	r5, [r4]

	bx	r6

	.align	2
.bsec_denable:
	.word	BSEC_DENABLE
fsbl_ptr:
