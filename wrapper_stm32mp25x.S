/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause */
/*
 * Copyright (c) 2019-2022, STMicroelectronics - All Rights Reserved
 * Author: Antonio Borneo <antonio.borneo@st.com>
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

#define BSEC_DENR	0x44000e20
#define BSEC_DENR_I	0xdeb60fff
#define BSEC_DENR_NI	(BSEC_DENR_I - 0x00000020)
#define DBG_CLAIM_0	(1ULL << 0)
#define DELAY_SECONDS	2

void __attribute__((noreturn)) (*fsbl)(uint64_t a, uint64_t b, uint64_t c, uint64_t d);

static inline void write_bsec_denr(uint32_t v)
{
	*(volatile uint32_t *)BSEC_DENR = v;
}

static inline uint64_t get_dbg_claimclr(void)
{
	uint64_t val;

	asm volatile("mrs\t%0, dbgclaimclr_el1" : "=r" (val));
	return val;
}

static inline uint64_t arch_timer_get_cntfrq(void)
{
	uint64_t val;

	asm volatile("mrs\t%0, cntfrq_el0" : "=r" (val));
	return val;
}

static inline uint64_t arch_counter_get_cntpct(void)
{
	uint64_t val;

	asm volatile("mrs\t%0, cntpct_el0" : "=r" (val));
	return val;
}

void __attribute__((noreturn)) wrapper(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
	uint32_t denr_val;
	uint64_t t0, t1, delay, deadline;

	denr_val = BSEC_DENR_NI;
	write_bsec_denr(denr_val);

	delay = DELAY_SECONDS * arch_timer_get_cntfrq();
	t0 = arch_counter_get_cntpct();
	deadline = t0 + delay;

	do {
		t1 = arch_counter_get_cntpct();
		if (t1 >= deadline)
			break;
	} while ((get_dbg_claimclr() & DBG_CLAIM_0) == 0);

	denr_val += (BSEC_DENR_I - BSEC_DENR_NI);
	write_bsec_denr(denr_val);
	fsbl(a, b, c, d);
}

uint64_t test(uint32_t *p)
{
	return 1ULL + *p;
}

 - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - -
*/

#define BSEC_DENR	0x44000e20
#define BSEC_DENR_I	0xdeb60fff
#define BSEC_DENR_NI	0xdeb60fdf

	.arch	armv8-a+crc
	.text
	.align	2
	.global	_start
	.type	_start, %function
_start:
	ldr	w4, .bsec_denr
	ldr	w5, .bsec_denr_ni
	str	w5, [x4]

	dsb	sy

	/*
	 * BootROM does not set cntfrq_el0. Use hardcoded value instead of
	 * mrs x6, cntfrq_el0
	 */
	ldr	w6, .cntfrq_el0_val
	mrs	x7, cntpct_el0
	add	x6, x7, x6, lsl #1

.L1:
	mrs	x7, cntpct_el0
	cmp	x6, x7
	bls	.L2

	mrs	x7, dbgclaimclr_el1
	tbz	x7, 0, .L1

.L2:
	ldr	w6, fsbl_ptr

	add	w5, w5, #(BSEC_DENR_I - BSEC_DENR_NI)
	isb
	str	w5, [x4]

	br	x6

	.align	2
.bsec_denr:
	.word	BSEC_DENR
.bsec_denr_ni:
	.word	BSEC_DENR_NI
.cntfrq_el0_val:
	.word	32000000
fsbl_ptr:
