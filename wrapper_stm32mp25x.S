/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause */
/*
 * Copyright (c) 2019-2023, STMicroelectronics - All Rights Reserved
 * Author: Antonio Borneo <antonio.borneo@foss.st.com>
 */

/*
 * The assembly code below has been obtained by manual editing the result
 * of compiling this C code fragment, with the command:
 *   aarch64-linux-gnu-gcc -mcpu=cortex-a35 -Os -S wrapper.c
 * Use this C code as reference to easily read the assembly and/or to
 * experiment changes to the assembly code.
 * Please keep aligned assembly and C code.
 *
 - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - -

#include <stdbool.h>
#include <stdint.h>

#define BSEC_DENR			0x44000e20
#define BSEC_DENR_I			0xdeb60fff
#define BSEC_DENR_NI			(BSEC_DENR_I - 0x00000020)
#define DBG_CLAIM_0			(1ULL << 0)
#define RIFSC_RIMC_CR			0x42080c00
#define RIFSC_RIMC_CR_TDCID_SHIFT	4
#define RIFSC_RIMC_CR_TDCID_MASK	0x00000070
#define STGENC_CNTFID0			0x48080020
#define DELAY_SECONDS			2
#define TDCID				1
#define MPIDR_CPUID_MASK		0x0000ffff

void __attribute__((noreturn)) (*fsbl)(uint64_t a, uint64_t b, uint64_t c, uint64_t d);

static bool is_tdcid(void)
{
	uint32_t rimc_cr, cid;

	rimc_cr = *(volatile uint32_t *)RIFSC_RIMC_CR;
	cid = (rimc_cr & RIFSC_RIMC_CR_TDCID_MASK) >> RIFSC_RIMC_CR_TDCID_SHIFT;
	return cid == TDCID;
}

static uint32_t cpu_id(void)
{
	uint64_t val;

	asm volatile("mrs\t%0, mpidr_el1" : "=r" (val));
	return val & MPIDR_CPUID_MASK;
}

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

static inline void set_dbg_claimclr(uint32_t val)
{
	asm volatile("msr\tdbgclaimclr_el1, %0" : : "r" (val));
}

static inline uint64_t arch_timer_get_cntfrq(void)
{
	uint64_t val;

	// BootROM does not initialize cntfrq
	// asm volatile("mrs\t%0, cntfrq_el0" : "=r" (val));
	//
	// Read the frequency from STGEN.
	// STGEN clock in RCC is already enabled by the BootROM.
	val = *(volatile uint32_t *)STGENC_CNTFID0;
	return val;
}

static inline uint64_t arch_counter_get_cntpct(void)
{
	uint64_t val;

	asm volatile("mrs\t%0, cntpct_el0" : "=r" (val));
	return val;
}

static inline void wait_for_event(void)
{
	asm volatile("wfe");
}

static inline void send_event(void)
{
	asm volatile("sev");
}

void __attribute__((noreturn)) wrapper(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
	uint32_t denr_val;
	uint64_t t0, t1, delay, deadline;

	if (cpu_id()) {
		wait_for_event();
		goto finish;
	}

	if (!is_tdcid())
		goto finish;

	denr_val = BSEC_DENR_NI;
	write_bsec_denr(denr_val);

	delay = DELAY_SECONDS * arch_timer_get_cntfrq();
	t0 = arch_counter_get_cntpct();
	deadline = t0 + delay;

	do {
		t1 = arch_counter_get_cntpct();
		if (t1 >= deadline)
			goto timeout;
	} while ((get_dbg_claimclr() & DBG_CLAIM_0) == 0);

	set_dbg_claimclr(DBG_CLAIM_0);

timeout:
	denr_val += (BSEC_DENR_I - BSEC_DENR_NI);
	write_bsec_denr(denr_val);

	send_event();

finish:
	fsbl(a, b, c, d);
}

uint64_t test(uint32_t *p)
{
	return 1ULL + *p;
}

 - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - -
*/

#define BSEC_DENR			0x44000e20
#define BSEC_DENR_I			0xdeb60fff
#define BSEC_DENR_NI			0xdeb60fdf
#define RIFSC_RIMC_CR			0x42080c00
#define STGENC_CNTFID0			0x48080020

#define RIFSC_RIMC_CR_TDCID_SHIFT	4
#define RIFSC_RIMC_CR_TDCID_MASK	0x00000070
#define TDCID				1
#define MPIDR_CPUID_MASK		0x0000ffff

	.arch	armv8-a+crc
	.text
	.align	2
	.global	_start
	.type	_start, %function
_start:
	mrs	x4, mpidr_el1
	tst	x4, #MPIDR_CPUID_MASK
	bne	.L3

	ldr	w4, .rifsc_rimc_cr
	ldr	w4, [x4]
	and	w4, w4, #RIFSC_RIMC_CR_TDCID_MASK
	cmp	w4, #(TDCID << RIFSC_RIMC_CR_TDCID_SHIFT)
	bne	.L4

	ldr	w4, .bsec_denr
	ldr	w5, .bsec_denr_ni
	str	w5, [x4]

	dsb	sy

	/*
	 * BootROM does not set cntfrq_el0. Use stgenc_cntfid0 value instead of
	 * mrs x6, cntfrq_el0
	 */
	ldr	w6, .stgenc_cntfid0
	ldr	w6, [x6]
	mrs	x7, cntpct_el0
	add	x6, x7, x6, lsl #1

.L1:
	mrs	x7, cntpct_el0
	cmp	x6, x7
	bls	.L2

	mrs	x7, dbgclaimclr_el1
	tbz	x7, 0, .L1

	mov	x7, #1
	msr	dbgclaimclr_el1, x7

.L2:
	ldr	w6, fsbl_ptr

	add	w5, w5, #(BSEC_DENR_I - BSEC_DENR_NI)
	isb
	sev
	str	w5, [x4]

	br	x6

.L3:
	ldr	w6, fsbl_ptr
	isb
	wfe
	br	x6

.L4:
	ldr	w6, fsbl_ptr
	br	x6

	.align	2
.bsec_denr:
	.word	BSEC_DENR
.bsec_denr_ni:
	.word	BSEC_DENR_NI
.rifsc_rimc_cr:
	.word	RIFSC_RIMC_CR
.stgenc_cntfid0:
	.word	STGENC_CNTFID0
fsbl_ptr:
