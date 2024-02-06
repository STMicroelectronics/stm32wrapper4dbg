/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause */
/*
 * Copyright (c) 2019-2024, STMicroelectronics - All Rights Reserved
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

#define BIT(x)				(1UL << (x))

// compute SECDED ECC as HAMMING(17,12) with parity
#define PARITY_4BIT(x)			((((x) >> 3) ^ ((x) >> 2) ^ ((x) >> 1) ^ (x)) & 1)
#define PARITY_12BIT(x)			PARITY_4BIT(((x) >> 8) ^ ((x) >> 4) ^ (x))
#define BSEC_DENR_ECC(x)		(((PARITY_12BIT((x) & 0x800)) << 17) | \
					 ((PARITY_12BIT((x) & 0x7f0)) << 16) | \
					 ((PARITY_12BIT((x) & 0x78e)) << 15) | \
					 ((PARITY_12BIT((x) & 0x66d)) << 14) | \
					 ((PARITY_12BIT((x) & 0xd5b)) << 13) | \
					 ((PARITY_12BIT((x) & 0xcb7)) << 12))
#define BSEC_DENR_v(x)			(0xdeb00000 | BSEC_DENR_ECC(x) | ((x) & 0xfff))

#define BSEC_BASE			0x44000000

#define BSEC_DENR_OFFSET		0x00000e20
#define BSEC_DENR_I			BSEC_DENR_v(0x0fff)
#define BSEC_DENR_NI			BSEC_DENR_v(0x0fdf)

#define BSEC_DBGACR_OFFSET		0x00000eac
#define BSEC_DBGMCR_OFFSET		0x00000e8c
#define BSEC_DBGXCR_ENABLE		0xb4b4b400

#define BSEC_AP_UNLOCK_OFFSET		0x00000e90
#define BSEC_AP_UNLOCK_ENABLE		0x000000b4

#define RIFSC_RIMC_CR			0x42080c00
#define STGENC_CNTFID0			0x48080020

#define RCC_BASE			0x44200000
#define RCC_DBGCFGR_OFFSET		0x00000520
#define RCC_DBGCFGR_DBGMCUEN		BIT(10)

#define DBGMCU_BASE			0x440a0000
#define DBGMCU_DBG_AUTH_DEV_OFFSET	0x00000104

#define RIFSC_RIMC_CR_TDCID_SHIFT	4
#define RIFSC_RIMC_CR_TDCID_MASK	0x00000070
#define TDCID				1
#define MPIDR_CPUID_MASK		0x0000ffff

#define DELAY_SECONDS			2

#define DBG_CLAIM_0			BIT(0)

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
	*(volatile uint32_t *)(BSEC_BASE + BSEC_DENR_OFFSET) = v;
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

	if (!is_tdcid())
		goto finish;

	if (cpu_id()) {
		wait_for_event();
		goto finish;
	}

	denr_val = BSEC_DENR_NI;
	write_bsec_denr(denr_val);

	*(volatile uint32_t *)(BSEC_BASE + BSEC_DBGACR_OFFSET) = BSEC_DBGXCR_ENABLE;
	*(volatile uint32_t *)(BSEC_BASE + BSEC_DBGMCR_OFFSET) = BSEC_DBGXCR_ENABLE;
	*(volatile uint32_t *)(BSEC_BASE + BSEC_AP_UNLOCK_OFFSET) = BSEC_AP_UNLOCK_ENABLE;

	*(volatile uint32_t *)(RCC_BASE + RCC_DBGCFGR_OFFSET) |= RCC_DBGCFGR_DBGMCUEN;
	*(volatile uint32_t *)(DBGMCU_BASE + DBGMCU_DBG_AUTH_DEV_OFFSET) = 0;

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
	denr_val = BSEC_DENR_I;
	write_bsec_denr(denr_val);

	send_event();

finish:
	fsbl(a, b, c, d);
}

 - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - -
*/

#define BIT(x)				(1UL << (x))

/* compute SECDED ECC as HAMMING(17,12) with parity */
#define PARITY_4BIT(x)			((((x) >> 3) ^ ((x) >> 2) ^ ((x) >> 1) ^ (x)) & 1)
#define PARITY_12BIT(x)			PARITY_4BIT(((x) >> 8) ^ ((x) >> 4) ^ (x))
#define BSEC_DENR_ECC(x)		(((PARITY_12BIT((x) & 0x800)) << 17) | \
					 ((PARITY_12BIT((x) & 0x7f0)) << 16) | \
					 ((PARITY_12BIT((x) & 0x78e)) << 15) | \
					 ((PARITY_12BIT((x) & 0x66d)) << 14) | \
					 ((PARITY_12BIT((x) & 0xd5b)) << 13) | \
					 ((PARITY_12BIT((x) & 0xcb7)) << 12))
#define BSEC_DENR_v(x)			(0xdeb00000 | BSEC_DENR_ECC(x) | ((x) & 0xfff))

#define BSEC_BASE			0x44000000

#define BSEC_DENR_OFFSET		0x00000e20
#define BSEC_DENR_I			BSEC_DENR_v(0x0fff)
#define BSEC_DENR_NI			BSEC_DENR_v(0x0fdf)

#define BSEC_DBGACR_OFFSET		0x00000eac
#define BSEC_DBGMCR_OFFSET		0x00000e8c
#define BSEC_DBGXCR_ENABLE		0xb4b4b400

#define BSEC_AP_UNLOCK_OFFSET		0x00000e90
#define BSEC_AP_UNLOCK_ENABLE		0x000000b4

#define RIFSC_RIMC_CR			0x42080c00
#define STGENC_CNTFID0			0x48080020

#define RCC_BASE			0x44200000
#define RCC_DBGCFGR_OFFSET		0x00000520
#define RCC_DBGCFGR_DBGMCUEN		BIT(10)

#define DBGMCU_BASE			0x440a0000
#define DBGMCU_DBG_AUTH_DEV_OFFSET	0x00000104

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
	ldr	w8, fsbl_ptr

	ldr	w4, .rifsc_rimc_cr
	ldr	w4, [x4]
	and	w4, w4, #RIFSC_RIMC_CR_TDCID_MASK
	cmp	w4, #(TDCID << RIFSC_RIMC_CR_TDCID_SHIFT)
	bne	.L4

	mrs	x4, mpidr_el1
	tst	x4, #MPIDR_CPUID_MASK
	bne	.L3

	ldr	w4, .bsec_base
	ldr	w5, .bsec_denr_ni
	str	w5, [x4, BSEC_DENR_OFFSET]
	ldr	w5, .bsec_dbgxcr_enable
	str	w5, [x4, BSEC_DBGACR_OFFSET]
	str	w5, [x4, BSEC_DBGMCR_OFFSET]
	mov	w5, BSEC_AP_UNLOCK_ENABLE
	str	w5, [x4, BSEC_AP_UNLOCK_OFFSET]

	ldr	w6, .rcc_base
	ldr	w5, [x6, RCC_DBGCFGR_OFFSET]
	orr	w7, w5, RCC_DBGCFGR_DBGMCUEN
	str	w7, [x6, RCC_DBGCFGR_OFFSET]

	ldr	w7, .dbgmcu_base
	str	w7, [x7, DBGMCU_DBG_AUTH_DEV_OFFSET]

	str     w5, [x6, RCC_DBGCFGR_OFFSET]

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
	ldr	w5, .bsec_denr_i
	sev
	str	w5, [x4, BSEC_DENR_OFFSET]

	b	.L4

.L3:
	wfe
.L4:
	br	x8

	.align	2
.bsec_base:
	.word	BSEC_BASE
.bsec_denr_i:
	.word	BSEC_DENR_I
.bsec_denr_ni:
	.word	BSEC_DENR_NI
.bsec_dbgxcr_enable:
	.word	BSEC_DBGXCR_ENABLE
.rcc_base:
	.word	RCC_BASE
.dbgmcu_base:
	.word	DBGMCU_BASE
.rifsc_rimc_cr:
	.word	RIFSC_RIMC_CR
.stgenc_cntfid0:
	.word	STGENC_CNTFID0
fsbl_ptr:
