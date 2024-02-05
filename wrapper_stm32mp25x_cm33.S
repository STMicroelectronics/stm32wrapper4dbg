/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause */
/*
 * Copyright (c) 2019-2024, STMicroelectronics - All Rights Reserved
 * Author: Antonio Borneo <antonio.borneo@foss.st.com>
 */

/*
 * The assembly code below has been obtained by manual editing the result
 * of compiling this C code fragment, with the command:
 *   arm-none-eabi-gcc -mcpu=cortex-m33 -Os -mthumb -S wrapper.c
 * Use this C code as reference to easily read the assembly and/or to
 * experiment changes to the assembly code.
 * Please keep aligned assembly and C code.
 *
 - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - -

#include <stdbool.h>
#include <stdint.h>

#define RESET_VECTOR_PC			0x0e080004
#define BSEC_DENR			0x44000e20
#define BSEC_DENR_I			0xdeb60fff
#define BSEC_DENR_NI			(BSEC_DENR_I - 0x00000400)
#define DBG_CLAIM_0			(1UL << 0)
#define DELAY_SECONDS			2
#define RIFSC_RIMC_CR			0x42080c00
#define RIFSC_RIMC_CR_TDCID_SHIFT	4
#define RIFSC_RIMC_CR_TDCID_MASK	0x00000070
#define TDCID				2

void __attribute__((noreturn)) (*fsbl)(int a, int b, int c, int d);

static bool is_tdcid(void)
{
	uint32_t rimc_cr, cid;

	rimc_cr = *(volatile uint32_t *)RIFSC_RIMC_CR;
	cid = (rimc_cr & RIFSC_RIMC_CR_TDCID_MASK) >> RIFSC_RIMC_CR_TDCID_SHIFT;
	return cid == TDCID;
}

static inline void write_bsec_denable(uint32_t v)
{
	*(volatile uint32_t *)BSEC_DENR = v;
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

void __attribute__((noreturn)) wrapper(int a, int b, int c, int dwrapper_stm32mp25x_cm33.S)
{
	uint32_t denable_val;
	uint32_t t0, t1, delay, deadline;
	int64_t dt64;
	int32_t dt;

	// set back the original reset vector
	*(volatile uint32_t *)RESET_VECTOR_PC = 1 | (uint32_t)&fsbl;

	if (!is_tdcid())
		goto finish;


	denable_val = BSEC_DENR_NI;
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
	denable_val += (BSEC_DENR_I - BSEC_DENR_NI);
	write_bsec_denable(denable_val);

finish:
	fsbl(a, b, c, d);
}

 - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - - %<- - - - -
*/
/*
 * Possible handshake with OpenOCD (A, B, C are any [2:0])
 * 1) wrapper set bit A in DBGMCU_CR, opens JTAG NI and waits.
 *    1.5) no debug connections, wrapper set back DBGMCU_CR to 0.
 * 2) OpenOCD connects and set bit B and, on halt also C.
 * 3) wrapper clears bit A and B, set bit C and opens JTAG I.
 * 4) OpenOCD set DBGMCU_CR to desired value (e.g. 0x07 or 0x17)
 */

#define BIT(x)				(1UL << (x))

#define CPU_FREQ_HZ			300000000
#define CM33_SYSTICK_FREQ_HZ		CPU_FREQ_HZ
#define CM33_SYSTICK_RELOADS_PER_S	32
#define CM33_SYSTICK_RELOAD_VALUE	((CM33_SYSTICK_FREQ_HZ) / (CM33_SYSTICK_RELOADS_PER_S))
#define DELAY_S				2

// must fit in 24 bits
#if CM33_SYSTICK_RELOAD_VALUE > 0x00ffffff
#error SYSTICK out of range, increase CM33_SYSTICK_RELOADS_PER_S
#endif

#define CM33_SYSTICK_BASE		0xe000e010
#define CM33_SYSTICK_CSR_OFFSET		0x000
#define CM33_SYSTICK_RVR_OFFSET		0x004
#define CM33_SYSTICK_CVR_OFFSET		0x008
#define CM33_SYSTICK_CSR_ENABLE		(BIT(2) | BIT(0))

#define CM33_FP_BASE			0xe0002000
#define CM33_FP_CTRL_OFFSET		0x000
#define CM33_FP_COMP_OFFSET(n)		(0x008 + 4 * (n))
#define CM33_FP_CTRL_ENABLE		(BIT(1) | BIT(0))
#define CM33_FP_COMP_ENABLE		BIT(0)

#define CM33_RESET_VECTOR		0x0e080000

#define BSEC_BASE			0x44000000
#define BSEC_SCRATCHR1_OFFSET		0xe04
#define BSEC_DENR_OFFSET		0xe20
#define BSEC_DENR_I			0xdeb60fff
//#define BSEC_DENR_NI			((BSEC_DENR_I) - BIT(5))
#define BSEC_DENR_NI			BSEC_DENR_I

// offset all bsec by 0xe00 for smaller code size
#define BSEC_VBASE			((BSEC_BASE) + 0xe00)
#define BSEC_SCRATCHR1_VOFFSET		((BSEC_SCRATCHR1_OFFSET) - 0xe00)
#define BSEC_DENR_VOFFSET		((BSEC_DENR_OFFSET) - 0xe00)

#define RCC_BASE			0x44200000
#define RCC_DBGCFGR_OFFSET		0x520
#define RCC_DBGCFGR_DBGEN		BIT(8)
#define RCC_DELAY_N			8	// (N >= 5)

#define DBGMCU_BASE			0x4a010000
#define DBGMCU_CR_OFFSET		0x004
#define DBGMCU_CR_VAL1			0x00000014
#define DBGMCU_CR_VAL2			0x00000011

#define TDCID				2

#define RIFSC_RIMC_BASE			0x42080000
#define RIFSC_RIMC_CR_OFFSET		0xc00
#define RIFSC_RIMC_CR_TDCID_SHIFT	4
#define RIFSC_RIMC_CR_TDCID_MASK	(7 << RIFSC_RIMC_CR_TDCID_SHIFT)
#define RIFSC_RIMC_CR_TDCID_VALUE	((TDCID) << RIFSC_RIMC_CR_TDCID_SHIFT)

// Bootfail red LED on PH4
#define LED_GPIO_BASE			0x442b0000
#define LED_GPIO_ODR_OFFSET		0x014
#define LED_GPIO_MASK			BIT(4)

#define r0_bsec_vbase			r0
#define r1_bsec_denr_val		r1
#define r2_dbgmcu_base			r2
#define r3_led_gpio_base		r3
#define r4_led_gpio_val			r4
/* scratch register r5, r6, r7. Avoid rx>r7 to use only "narrow" instructions */

	.cpu cortex-m33
	.text
	.align	1
	.global	_start
	.arch armv7-m
	.syntax unified
	.thumb
	.thumb_func

_start:
	/* skip wrapper if not TDCID */
	ldr	r5, .rifsc_rimc_cr
	ldr	r5, [r5]
	and	r5, r5, #RIFSC_RIMC_CR_TDCID_MASK
	cmp	r5, #RIFSC_RIMC_CR_TDCID_VALUE
	bne	.L_go_fsbl

	/* halt on first reset */
	ldr	r0_bsec_vbase, .bsec_vbase
	ldr	r5, [r0_bsec_vbase, BSEC_SCRATCHR1_VOFFSET]
	movs	r6, 1
	str	r6, [r0_bsec_vbase, BSEC_SCRATCHR1_VOFFSET]
	cmp	r5, 0
.L_first_reset:
	beq	.L_first_reset

	/* open debug early, as DBGSWEN is required to access DBGMCU */
	ldr	r1_bsec_denr_val, .bsec_denr_ni
	str	r1_bsec_denr_val, [r0_bsec_vbase, BSEC_DENR_VOFFSET]

	/* enable clk for DGBMCU */
	ldr	r5, .rcc_dbgcfgr
	movs	r6, RCC_DBGCFGR_DBGEN
	str	r6, [r5]
	ldr	r6, [r5]

	/* wait for clk enabled */
	movs	r5, RCC_DELAY_N
.L_delay_rcc:
	subs	r5, r5, 1
	bne	.L_delay_rcc

	/*
	 * Set on bit in DBGMCU_CR to inform debugger that wrapper is present.
	 * This also prevents CA35 to enter in standby.
	 */
	ldr	r2_dbgmcu_base, .dbgmcu_base
	movs	r5, DBGMCU_CR_VAL1
	str	r5, [r2_dbgmcu_base, DBGMCU_CR_OFFSET]

	/* Initialize systick */
	ldr	r5, .cm33_systick_base
	ldr	r6, .cm33_systick_reload
	str	r6, [r5, CM33_SYSTICK_RVR_OFFSET]
	movs	r6, CM33_SYSTICK_CSR_ENABLE
	str	r6, [r5, CM33_SYSTICK_CSR_OFFSET]
	str	r6, [r5, CM33_SYSTICK_CVR_OFFSET]	/* restart */

	/* read led value */
	ldr	r3_led_gpio_base, .led_gpio_base
	ldr	r4_led_gpio_val, [r3_led_gpio_base, LED_GPIO_ODR_OFFSET]

	/* wait loop */
	movs	r6, CM33_SYSTICK_RELOADS_PER_S * DELAY_S
.Loop_wait:
	ldr	r7, [r2_dbgmcu_base, DBGMCU_CR_OFFSET]
	lsls	r7, 31	/* put BIT(1) in carry, BIT(0) in sign */
	bcs	.L_debugger_detected
	ldr	r7, [r5, CM33_SYSTICK_CSR_OFFSET]
	lsls	r7, 15
	bpl	.Loop_wait

	/* led toggle */
	eor	r4_led_gpio_val, LED_GPIO_MASK
	str	r4_led_gpio_val, [r3_led_gpio_base, LED_GPIO_ODR_OFFSET]

	subs	r6, r6, 1
	bne	.Loop_wait
	b	.L_no_halt

.L_debugger_detected:
	bpl	.L_no_halt

	/* Set breakpoint */
	ldr	r5, .cm33_fp_base
	movs	r6, CM33_FP_CTRL_ENABLE
	str	r6, [r5, CM33_FP_CTRL_OFFSET]
	ldr	r6, fsbl_ptr
	orr	r6, r6, CM33_FP_COMP_ENABLE
	/* for test purpose: adr r6, .L_label + 1 */
	str	r6, [r5, CM33_FP_COMP_OFFSET(0)]

.L_no_halt:
	/* led off */
	orr	r4_led_gpio_val, LED_GPIO_MASK
	str	r4_led_gpio_val, [r3_led_gpio_base, LED_GPIO_ODR_OFFSET]

	/* final value in DBGMCU_CR */
	movs	r5, DBGMCU_CR_VAL2
	str	r5, [r2_dbgmcu_base, DBGMCU_CR_OFFSET]

	/* open debug */
	adds	r1_bsec_denr_val, r1_bsec_denr_val, #(BSEC_DENR_I - BSEC_DENR_NI)
	str	r1_bsec_denr_val, [r0_bsec_vbase, BSEC_DENR_VOFFSET]

.L_go_fsbl:
	/* Set reset vector back to fsbl as wrapper could be overwritten */
	ldr	r5, .cm33_reset_vector
	ldr	r6, fsbl_ptr
	str	r6, [r5, 4]

	/* At last, jump to fsbl */
	bx	r6

	.align	2
.bsec_vbase:
	.word	BSEC_VBASE
.bsec_denr_ni:
	.word	BSEC_DENR_NI
.cm33_systick_base:
	.word	CM33_SYSTICK_BASE
.cm33_systick_reload:
	.word	CM33_SYSTICK_RELOAD_VALUE
.led_gpio_base:
	.word	LED_GPIO_BASE
.cm33_reset_vector:
	.word	CM33_RESET_VECTOR
.rifsc_rimc_cr:
	.word	RIFSC_RIMC_BASE + RIFSC_RIMC_CR_OFFSET
.rcc_dbgcfgr:
	.word	RCC_BASE + RCC_DBGCFGR_OFFSET
.dbgmcu_base:
	.word	DBGMCU_BASE
.cm33_fp_base:
	.word	CM33_FP_BASE
fsbl_ptr:
