/* SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause */
/*
 * Copyright (c) 2019-2024, STMicroelectronics - All Rights Reserved
 * Author: Antonio Borneo <antonio.borneo@foss.st.com>
 */

/*
 * ARM: https://gcc.gnu.org/git/?p=gcc.git;a=blob;f=gcc/config/arm/aout.h
 *   arm-none-eabi-gcc -Os -fcall-used-r4 -fcall-used-r5 -ffixed-r7 -ffixed-r11 -ffixed-r14 -fconserve-stack -c x.c -Wstack-usage=0
 *   arm-none-eabi-gcc -Os -fcall-used-r4 -fcall-used-r5 -ffixed-r7 -ffixed-r11 -ffixed-r14 -fconserve-stack -fomit-frame-pointer -mcpu=cortex-m33 -mthumb -c x.c -Wstack-usage=0
 *   arm-none-eabi-objdump -d x.o
 *
 *   0, 1,  2, 3,  4, 5, 6, X,
 *   8, 9, 10, X, 12, X, X, X,
 *
 *   #define ARM_HARD_FRAME_POINTER_REGNUM   11
 *   #define THUMB_HARD_FRAME_POINTER_REGNUM  7
 *
 *   "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
 *   "r8", "r9", "r10", "fp", "ip", "sp", "lr", "pc",
 *
 * https://gcc.gnu.org/git/?p=gcc.git;a=blob;f=gcc/config/arm/arm.h
 * Register allocation in ARM Procedure Call Standard
 *  (S - saved over call, F - Frame-related).
 *
 *      r0         *    argument word/integer result
 *      r1-r3           argument word
 *
 *      r4-r8        S  register variable
 *      r9           S  (rfp) register variable (real frame pointer)
 *
 *      r10        F S  (sl) stack limit (used by -mapcs-stack-check)
 *      r11        F S  (fp) argument pointer
 *      r12             (ip) temp workspace
 *      r13        F S  (sp) lower end of current stack frame
 *      r14             (lr) link address/workspace
 *      r15        F    (pc) program counter
 *
 *
 * AARCH64: https://gcc.gnu.org/git/?p=gcc.git;a=blob;f=gcc/config/aarch64/aarch64.h
 *   aarch64-linux-gnu-gcc -Os -Wall -Wstack-usage=0 -mcpu=cortex-a35 -fcall-used-x19 -fcall-used-x20 -fcall-used-x21 -fcall-used-x22 -fcall-used-x23 -fcall-used-x24 -fcall-used-x25 \
 *      -fcall-used-x26 -fcall-used-x27 -fcall-used-x28 -fconserve-stack -fomit-frame-pointer -ffixed-x30 -c x.c
 *   aarch64-linux-gnu-objdump -d firmware-example.o
 *
 *   "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
 *   "x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
 *   "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
 *   "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp",
 *
 *    31 64-bit general purpose registers R0-R30:
 *    R30          LR (link register)
 *    R29          FP (frame pointer)
 *    R19-R28      Callee-saved registers
 *    R18          The platform register; use as temporary register.
 *    R17          IP1 The second intra-procedure-call temporary register
 *                 (can be used by call veneers and PLT code); otherwise use
 *                 as a temporary register
 *    R16          IP0 The first intra-procedure-call temporary register (can
 *                 be used by call veneers and PLT code); otherwise use as a
 *                 temporary register
 *    R9-R15       Temporary registers
 *    R8           Structure value parameter / temporary register
 *    R0-R7        Parameter/result registers
 *
 *    SP           stack pointer, encoded as X/R31 where permitted.
 *    ZR           zero register, encoded as X/R31 elsewhere
 *
 *    32 x 128-bit floating-point/vector registers
 *    V16-V31      Caller-saved (temporary) registers
 *    V8-V15       Callee-saved registers
 *    V0-V7        Parameter/result registers
 *
 *    The vector register V0 holds scalar B0, H0, S0 and D0 in its least
 *    significant bits.  Unlike AArch32 S1 is not packed into D0, etc.
 *
 *    P0-P7        Predicate low registers: valid in all predicate contexts
 *    P8-P15       Predicate high registers: used as scratch space
 *
 *    FFR          First Fault Register, a fixed-use SVE predicate register
 *    FFRT         FFR token: a fake register used for modelling dependencies
 *
 *    VG           Pseudo "vector granules" register
 *
 *    VG is the number of 64-bit elements in an SVE vector.  We define
 *    it as a hard register so that we can easily map it to the DWARF VG
 *    register.  GCC internally uses the poly_int variable aarch64_sve_vg
 *    instead.
 */

#include <stdint.h>

#define BIT(x)				(1UL << (x))

#define CPU_FREQ_HZ			300000000
#define CM33_SYST_FREQ_HZ		CPU_FREQ_HZ
#define CM33_SYST_RELOADS_PER_S	32
#define CM33_SYST_RELOAD_VALUE	((CM33_SYST_FREQ_HZ) / (CM33_SYST_RELOADS_PER_S))
#define DELAY_S				2
#define CM33_SYST_RELOADS		(DELAY_S * CM33_SYST_RELOADS_PER_S)

/* must fit in 24 bits */
#if CM33_SYST_RELOAD_VALUE > 0x00ffffff
#error SYST out of range, increase CM33_SYST_RELOADS_PER_S
#endif

#define CM33_RESET_VECTOR		0x0e080000
#define CM33_RESET_VECTOR_PC_OFFSET	0x004

#define CM33_SYST_BASE			0xe000e010
#define CM33_SYST_CSR_OFFSET		0x000
#define CM33_SYST_RVR_OFFSET		0x004
#define CM33_SYST_CVR_OFFSET		0x008
#define CM33_SYST_CSR_ENABLE		(BIT(2) | BIT(0))
#define CM33_SYST_CSR_CNTFLG_MASK	BIT(16)

#define CM33_FP_BASE			0xe0002000
#define CM33_FP_CTRL_OFFSET		0x000
#define CM33_FP_COMP_OFFSET(n)		(0x008 + 4 * (n))
#define CM33_FP_CTRL_ENABLE		(BIT(1) | BIT(0))
#define CM33_FP_COMP_ENABLE		BIT(0)

#define CM33_DHCSR_BASE			0xe000edf0
#define CM33_DHCSR_C_DEBUGEN		BIT(0)

#define BSEC_BASE			0x44000000
#define BSEC_SCRATCHR1_OFFSET		0xe04
#define BSEC_SCRATCHR1_VAL		1
#define BSEC_DENR_OFFSET		0xe20
#define BSEC_DENR_VAL			0xdeb60fff

#define RCC_BASE			0x44200000
#define RCC_DBGCFGR_OFFSET		0x520
#define RCC_DBGCFGR_DBGEN		BIT(8)
#define RCC_DELAY_N			16	/* (N >= 5) */

#define DBGMCU_BASE			0x4a010000
#define DBGMCU_CR_OFFSET		0x004
#define DBGMCU_CR_VAL1			0x00000014
#define DBGMCU_CR_VAL2			0x00000017

#define TDCID				2

#define RIFSC_RIMC_BASE			0x42080000
#define RIFSC_RIMC_CR_OFFSET		0xc00
#define RIFSC_RIMC_CR_TDCID_SHIFT	4
#define RIFSC_RIMC_CR_TDCID_MASK	(7 << RIFSC_RIMC_CR_TDCID_SHIFT)
#define RIFSC_RIMC_CR_TDCID_VALUE	((TDCID) << RIFSC_RIMC_CR_TDCID_SHIFT)

/* Bootfail red LED on PH4 */
#define LED_GPIO_BASE			0x442b0000
#define LED_GPIO_ODR_OFFSET		0x014
#define LED_GPIO_MASK			BIT(4)

static inline void write32(unsigned long addr, uint32_t val)
{
	volatile uint32_t *a = (uint32_t *)addr;

	*a = val;
}

static inline uint32_t read32(unsigned long addr)
{
	volatile uint32_t *a = (uint32_t *)addr;

	return *a;
}

static inline void setbits32(unsigned long addr, uint32_t val)
{
	volatile uint32_t *a = (uint32_t *)addr;

	*a = *a | val;
}

static inline void clrbits32(unsigned long addr, uint32_t val)
{
	volatile uint32_t *a = (uint32_t *)addr;

	*a = *a & ~val;
}

void _start(void) __attribute__ ((noreturn));
void _start(void)
{
#ifdef __GCC_HAVE_DWARF2_CFI_ASM
	asm(".cfi_undefined lr");
	asm(".cfi_undefined sp");
#endif

	uint32_t loc_fsbl_ptr;

	/* skip wrapper if not CM33-TD */
	uint32_t rifsc_rimc_cr = read32(RIFSC_RIMC_BASE + RIFSC_RIMC_CR_OFFSET);
	if ((rifsc_rimc_cr & RIFSC_RIMC_CR_TDCID_MASK) != RIFSC_RIMC_CR_TDCID_VALUE)
		goto wrapper_exit;

	/* halt on first reset, wait for second one */
	uint32_t double_boot = read32(BSEC_BASE + BSEC_SCRATCHR1_OFFSET);
	write32(BSEC_BASE + BSEC_SCRATCHR1_OFFSET, BSEC_SCRATCHR1_VAL);
	if (double_boot != BSEC_SCRATCHR1_VAL)
		while (1) {};

	/* open debug early, as DBGSWEN is required to access DBGMCU */
	write32(BSEC_BASE + BSEC_DENR_OFFSET, BSEC_DENR_VAL);

	setbits32(RCC_BASE + RCC_DBGCFGR_OFFSET, RCC_DBGCFGR_DBGEN);
	/*
	 * wait for clock enabled
	 * don't unroll, add dummy asm to prevent optimizations
	 */
	#pragma GCC unroll 1
	for (unsigned int i = RCC_DELAY_N; i; i--)
		asm("");

	/* Prevent CA35 to sleep and signal the debugger that there is a wrapper */
	write32(DBGMCU_BASE + DBGMCU_CR_OFFSET, DBGMCU_CR_VAL1);

	/* Initialize systick */
	write32(CM33_SYST_BASE + CM33_SYST_RVR_OFFSET, CM33_SYST_RELOAD_VALUE);
	write32(CM33_SYST_BASE + CM33_SYST_CSR_OFFSET, CM33_SYST_CSR_ENABLE);
	write32(CM33_SYST_BASE + CM33_SYST_CVR_OFFSET, CM33_SYST_CSR_ENABLE);

	/* wait for debugger or timeout, blinking the LED */
	uint32_t led = read32(LED_GPIO_BASE + LED_GPIO_ODR_OFFSET);
	for (unsigned int timeout = CM33_SYST_RELOADS; timeout; ) {
		if (read32(DBGMCU_BASE + DBGMCU_CR_OFFSET) != DBGMCU_CR_VAL1)
			break;

		if (read32(CM33_SYST_BASE + CM33_SYST_CSR_OFFSET) & CM33_SYST_CSR_CNTFLG_MASK) {
			led ^= LED_GPIO_MASK;
			write32(LED_GPIO_BASE + LED_GPIO_ODR_OFFSET, led);
			timeout--;
		}
	}

	/* LED off */
	write32(LED_GPIO_BASE + LED_GPIO_ODR_OFFSET, led | LED_GPIO_MASK);

	/* does debugger ask to halt? */
	if (read32(CM33_DHCSR_BASE) & CM33_DHCSR_C_DEBUGEN) {
		/* set HW breakpoint at FSBL-M */
		asm("ldr %0, fsbl_ptr" : "=r" (loc_fsbl_ptr));
		write32(CM33_FP_BASE + CM33_FP_CTRL_OFFSET, CM33_FP_CTRL_ENABLE);
		write32(CM33_FP_BASE + CM33_FP_COMP_OFFSET(0), loc_fsbl_ptr | CM33_FP_COMP_ENABLE);
	}

	/* final value in DBGMCU_CR */
	write32(DBGMCU_BASE + DBGMCU_CR_OFFSET, DBGMCU_CR_VAL2);

wrapper_exit:

	asm("ldr %0, fsbl_ptr" : "=r" (loc_fsbl_ptr));

	/* Set reset vector back to FSBL-M, as wrapper could be overwritten */
	write32(CM33_RESET_VECTOR + CM33_RESET_VECTOR_PC_OFFSET, loc_fsbl_ptr);

	/* at last, jump to FSBL-M */
	asm("bx %0" : : "r" (loc_fsbl_ptr));

	/* validate attribute noreturn */
	while (1) {};
}

// vi:nospell
