# SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause
# Copyright (c) 2019-2022, STMicroelectronics - All Rights Reserved

CROSS_COMPILE_ARM32 = arm-none-eabi-
CROSS_COMPILE_ARM64 = aarch64-linux-gnu-

# Without cross compiler, don't remove or rebuild it
xtool_32_missing := $(shell type -t $(CROSS_COMPILE_ARM32){gcc,objdump} > /dev/null; echo $$?)
xtool_64_missing := $(shell type -t $(CROSS_COMPILE_ARM64){gcc,objdump} > /dev/null; echo $$?)

# Without cross compiler, don't remove or rebuild it
ifeq ($(xtool_32_missing),0)
extra_dep := wrapper_stm32mp15x_ca7.inc wrapper_stm32mp25x_cm33.inc
else
extra_dep :=
endif

ifeq ($(xtool_64_missing),0)
extra_dep += wrapper_stm32mp21x_ca35.inc wrapper_stm32mp25x_ca35.inc
endif

stm32wrapper4dbg: stm32wrapper4dbg.c $(extra_dep)
	$(CC) -O2 $(CFLAGS) $(LDFLAGS) -Wall -Wextra $< -o $@

%.inc: %.bin
	echo '/* Generated automatically by Makefile */' > $@
	od -v -A n -t x1 $< | sed 's/ *\(..\) */0x\1,/g' >> $@

%_ca7.bin: %_ca7.elf
	$(CROSS_COMPILE_ARM32)objcopy -O binary $< $@

%_cm33.bin: %_cm33.elf
	$(CROSS_COMPILE_ARM32)objcopy -O binary $< $@

%_ca35.bin: %_ca35.elf
	$(CROSS_COMPILE_ARM64)objcopy -R .eh_frame -O binary $< $@

%_ca7.elf: %_ca7.S
	$(CROSS_COMPILE_ARM32)gcc -Wall -static -nostartfiles -mlittle-endian -Wa,-EL -Wl,-n -Wl,-Ttext,0x2ffc2500 $< -o $@

%_cm33.elf: %_cm33.S
	$(CROSS_COMPILE_ARM32)gcc -Wall -static -nostartfiles -mlittle-endian -Wa,-EL -Wl,-n -Wl,-Ttext,0x0e080000 $< -o $@

wrapper_stm32mp25x_cm33.s: wrapper_stm32mp25x_cm33.c
	$(CROSS_COMPILE_ARM32)gcc -Wall -Werror -Wstack-usage=0 -Os -g -fcall-used-r4 -fcall-used-r5 -ffixed-r7 -ffixed-r11 -ffixed-r14 -fconserve-stack -fomit-frame-pointer -mcpu=cortex-m33 -mthumb -S $< -o $@

wrapper_stm32mp25x_cm33.elf: wrapper_stm32mp25x_cm33.s add_symbol.S
	$(CROSS_COMPILE_ARM32)gcc -Wall -Werror -static -g -mcpu=cortex-m33 -mthumb -nostartfiles -Wl,-n -Wl,-Ttext,0x0e080000 -DASM_FILE=\"$<\" add_symbol.S -o $@

wrapper_stm32mp25x_ca35.s: wrapper_stm32mp25x_ca35.c
	$(CROSS_COMPILE_ARM64)gcc -Wall -Werror -Wstack-usage=0 -Os -g -fcall-used-x19 -fcall-used-x20 -fcall-used-x21 -fcall-used-x22 -fcall-used-x23 -fcall-used-x24 -fcall-used-x25 -fcall-used-x26 -fcall-used-x27 -fcall-used-x28 -fconserve-stack -fomit-frame-pointer -ffixed-x30 -mcpu=cortex-a35 -S $< -o $@

wrapper_stm32mp25x_ca35.elf: wrapper_stm32mp25x_ca35.s add_symbol.S
	$(CROSS_COMPILE_ARM64)gcc -Wall -Werror -static -g -mcpu=cortex-a35 -nostartfiles -Wl,-n -Wl,-Ttext,0x0e012000 -Wl,--build-id=none -DASM_FILE=\"$<\" add_symbol.S -o $@

%_ca35.elf: %_ca35.S
	$(CROSS_COMPILE_ARM64)gcc -Wall -static -nostartfiles -mlittle-endian -Wa,-EL -Wl,-n -Wl,-Ttext,0x0e012000 -Wl,--build-id=none $< -o $@

.PRECIOUS: %_ca7.bin %_ca35.bin %_cm33.bin %_ca7.elf %_ca35.elf %_cm33.elf

clean:
	rm -f stm32wrapper4dbg wrapper_stm32*.bin wrapper_stm32mp*.elf $(extra_dep)
