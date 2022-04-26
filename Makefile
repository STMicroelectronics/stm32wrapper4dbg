# SPDX-License-Identifier: GPL-2.0-or-later OR BSD-3-Clause
# Copyright (c) 2019-2022, STMicroelectronics - All Rights Reserved

CROSS_COMPILE_ARM32 = arm-none-eabi-
CROSS_COMPILE_ARM64 = aarch64-linux-gnu-

# Without cross compiler, don't remove or rebuild it
xtool_32_missing := $(shell type -t $(CROSS_COMPILE_ARM32){gcc,objdump} > /dev/null; echo $$?)
xtool_64_missing := $(shell type -t $(CROSS_COMPILE_ARM64){gcc,objdump} > /dev/null; echo $$?)

# Without cross compiler, don't remove or rebuild it
ifeq ($(xtool_32_missing),0)
extra_dep := wrapper_stm32mp15x.inc
else
extra_dep :=
endif

ifeq ($(xtool_64_missing),0)
extra_dep += wrapper_stm32mp25x.inc
endif

stm32wrapper4dbg: stm32wrapper4dbg.c $(extra_dep)
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall $< -o $@

%.inc: %.bin
	echo '/* Generated automatically by Makefile */' > $@
	od -v -A n -t x1 $< | sed 's/ *\(..\) */0x\1,/g' >> $@

wrapper_stm32mp15x.bin: wrapper_stm32mp15x.elf
	$(CROSS_COMPILE_ARM32)objcopy -O binary $< $@

wrapper_stm32mp25x.bin: wrapper_stm32mp25x.elf
	$(CROSS_COMPILE_ARM64)objcopy -R .note.gnu.build-id -O binary $< $@

wrapper_stm32mp15x.elf: wrapper_stm32mp15x.S
	$(CROSS_COMPILE_ARM32)gcc -Wall -static -nostartfiles -mlittle-endian -Wa,-EL -Wl,-Ttext,0x2ffc2500 $< -o $@

wrapper_stm32mp25x.elf: wrapper_stm32mp25x.S
	$(CROSS_COMPILE_ARM64)gcc -Wall -static -nostartfiles -mlittle-endian -Wa,-EL -Wl,-Ttext,0x0e012000 $< -o $@

.PRECIOUS: %.bin %.elf

clean:
	rm -f stm32wrapper4dbg wrapper_stm32mp15x.bin wrapper_stm32mp15x.elf wrapper_stm32mp25x.bin wrapper_stm32mp25x.elf $(extra_dep)
