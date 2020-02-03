# SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause

CROSS_COMPILE = arm-none-eabi-

# Without cross compiler, don't remove or rebuild it
xtool_missing := $(shell type -t $(CROSS_COMPILE){gcc,objdump} > /dev/null; echo $$?)
# Without cross compiler, don't remove or rebuild it
ifeq ($(xtool_missing),0)
extra_dep := wrapper_stm32mp15x.inc
else
extra_dep :=
endif

stm32wrapper4dbg: stm32wrapper4dbg.c $(extra_dep)
	$(CC) $(CFLAGS) -Wall -O3 $< -o $@

%.inc: %.bin
	echo '/* Generated automatically by Makefile */' > $@
	od -v -A n -t x1 $< | sed 's/ *\(..\) */0x\1,/g' >> $@

%.bin: %.elf
	$(CROSS_COMPILE)objcopy -O binary $< $@

%.elf: %.S
	$(CROSS_COMPILE)gcc -Wall -static -nostartfiles -mlittle-endian -Wa,-EL -Wl,-Ttext,0x2ffc2500 $< -o $@

.PRECIOUS: %.bin %.elf

clean:
	rm -f stm32wrapper4dbg wrapper_stm32mp15x.bin wrapper_stm32mp15x.elf $(extra_dep)
