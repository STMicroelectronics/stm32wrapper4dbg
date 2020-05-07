# stm32wrapper4dbg

A tool that adds a debug wrapper to a stm32 fsbl image.

## Tool description

To handle secure boot, **STM32 MPU** prevents the debugger to halt
the system at reset vector.
This cause the debugger to halt each core at a random address, as
soon as it get access to the debug port.
Such random halt address is not optimal to debug the early boot
steps of either the *First-Stage Boot Loader* (fsbl)
(e.g. **TF-A**) or the *Second-Stage Boot Loader*
(e.g. **U-Boot**).

A common workaround consists by adding an infinite loop at the
entry of fsbl, so the debugger can attach, halt and skip the loop.
This has the drawback of requiring modification in the source code
of fsbl.

*stm32wrapper4dbg* adds a binary wrapper to an existing fsbl image
in *stm32 binary format* and generates a new wrapped stm32 image.
The wrapped image is intended to replace the existing fsbl image
flashed on **STM32 MPU** board during the debug activity.

The wrapper code is executed before the fsbl code and:

* enables the debug port (JTAG and SWD);
* waits at maximum two seconds for a debugger to attach and to
  toggle *debug claim* bit zero, then jumps to fsbl;
* if the debugger *has requested to halt*, then the boot will
  halt at the very first instruction of fsbl. If no debugger is
  detected or the debugger has not requested any halt, the fsbl
  is executed.

**ATTENTION:** on devices *closed* with OTP, the debug port is not
accessible, for obvious security reasons. A wrapped image created
with *stm32wrapper4dbg* will **open the debug port**. A wrapped
image must be signed with the user key to be used in the secured
boot. **Do not distribute the signed wrapped image** to prevent
its use to compromise the secure boot.

## Getting Started

### Prerequisite

The fsbl in *stm32 binary image* format must be available.

### Installing

Simply run:

```
make
```

then copy the file *stm32wrapper4dbg* and the man page file
*stm32wrapper4dbg.1*.

### Running stm32wrapper4dbg

Check the man page *stm32wrapper4dbg (1)* for syntax and examples.

## Contributing

See contributing.md for contribution guidelines to *stm32wrapper4dbg*.

## Maintainers

* Antonio Borneo <antonio.borneo@st.com>

## License

The tool *stm32wrapper4dbg* is dual-licensed under
*GPL-2.0-or-later* **OR** *BSD-3-Clause*.

You may use this work according to either of these licenses as is
most appropriate for your project on a case-by-case basis.
