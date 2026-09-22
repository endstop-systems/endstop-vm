/* QEMU's `virt` machine puts RAM at 0x8000_0000 and enters at its start. */
ENTRY(_start)
MEMORY { RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 8M }
SECTIONS {
  .text : { *(.text.entry) *(.text .text.*) } > RAM
  .rodata : { *(.rodata .rodata.*) } > RAM
  .data : { *(.data .data.*) *(.sdata .sdata.*) } > RAM
  .bss : { __bss_start = .; *(.bss .bss.*) *(.sbss .sbss.*) *(COMMON); __bss_end = .; } > RAM
  . = ALIGN(16);
  __stack_bottom = .;
  . += 64K;
  __stack_top = .;
}
