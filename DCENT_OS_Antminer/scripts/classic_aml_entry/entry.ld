/* Standalone go application: reviewed host artifact, no automatic entry script. */
ENTRY(_start)
SECTIONS {
  . = 0x07800000;
  .text : { KEEP(*(.entry)) *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .bss (NOLOAD) : { *(.bss*) *(COMMON) }
  /DISCARD/ : { *(.comment*) *(.note*) *(.eh_frame*) }
  ASSERT(SIZEOF(.bss) == 0, "standalone entry must initialize all storage explicitly")
  ASSERT(. <= 0x07810000, "entry exceeds reserved 64KiB image span")
}
