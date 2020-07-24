/* Entry Point */
ENTRY(__reset_irq)

MEMORY
{
    RAM (xrw)     : ORIGIN = 0x20000000, LENGTH = 256K
    FLASH (rx)     : ORIGIN = 0x00000000, LENGTH = 800K /* this will only work in qemu */
}

_estack = ORIGIN(RAM) + LENGTH(RAM);
_stack_reserve = 16k;

/* Define output sections */
SECTIONS
{
  /* ISR vector table */
  .vectortable :
  {
    KEEP(*(.vectortable.isr))
    . = ALIGN(4);
  } >FLASH

  /* Code */
  .text :
  {
    . = ALIGN(4);
    *(.startup)
    *(.text)
    *(.text*)
    *(.glue_7)
    *(.glue_7t)
    *(.eh_frame)

    KEEP (*(.init))
    KEEP (*(.fini))

    . = ALIGN(4);
    _etext = .;
  } >FLASH

  /* read-only data */
  .rodata :
  {
    . = ALIGN(4);
    *(.rodata)
    *(.rodata*)
    . = ALIGN(4);
  } >FLASH

  /* arm stuff */
  .ARM.extab   :
  {
    *(.ARM.extab* .gnu.linkonce.armextab.*)
  } >FLASH
  .ARM :
  {
    __exidx_start = .;
    *(.ARM.exidx*)
    __exidx_end = .;
  } >FLASH

  /* initialization stuff */
  .preinit_array     :
  {
    . = ALIGN(4);
    PROVIDE_HIDDEN (__preinit_array_start = .);
    KEEP (*(.preinit_array*))
    PROVIDE_HIDDEN (__preinit_array_end = .);
  } >FLASH
  .init_array :
  {
    PROVIDE_HIDDEN (__init_array_start = .);
    KEEP (*(SORT(.init_array.*)))
    KEEP (*(.init_array*))
    PROVIDE_HIDDEN (__init_array_end = .);
  } >FLASH

  /* data (copied to memory on startup) */
  _sidata = LOADADDR(.data);
  .data : 
  {
    . = ALIGN(4);
    _sdata = .;
    *(.data)
    *(.data*)
    *(.datatext)
    . = ALIGN(4);
    _edata = .;
  } >RAM AT >FLASH

  /* data (zeroed on startup) */
  . = ALIGN(4);
  .bss :
  {
    _sbss = .;
    __bss_start__ = _sbss;
    *(.bss)
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
    __bss_end__ = _ebss;
  } >RAM

  /* program heap for all allocations */
  __heap_start__ = .;
  __heap_end__ = __heap_start__ + (LENGTH(RAM) - (__heap_start__ - ORIGIN(RAM) + _stack_reserve));

  /* shrug */
  .ARM.attributes 0 :
  {
    *(.ARM.attributes)
  }
}