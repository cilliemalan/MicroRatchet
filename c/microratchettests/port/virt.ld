/* Entry Point */
ENTRY(Reset_Handler)



MEMORY
{
RAM (xrw)     : ORIGIN = 0x40000000, LENGTH = 128M
FLASH (rx)    : ORIGIN = 0x00000000, LENGTH = 64M
}

_estack = ORIGIN(RAM) + LENGTH(RAM);

/* Define output sections */
SECTIONS
{
  .text :
  {
    . = 0x1000;         /* boot code jumps here */
    _stext = .;
    *(.startup)
    *(.startup*)
    *(.text)           /* .text sections (code) */
    *(.text*)          /* .text* sections (code) */
    *(.eh_frame)

    KEEP (*(.init))
    KEEP (*(.fini))

    _etext = .;

  } >FLASH

  .rodata :
  {
    . = ALIGN(4);
    *(.rodata)         /* .rodata sections (constants, strings, etc.) */
    *(.rodata*)        /* .rodata* sections (constants, strings, etc.) */
    . = ALIGN(4);
  } >FLASH

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

  .preinit_array     :
  {
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
  .fini_array :
  {
    PROVIDE_HIDDEN (__fini_array_start = .);
    KEEP (*(SORT(.fini_array.*)))
    KEEP (*(.fini_array*))
    PROVIDE_HIDDEN (__fini_array_end = .);
  } >FLASH

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

  . = ALIGN(4);
  .bss :
  {
    _sbss = .;
    __bss_start__ = _sbss;
    KEEP(*(.bss))
    *(.bss*)
    *(COMMON)

    . = ALIGN(4);
    _ebss = .;
    __bss_end__ = _ebss;
    
    . = ALIGN(4);
  } >RAM

  /DISCARD/ :
  {
    libc.a ( * )
    libm.a ( * )
    libgcc.a ( * )
  }

  .ARM.attributes 0 :
  {
    *(.ARM.attributes)
  }
}