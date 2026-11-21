/* HOSTILE test image: one segment that is writable AND executable. */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

PHDRS
{
    all PT_LOAD FLAGS(7);
}

SECTIONS
{
    . = 0x400000;
    .text ALIGN(4K) : { KEEP(*(.text._start)) *(.text .text.*) *(.rodata .rodata.*) *(.data .data.*) *(.bss .bss.*) } :all
    /DISCARD/ : { *(.eh_frame .eh_frame_hdr) *(.comment) *(.note .note.*) }
}
