/* Centinela-OS user image: separate R-X, R and RW segments (W^X). */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data   PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0x400000;
    .text ALIGN(4K) : { KEEP(*(.text._start)) *(.text .text.*) } :text
    .rodata ALIGN(4K) : { *(.rodata .rodata.*) } :rodata
    .data ALIGN(4K) : { *(.data .data.*) } :data
    .bss ALIGN(4K) : { *(.bss .bss.*) *(COMMON) } :data
    /DISCARD/ : { *(.eh_frame .eh_frame_hdr) *(.comment) *(.note .note.*) }
}
