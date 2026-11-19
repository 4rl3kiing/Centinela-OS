OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

KERNEL_VMA = 0xffffffff80000000;
KERNEL_LMA = 0x00100000;

PHDRS
{
    text   PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data   PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = KERNEL_VMA;

    .text ALIGN(4K) : AT(KERNEL_LMA)
    {
        KEEP(*(.text._start))
        *(.text .text.*)
    } :text

    .rodata ALIGN(4K) : AT(ALIGN(LOADADDR(.text) + SIZEOF(.text), 4K))
    {
        KEEP(*(.limine_requests))
        *(.rodata .rodata.*)
    } :rodata

    .data ALIGN(4K) : AT(ALIGN(LOADADDR(.rodata) + SIZEOF(.rodata), 4K))
    {
        *(.data .data.*)
    } :data

    .bss ALIGN(4K) (NOLOAD) : AT(ALIGN(LOADADDR(.data) + SIZEOF(.data), 4K))
    {
        *(COMMON)
        *(.bss .bss.*)
    } :data

    /DISCARD/ :
    {
        *(.eh_frame .eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}
