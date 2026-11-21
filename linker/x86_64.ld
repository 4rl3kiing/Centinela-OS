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
    /* Limine chooses the physical load address; the kernel obtains it from
       the executable-address response. Only virtual bounds are exported. */
    __kernel_virt_start = KERNEL_VMA;
    . = KERNEL_VMA;

    .text ALIGN(4K) : AT(KERNEL_LMA)
    {
        KEEP(*(.text._start))
        *(.text .text.*)
    } :text

    /* Limine writes request responses before entry; afterwards the kernel only
       reads them, so keeping them in the read-only segment blocks tampering. */
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

    __kernel_virt_end = ADDR(.bss) + SIZEOF(.bss);

    /DISCARD/ :
    {
        *(.eh_frame .eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}
