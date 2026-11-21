OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

KERNEL_VMA = 0xffffffff80000000;
KERNEL_LMA = 0x00100000;

PHDRS
{
    text    PT_LOAD FLAGS(5);
    rodata  PT_LOAD FLAGS(4);
    data    PT_LOAD FLAGS(6);
    dynamic PT_DYNAMIC FLAGS(6);
}

SECTIONS
{
    /* Limine chooses the physical load address; the kernel obtains it from
       the executable-address response. Only virtual bounds are exported. */
    . = KERNEL_VMA;

    .text ALIGN(4K) : AT(KERNEL_LMA)
    {
        /* Section-relative (not absolute) so it is relocated under KASLR. */
        __kernel_virt_start = .;
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

    /* Relocation tables Limine applies when it randomizes the base (KASLR). */
    .rela.dyn : { *(.rela.dyn) *(.rela.*) } :rodata
    .dynsym : { *(.dynsym) } :rodata
    .dynstr : { *(.dynstr) } :rodata
    .gnu.hash : { *(.gnu.hash) } :rodata
    .hash : { *(.hash) } :rodata

    .data ALIGN(4K) : AT(ALIGN(LOADADDR(.hash) + SIZEOF(.hash), 4K))
    {
        *(.data .data.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.got .got.*)
    } :data

    .dynamic : AT(LOADADDR(.data) + SIZEOF(.data))
    {
        *(.dynamic)
    } :data :dynamic

    .bss ALIGN(4K) (NOLOAD) : AT(ALIGN(LOADADDR(.dynamic) + SIZEOF(.dynamic), 4K))
    {
        *(COMMON)
        *(.bss .bss.*)
        __kernel_virt_end = .;
    } :data


    /DISCARD/ :
    {
        *(.eh_frame .eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
    }
}
