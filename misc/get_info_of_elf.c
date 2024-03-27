#include <stdio.h>
#include <elf.h>

const char* get_elf_class_string(unsigned char elf_class) {
    switch (elf_class) {
        case ELFCLASS32: return "32-bit";
        case ELFCLASS64: return "64-bit";
        default: return "Unknown class";
    }
}

const char* get_elf_osabi_string(unsigned char osabi) {
    switch (osabi) {
        case ELFOSABI_SYSV: return "UNIX System V";
        case ELFOSABI_HPUX: return "HP-UX";
        case ELFOSABI_NETBSD: return "NetBSD";
        case ELFOSABI_LINUX: return "Linux";
        case ELFOSABI_SOLARIS: return "Sun Solaris";
        case ELFOSABI_AIX: return "AIX";
        case ELFOSABI_IRIX: return "IRIX";
        case ELFOSABI_FREEBSD: return "FreeBSD";
        case ELFOSABI_TRU64: return "Compaq TRU64 UNIX";
        case ELFOSABI_MODESTO: return "Novell Modesto";
        case ELFOSABI_OPENBSD: return "OpenBSD";
        case ELFOSABI_ARM_AEABI: return "ARM EABI";
        case ELFOSABI_ARM: return "ARM";
        case ELFOSABI_STANDALONE: return "Standalone (embedded) application";
        default: return "Unknown OS/ABI";
    }
}

const char* get_elf_type_string(uint16_t type) {
    switch (type) {
        case ET_NONE: return "No file type";
        case ET_REL: return "Relocatable file";
        case ET_EXEC: return "Executable file";
        case ET_DYN: return "Shared object file";
        case ET_CORE: return "Core file";
        default: return "Unknown file type";
    }
}

const char* get_elf_machine_string(uint16_t machine) {
    switch (machine) {
        case EM_NONE: return "No machine";
        case EM_M32: return "AT&T WE 32100";
        case EM_SPARC: return "Sun SPARC";
        case EM_386: return "Intel 80386";
        case EM_68K: return "Motorola 68000";
        case EM_88K: return "Motorola 88000";
        case EM_860: return "Intel 80860";
        case EM_MIPS: return "MIPS RS3000";
        case EM_ARM: return "ARM";
        case EM_X86_64: return "AMD x86-64";
        default: return "Unknown machine";
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("请提供一个ELF文件作为参数。\n");
        return 1;
    }

    const char *filename = argv[1];
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("无法打开文件 %s。\n", filename);
        return 1;
    }
    
    Elf64_Ehdr header;
    fread(&header, sizeof(header), 1, file);
    fclose(file);
    
	printf("Class: %s\n", get_elf_class_string(header.e_ident[EI_CLASS]));
    printf("OS/ABI: %s\n", get_elf_osabi_string(header.e_ident[EI_OSABI]));
    printf("Type: %s\n", get_elf_type_string(header.e_type));
    printf("Machine: %s\n", get_elf_machine_string(header.e_machine));

    return 0;
}