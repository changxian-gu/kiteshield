#include <string.h>

#include "packer/include/elfutils.h"

void parse_mapped_elf(
        void *start,
        size_t size,
        struct mapped_elf *elf) {

    /**
     * 构建elf映射
     * start是申请空间的头地址
     */
    elf->start = start;
    /**
     * size是源elf的文件大小
     */
    elf->size = size;
    /**
     * elf的头是申请空间的起始地址
     */
    elf->ehdr = (Elf64_Ehdr *) start;
    /**
     * elf program header table 的地址等于elf的头地址加program的偏移量
     */
    elf->phdr_tbl = (Elf64_Phdr *) (elf->start + elf->ehdr->e_phoff);
    if (elf->ehdr->e_shoff == 0)
        elf->shdr_tbl = NULL;
    else
        elf->shdr_tbl = (Elf64_Shdr *) (elf->start + elf->ehdr->e_shoff);

    /* elf_get_sec_by_name only depends on shstrtab being set */
    /**
     * e_shstrndx Section header string table index
     * 在ELF文件中，会用到很多字符串，比如节名
     * ELF中引用字符串只需要给出一个数组下标即可
     * 常见的节名为”.strtab”或”.shstrtab”。这两个字符串表分别为字符串表(String Table)
     * 和节表字符串表(Header String Table)，字符串表保存的是普通的字符串，
     * 而节表字符串表用来保存节表中用到的字符串，比如节名。
     */
    if (elf->ehdr->e_shstrndx == 0)
        elf->shstrtab = NULL;
    else
        /**
         * 获取shstrtab section_table[]
         * */
        elf->shstrtab = elf->shdr_tbl + elf->ehdr->e_shstrndx;

    elf->strtab = elf_get_sec_by_name(elf, ".strtab");
    /**
     * extern 表示定义的函数和全局变量可以被其它模块引用。如果不写extern，默认就是extern。
     * static 表示定义的符号和变量只能被本模块引用。
     * symtab 记录的是符号严格来说有两种。
     * 全局符号，某模块定义以后除了自己外，其他所有模块也可以引用。
     * 本地符号，只能本地引用
     */
    elf->symtab = elf_get_sec_by_name(elf, ".symtab");
    elf->text = elf_get_sec_by_name(elf, ".text");



    // int text_idx = get_section_idx(elf, ".text");
    // // 计算.text中函数的数量
    // Elf64_Sym* p_sym = NULL;
    // int nfunc_in_text = 0;
    // for (p_sym = (Elf64_Sym *)elf->symtab->sh_offset; p_sym < elf->symtab->sh_offset + elf->symtab->sh_size; p_sym++) {
    //     if (p_sym->st_shndx == text_idx)
    //         nfunc_in_text++;
    // }
    // // 在内存中多分配.text大小?不行，万一函数长度还没对齐长度长呢，那就完了
    // // des 要求8bytes
    // int align_need = 8;
    // // 多分配.text 中函数个数 * 对齐大小的空间
    // int size_added = nfunc_in_text * align_need;
    // int new_elf_size = size + size_added;
    // void* new_start = malloc(new_elf_size * sizeof(char));
    // memcpy(new_start, start, new_elf_size);
    // // 建立一些基本的映射
    // struct mapped_elf new_elf;
    // new_elf.size = new_elf_size
    // new_elf.start = new_start;
    // new_elf.ehdr = (Elf64_Ehdr*) new_start;
    // new_new_elf->phdr_tbl = (Elf64_Phdr*) (new_elf->start + new_elf->ehdr->e_phoff);
    // if (new_elf->ehdr->e_shoff == 0)
    //     new_elf->shdr_tbl = NULL;
    // else
    //     new_elf->shdr_tbl = (Elf64_Shdr*) (new_elf->start + new_elf->ehdr->e_shoff);

    // if (new_elf->ehdr->e_shstrndx == 0)
    //     new_elf->shstrtab = NULL;
    // else
    //     new_elf->shstrtab = new_elf->shdr_tbl + new_elf->ehdr->e_shstrndx;

    // new_elf->strtab = elf_get_sec_by_name(new_elf, ".strtab");
    // new_elf->symtab = elf_get_sec_by_name(new_elf, ".symtab");
    // new_elf->text = elf_get_sec_by_name(new_elf, ".text");

    // // 获得text section 的首地址
    // size_t text_section_start = new_elf->text->sh_addr;
    // // 获得text section 的长度
    // size_t text_section_size = new_elf->text->sh_size;
    // // 获得text section 后一个section的首地址
    // size_t section_nextto_text = text_section_start + text_section_size;
    // // 把.text 后的section全部后移size_added
    // memcpy(section_nextto_text + size_added, section_nextto_text, size - section_nextto_text);
    // // 把新增的这块内存全部设置为 0x90 , 即 nop
    // memset(section_nextto_text, 0x90, size_added);
    
    // // 接下来修改.text内部的函数
    // char* mem_tmp = malloc((text_section_size + size_added) * sizeof(char));
    // char* p = mem_tmp;
    // // 为每个函数添加align_need大小的空间
    // for (p_sym = (Elf64_Sym *)new_elf->symtab->sh_offset; p_sym < new_elf->symtab->sh_offset + new_elf->symtab->sh_size; p_sym++) {
    //     if (p_sym->st_shndx == text_idx) {
    //         // 获取每一个symbol的地址和大小
    //         Elf64_Addr sym_val = p_sym->st_value;
    //         Elf64_Xword sym_size = p_sym->st_size;
    //         if (sym_val == 0)
    //             continue;
    //         else {
    //             memcpy(p, sym_val, sym_size);
    //             p_sym->st_value = p;
    //             p += sym_size + align_need;
    //         }
    //     }
    // }
    // memcpy(text_section_start, mem_tmp, text_section_size + size_added);
    // // 修改section header table
    
}

// size_t get_section_idx(
//         const struct mapped_elf *elf,
//         const char *name) {
//     /**
//      * 从section header开始依次比较与name是否相同
//      */
//     Elf64_Shdr *curr_shdr = elf->shdr_tbl;
//     int i = 0;
//     for (i = 0; i < elf->ehdr->e_shnum; i++) {
//         if (curr_shdr->sh_type != SHT_NULL &&
//             strcmp(elf_get_sec_name(elf, curr_shdr), name) == 0)
//             return i;
//         curr_shdr++;
//     }

//     return -1;
// }

const Elf64_Shdr *elf_get_sec_by_name(
        const struct mapped_elf *elf,
        const char *name) {
    /**
     * 从section header开始依次比较与name是否相同
     */
    Elf64_Shdr *curr_shdr = elf->shdr_tbl;

    for (int i = 0; i < elf->ehdr->e_shnum; i++) {
        if (curr_shdr->sh_type != SHT_NULL &&
            strcmp(elf_get_sec_name(elf, curr_shdr), name) == 0)
            return curr_shdr;

        curr_shdr++;
    }

    return NULL;
}

const char *elf_get_sec_name(
        const struct mapped_elf *elf,
        const Elf64_Shdr *shdr) {
    if (elf->shstrtab == NULL)
        return NULL;
    /**
     * elf->start + elf->shstrtab->sh_offset 取到shstrtab
     * + sh_name 下标取值
     */
    return (const char *) (elf->start + elf->shstrtab->sh_offset + shdr->sh_name);
}

uint8_t *elf_get_sym_location(
        const struct mapped_elf *elf,
        const Elf64_Sym *sym) {
    for (int i = 0; i < elf->ehdr->e_phnum; i++) {
        Elf64_Phdr *curr_phdr = elf->phdr_tbl + i;

        if (curr_phdr->p_type != PT_LOAD)
            continue;

        if (curr_phdr->p_vaddr <= sym->st_value &&
            (curr_phdr->p_vaddr + curr_phdr->p_memsz) > sym->st_value) {
            return (void *) (elf->start + (curr_phdr->p_offset +
                                           (sym->st_value - curr_phdr->p_vaddr)));
        }
    }

    return NULL;
}

int elf_sym_in_text(
        const struct mapped_elf *elf,
        const Elf64_Sym *sym) {
    return elf->text->sh_addr <= sym->st_value &&
           (elf->text->sh_addr + elf->text->sh_size) > sym->st_value;
}

const char *elf_get_sym_name(
        const struct mapped_elf *elf,
        const Elf64_Sym *sym) {
    return (const char *) (elf->start + elf->strtab->sh_offset + sym->st_name);
}
