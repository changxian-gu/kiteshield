#include <elf.h>

#include "common/include/defs.h"
#include "cipher/aes.h"
#include "cipher/des.h"
#include "cipher/des3.h"
#include "cipher/rc4.h"
#include "cipher_modes/ecb.h"
#include "common/include/obfuscation.h"

#include "loader/include/types.h"
#include "loader/include/debug.h"
#include "loader/include/elf_auxv.h"
#include "loader/include/syscalls.h"
#include "loader/include/anti_debug.h"
#include "loader/include/string.h"

#include "compression/lzma/Lzma.h"
// zstd解压的单文件实现，直接包含较为简单(待修正)
#include "compression/zstd/zstddeclib.c"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGE_MASK (~0 << PAGE_SHIFT)

#define PAGE_ALIGN_DOWN(ptr) ((ptr) & PAGE_MASK)
#define PAGE_ALIGN_UP(ptr) ((((ptr) - 1) & PAGE_MASK) + PAGE_SIZE)
#define PAGE_OFFSET(ptr) ((ptr) & ~(PAGE_MASK))

enum Encryption {
    RC4 = 1,
    DES,
    TDEA,
    AES
};
enum Compression {
    LZMA = 1,
    LZO,
    UCL,
    ZSTD
};

// 串口
// typedef struct termios termios_t;
// typedef struct serial_data {
//     unsigned char databuf[132];//发送/接受数据
//     int serfd;//串口文件描述符
// } ser_Data;

// int serial_communication() {
//     /**
//      * extern void *malloc (size_t __size) __THROW __attribute_malloc__
//      */
//     termios_t *ter_s = ks_malloc(sizeof(ter_s));
//     int serport1fd = sys_open("/dev/ttyUSB0", O_RDWR | O_NOCTTY | O_NDELAY, 0777);

//     return serport1fd;
// }


// 编译的时候存的key其实还没有初始化，在packer里面用混淆后的key覆盖了
// .text段是64位对齐的，key存储的位置偏移是b0，.text段会自动对齐到c0（key的长度小于等于16字节）, 100(如果key的长度大于16字节)
struct key_placeholder obfuscated_key  __attribute__((aligned(1), section(".key")));

// struct aes_key obfuscated_key __attribute__((aligned(1), section(".key")));


static void *map_load_section_from_mem(void *elf_start, Elf64_Phdr phdr) {
    uint64_t base_addr = ((Elf64_Ehdr *) elf_start)->e_type == ET_DYN ?
                         DYN_PROG_BASE_ADDR : 0;

    /* Same rounding logic as in map_load_section_from_fd, see comment below.
     * Note that we don't need a separate mmap here for bss if memsz > filesz
     * as we map an anonymous region and copy into it rather than mapping from
     * an fd (ie. we can just not touch the remaining space and it will be full
     * of zeros by default).
     */
    // 存在疑问：为什么申请的长度这么长?
    void *addr = sys_mmap((void *) (base_addr + PAGE_ALIGN_DOWN(phdr.p_vaddr)),
                          phdr.p_memsz + PAGE_OFFSET(phdr.p_vaddr),
                          PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    DIE_IF((long) addr < 0, "mmap failure");
    DEBUG_FMT("mapping LOAD section from packed binary at %p", addr);

    /* Copy data from the packed binary */
    char *curr_addr = addr;
    for (Elf64_Off f_off = PAGE_ALIGN_DOWN(phdr.p_offset);
         f_off < phdr.p_offset + phdr.p_filesz;
         f_off++) {
        (*curr_addr++) = *((char *) elf_start + f_off);
    }

    /* Set correct permissions (change from -w-) */
    int prot = (phdr.p_flags & PF_R ? PROT_READ : 0) |
               (phdr.p_flags & PF_W ? PROT_WRITE : 0) |
               (phdr.p_flags & PF_X ? PROT_EXEC : 0);
    DIE_IF(
            sys_mprotect(addr, phdr.p_memsz + PAGE_OFFSET(phdr.p_vaddr), prot) < 0,
            "mprotect error");
    return addr;
}

static void *map_load_section_from_fd(int fd, Elf64_Phdr phdr, int absolute) {
    int prot = 0;
    if (phdr.p_flags & PF_R)
        prot |= PROT_READ;
    if (phdr.p_flags & PF_W)
        prot |= PROT_WRITE;
    if (phdr.p_flags & PF_X)
        prot |= PROT_EXEC;

    uint64_t base_addr = absolute ? 0 : DYN_INTERP_BASE_ADDR;

    /* mmap requires that the addr and offset fields are multiples of the page
     * size. Since that may not be the case for the p_vaddr and p_offset fields
     * in an ELF binary, we have to do some math to ensure the passed in
     * address/offset are multiples of the page size.
     *
     * To calculate the load address, we start at the interpreter base address
     * (which is a multiple of the page size itself), and add p_vaddr rounded
     * down to the nearest page size multiple. We round down the offset parameter
     * to the nearest page size multiple in the same way. Since both the offset
     * and virtual address are guaranteed to be congruent modulo the page size
     * (as per the ELF standard), this will result in them both being rounded
     * down by the same amount, and the produced mapping will be correct.
     */
    void *addr = sys_mmap((void *) (base_addr + PAGE_ALIGN_DOWN(phdr.p_vaddr)),
                          phdr.p_filesz + PAGE_OFFSET(phdr.p_vaddr),
                          prot,
                          MAP_PRIVATE | MAP_FIXED,
                          fd,
                          PAGE_ALIGN_DOWN(phdr.p_offset));
    DIE_IF((long) addr < 0,
           "mmap failure while mapping load section from fd");

    /* If p_memsz > p_filesz, the remaining space must be filled with zeros
     * (Usually the .bss section), map extra anon pages if this is the case. */
    if (phdr.p_memsz > phdr.p_filesz) {
        /* Unless the segment mapped above falls perfectly on a page boundary,
         * we've mapped some .bss already by virtue of the fact that mmap will
         * round the size of our mapping up to a page boundary. Subtract that
         * already mapped bss from the extra space we have to allocate */

        /* Page size minus amount of space occupied in the last page of the above
         * mapping by the file */
        size_t bss_already_mapped =
                PAGE_SIZE - PAGE_OFFSET(phdr.p_vaddr + phdr.p_filesz);
        void *extra_pages_start =
                (void *) PAGE_ALIGN_UP(base_addr + phdr.p_vaddr + phdr.p_filesz);

        if (bss_already_mapped < (phdr.p_memsz - phdr.p_filesz)) {
            size_t extra_space_needed =
                    (size_t) (phdr.p_memsz - phdr.p_filesz) - bss_already_mapped;

            void *extra_space = sys_mmap(extra_pages_start,
                                         extra_space_needed,
                                         prot,
                                         MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                                         -1, 0);

            DIE_IF((long) extra_space < 0,
                   "mmap failure while mapping extra space for static vars");

            DEBUG_FMT("mapped extra space for static data (.bss) at %p len %u",
                      extra_space, extra_space_needed);
        }

        /* While any extra pages mapped will be zeroed by default, this is not the
         * case for the part of the original page corresponding to
         * bss_already_mapped (it will contain junk from the file) so we zero it
         * here.  */
        uint8_t *bss_ptr = (uint8_t *) (base_addr + phdr.p_vaddr + phdr.p_filesz);
        if (!(prot & PROT_WRITE)) {
            DIE_IF(
                    sys_mprotect(bss_ptr, bss_already_mapped, PROT_WRITE) < 0,
                    "mprotect error");
        }

        for (size_t i = 0; i < bss_already_mapped; i++)
            *(bss_ptr + i) = 0;

        if (!(prot & PROT_WRITE)) {
            DIE_IF(
                    sys_mprotect(bss_ptr, bss_already_mapped, prot) < 0,
                    "mprotect error");
        }
    }

    DEBUG_FMT("mapped LOAD section from fd at %p", addr);
    return addr;
}

static void map_interp(void *path, void **entry, void **interp_base) {
    DEBUG_FMT("mapping INTERP ELF at path %s", path);
    int interp_fd = sys_open(path, O_RDONLY, 0);
    DIE_IF(interp_fd < 0, "could not open interpreter binary");

    Elf64_Ehdr ehdr;
    DIE_IF(sys_read(interp_fd, &ehdr, sizeof(ehdr)) < 0,
           "read failure while reading interpreter binary header");

    *entry = ehdr.e_type == ET_EXEC ?
             (void *) ehdr.e_entry : (void *) (DYN_INTERP_BASE_ADDR + ehdr.e_entry);
    int base_addr_set = 0;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr curr_phdr;

        off_t lseek_res = sys_lseek(interp_fd,
                                    ehdr.e_phoff + i * sizeof(Elf64_Phdr),
                                    SEEK_SET);
        DIE_IF(lseek_res < 0, "lseek failure while mapping interpreter");

        size_t read_res = sys_read(interp_fd, &curr_phdr, sizeof(curr_phdr));
        DIE_IF(read_res < 0, "read failure while mapping interpreter");

        /* We shouldn't be dealing with any non PT_LOAD segments here */
        if (curr_phdr.p_type != PT_LOAD)
            continue;

        void *addr = map_load_section_from_fd(interp_fd, curr_phdr,
                                              ehdr.e_type == ET_EXEC);

        if (!base_addr_set) {
            DEBUG_FMT("interpreter base address is %p", addr);
            *interp_base = addr;
            base_addr_set = 1;
        }
    }

    DIE_IF(sys_close(interp_fd) < 0, "could not close interpreter binary");
}

static void *map_elf_from_mem(
        void *elf_start,
        void **interp_entry,
        void **interp_base) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) elf_start;

    int load_addr_set = 0;
    void *load_addr = NULL;

    Elf64_Phdr *curr_phdr = elf_start + ehdr->e_phoff;
    Elf64_Phdr *interp_hdr = NULL;
    // 遍历所有的program header
    for (int i = 0; i < ehdr->e_phnum; i++) {
        void *seg_addr = NULL;

        if (curr_phdr->p_type == PT_LOAD)
            seg_addr = map_load_section_from_mem(elf_start, *curr_phdr);
        else if (curr_phdr->p_type == PT_INTERP) {
            interp_hdr = curr_phdr;
        }

        if (!load_addr_set && seg_addr != NULL) {
            load_addr = seg_addr;
            load_addr_set = 1;
        }

        curr_phdr++;
    }

    if (interp_hdr) {
        map_interp(elf_start + interp_hdr->p_offset, interp_entry, interp_base);
    } else {
        *interp_base = NULL;
        *interp_entry = NULL;
    }

    return load_addr;
}

static void replace_auxv_ent(unsigned long long *auxv_start,
                             unsigned long long label,
                             unsigned long long value) {
    unsigned long long *curr_ent = auxv_start;
    while (*curr_ent != label && *curr_ent != AT_NULL) curr_ent += 2;
    DIE_IF_FMT(*curr_ent == AT_NULL, "could not find auxv entry %d", label);

    *(++curr_ent) = value;
    DEBUG_FMT("replaced auxv entry %llu with value %llu (0x%p)", label, value,
              value);
}

// 设置辅助数组的值
static void setup_auxv(
        void *argv_start,
        void *entry,
        void *phdr_addr,
        void *interp_base,
        unsigned long long phnum) {

// 一个简单的宏定义，用来找到下一个NULL
#define ADVANCE_PAST_NEXT_NULL(ptr) \
  while (*(++ptr) != 0) ;           \
  ptr++;

    unsigned long long *auxv_start = argv_start;
    // 下面这两行干嘛去？？
    // 运行完这个宏定义到了环境变量开始的地方
    ADVANCE_PAST_NEXT_NULL(auxv_start) /* argv */
    // 运行完这个宏定义到了环境变量结束的地方后一个
    ADVANCE_PAST_NEXT_NULL(auxv_start) /* envp */
    // 运行完之后指向auxiliary vector开始的地方

    DEBUG_FMT("taking %p as auxv start", auxv_start);
    replace_auxv_ent(auxv_start, AT_ENTRY, (unsigned long long) entry);
    replace_auxv_ent(auxv_start, AT_PHDR, (unsigned long long) phdr_addr);
    replace_auxv_ent(auxv_start, AT_BASE, (unsigned long long) interp_base);
    replace_auxv_ent(auxv_start, AT_PHNUM, phnum);
}

static void decrypt_packed_bin(
        void *packed_bin_start,
        size_t *packed_bin_size,
        struct aes_key *key) {

    DEBUG_FMT("AES decrypting binary with key %s", STRINGIFY_KEY(key));
    DEBUG_FMT("the packed_bin_size : %u\n", *packed_bin_size);
    DEBUG_FMT("the address of packed_bin_start: %p\n", packed_bin_start);

    // DEBUG_FMT("open serial %d\n", serial_communication());

    unsigned long t = *packed_bin_size - *packed_bin_size % sizeof(struct aes_key);
    char* out = (char*)ks_malloc(t * sizeof(char));
    DEBUG_FMT("the val : %d\n", *(char*)out);
    AesContext aes_context;
    aesInit(&aes_context, key->bytes, sizeof(struct aes_key));
    ecbDecrypt(AES_CIPHER_ALGO, &aes_context, packed_bin_start, out, t);
    DEBUG_FMT("the val : %d\n", *((char*)out));
    memcpy(packed_bin_start, out, t);
    DEBUG_FMT("decrypt success %d", 1);
    ks_free(out);
}

static void decrypt_packed_bin_des(
        void *packed_bin_start,
        size_t *packed_bin_size,
        struct des_key *key) {

    DEBUG_FMT("DES decrypting binary with key %s", STRINGIFY_KEY(key));
    DEBUG_FMT("the packed_bin_size : %u\n", *packed_bin_size);
    DEBUG_FMT("the address of packed_bin_start: %p\n", packed_bin_start);

    // DEBUG_FMT("open serial %d\n", serial_communication());

    unsigned long t = *packed_bin_size - *packed_bin_size % sizeof(struct des_key);
    char* out = (char*)ks_malloc(t * sizeof(char));
    DEBUG_FMT("the val : %d\n", *(char*)out);
    DesContext des_context;
    desInit(&des_context, key->bytes, sizeof(struct des_key));
    ecbDecrypt(DES_CIPHER_ALGO, &des_context, packed_bin_start, out, t);
    DEBUG_FMT("the val : %d\n", *((char*)out));
    memcpy(packed_bin_start, out, t);
    DEBUG_FMT("decrypt success %d", 1);
    ks_free(out);
}


static void decrypt_packed_bin_des3(
        void *packed_bin_start,
        size_t *packed_bin_size,
        struct des3_key *key) {

    DEBUG_FMT("DES3 decrypting binary with key %s", STRINGIFY_KEY(key));
    DEBUG_FMT("the packed_bin_size : %u\n", *packed_bin_size);
    DEBUG_FMT("the address of packed_bin_start: %p\n", packed_bin_start);

    // DEBUG_FMT("open serial %d\n", serial_communication());

    unsigned long t = *packed_bin_size - *packed_bin_size % sizeof(struct des3_key);
    char* out = (char*)ks_malloc(t * sizeof(char));
    DEBUG_FMT("the val : %d\n", *(char*)out);
    Des3Context des3_context;
    des3Init(&des3_context, key->bytes, sizeof(struct des3_key));
    ecbDecrypt(DES3_CIPHER_ALGO, &des3_context, packed_bin_start, out, t);
    DEBUG_FMT("the val : %d\n", *((char*)out));
    memcpy(packed_bin_start, out, t);
    DEBUG_FMT("decrypt success %d", 1);
    ks_free(out);
}

static void decrypt_packed_bin_rc4(
        void *packed_bin_start,
        size_t *packed_bin_size,
        struct rc4_key *key) {

    DEBUG_FMT("RC4 decrypting binary with key %s", STRINGIFY_KEY(key));
    DEBUG_FMT("the packed_bin_size : %u\n", *packed_bin_size);
    DEBUG_FMT("the address of packed_bin_start: %p\n", packed_bin_start);

    // DEBUG_FMT("open serial %d\n", serial_communication());

    unsigned long t = *packed_bin_size - *packed_bin_size % sizeof(struct rc4_key);
    char* out = (char*)ks_malloc(t * sizeof(char));
    DEBUG_FMT("the val : %d\n", *(char*)out);
    Rc4Context rc4_context;
    rc4Init(&rc4_context, key->bytes, sizeof(struct rc4_key));
    rc4Cipher(&rc4_context, packed_bin_start, out, t);
    DEBUG_FMT("the val : %d\n", *((char*)out));
    memcpy(packed_bin_start, out, t);
    DEBUG_FMT("decrypt success %d", 1);
    ks_free(out);
}

/* Convenience wrapper around obf_deobf_outer_key to automatically pass in
 * correct loader code offsets. */
void loader_outer_key_deobfuscate(
        struct key_placeholder *old_key,
        struct aes_key *new_key,
        uint8_t* loader_bin,
        size_t loader_bin_size) {

    __builtin_memcpy(new_key, old_key, sizeof(*new_key));

    #ifdef NO_ANTIDEBUG
    return;
    #endif

    /* Skip the struct aes_key of course, we just want the code */
    unsigned int loader_index = KEY_SIZE_AFTER_ALIGN;
    unsigned int key_index = 0;
    while (loader_index < loader_bin_size / 10) {
        new_key->bytes[0] ^= loader_bin[loader_index];
        loader_index++;
        key_index = (key_index + 1) % sizeof(new_key->bytes);
    }
}

void loader_outer_key_deobfuscate_aes(
        struct key_placeholder *old_key,
        struct aes_key *new_key,
        uint8_t* loader_bin,
        size_t loader_bin_size) {

    __builtin_memcpy(new_key, old_key->bytes, sizeof(*new_key));

    #ifdef NO_ANTIDEBUG
    return;
    #endif

    /* Skip the struct aes_key of course, we just want the code */
    unsigned int loader_index = KEY_SIZE_AFTER_ALIGN;
    unsigned int key_index = 0;
    while (loader_index < loader_bin_size / 10) {
        new_key->bytes[0] ^= loader_bin[loader_index];
        loader_index++;
        key_index = (key_index + 1) % sizeof(new_key->bytes);
    }
}

void loader_outer_key_deobfuscate_des(
        struct key_placeholder *old_key,
        struct des_key *new_key,
        uint8_t* loader_bin,
        size_t loader_bin_size) {

    __builtin_memcpy(new_key, old_key->bytes, sizeof(*new_key));

    #ifdef NO_ANTIDEBUG
    return;
    #endif

    /* Skip the struct des_key of course, we just want the code */
    unsigned int loader_index = KEY_SIZE_AFTER_ALIGN;
    unsigned int key_index = 0;
    while (loader_index < loader_bin_size / 10) {
        new_key->bytes[0] ^= loader_bin[loader_index];
        loader_index++;
        key_index = (key_index + 1) % sizeof(new_key->bytes);
    }
}

void loader_outer_key_deobfuscate_rc4(
        struct key_placeholder *old_key,
        struct rc4_key *new_key,
        uint8_t* loader_bin,
        size_t loader_bin_size) {

    __builtin_memcpy(new_key, old_key->bytes, sizeof(*new_key));

    #ifdef NO_ANTIDEBUG
    return;
    #endif

    /* Skip the struct rc4_key of course, we just want the code */
    unsigned int loader_index = KEY_SIZE_AFTER_ALIGN;
    unsigned int key_index = 0;
    while (loader_index < loader_bin_size / 10) {
        new_key->bytes[0] ^= loader_bin[loader_index];
        loader_index++;
        key_index = (key_index + 1) % sizeof(new_key->bytes);
    }
}

void loader_outer_key_deobfuscate_des3(
        struct key_placeholder *old_key,
        struct des3_key *new_key,
        uint8_t* loader_bin,
        size_t loader_bin_size) {

    __builtin_memcpy(new_key, old_key->bytes, sizeof(struct des3_key));

    #ifdef NO_ANTIDEBUG
    return;
    #endif

    /* Skip the struct des3_key of course, we just want the code */
    unsigned int loader_index = KEY_SIZE_AFTER_ALIGN;
    unsigned int key_index = 0;
    while (loader_index < loader_bin_size / 10) {
        new_key->bytes[0] ^= loader_bin[loader_index];
        loader_index++;
        key_index = (key_index + 1) % sizeof(struct des3_key);
    }
}

int decompress_bin(const uint8_t* in, uint32_t in_len, uint8_t* out, uint32_t* out_len) {
    return 0;
}

/* Load the packed binary, returns the address to hand control to when done */
void *load(void *entry_stacktop) {
    ks_malloc_init();
    // 反调试功能, 具体怎么反调试的?
    if (antidebug_proc_check_traced())
        DIE(TRACED_MSG);

    antidebug_remove_ld_env_vars(entry_stacktop);

    /* Disable core dumps via rlimit here before we start doing sensitive stuff
     * like key deobfuscation and binary decryption. Child process should
     * inherit these limits after the fork, although it wouldn't hurt to call
     * this again post-fork just in case this inlined call is patched out. */
    antidebug_rlimit_set_zero_core();

    /* As per the SVr4 ABI */
    /* int argc = (int) *((unsigned long long *) entry_stacktop); */
    // char* 类型的指针
    char **argv = ((char **) entry_stacktop) + 1;
    enum Encryption encryption_algorithm = AES;
    enum Compression compression_algorithm = ZSTD;
    // get the alogorithm type
    switch (obfuscated_key.encryption) {
        case 1:
            encryption_algorithm = RC4;
            break;
        case 2:
            encryption_algorithm = DES;
            break;
        case 3:
            encryption_algorithm = TDEA;
            break;
        case 4:
            encryption_algorithm = AES;
            break;
    }

    switch (obfuscated_key.compression) {
        case 1:
            compression_algorithm = LZMA;
            break;
        case 2:
            compression_algorithm = LZO;
            break;
        case 3:
            compression_algorithm = UCL;
            break;
        case 4:
            compression_algorithm = ZSTD;
            break;
    }


    /* "our" EHDR (ie. the one in the on-disk binary that was run) */
    // hello_world_pak
    Elf64_Ehdr *us_ehdr = (Elf64_Ehdr *) LOADER_ADDR;

    /* The PHDR in our binary corresponding to the loader (ie. this code) */
    Elf64_Phdr *loader_phdr = (Elf64_Phdr *)
            (LOADER_ADDR + us_ehdr->e_phoff);

    /* The PHDR in our binary corresponding to the encrypted app */
    Elf64_Phdr *packed_bin_phdr = loader_phdr + 1;

    /* The EHDR of the actual application to be run (encrypted until
     * decrypt_packed_bin is called)
     */
    Elf64_Ehdr *packed_bin_ehdr = (Elf64_Ehdr *) (packed_bin_phdr->p_vaddr);

    DEBUG_FMT("obkey %s", STRINGIFY_KEY(&obfuscated_key));

    // zstd decompression
    uint8_t* compressedBlob = packed_bin_phdr->p_vaddr;
    uint32_t compressedSize = packed_bin_phdr->p_filesz;
    uint32_t decompressedSize = packed_bin_phdr->p_memsz;
    uint8_t* decompressedBlob = ks_malloc(decompressedSize);
    DEBUG_FMT("Decompress: from %d to %d\n", compressedSize, decompressedSize);
    decompressedSize = ZSTD_decompress(decompressedBlob, decompressedSize, compressedBlob, compressedSize);
    memcpy((void*) packed_bin_phdr->p_vaddr, decompressedBlob, decompressedSize);


    /* The first ELF segment (loader code) includes the ehdr and two phdrs,
     * adjust loader code start and size accordingly */
    size_t hdr_adjust = sizeof(Elf64_Ehdr) + (2 * sizeof(Elf64_Phdr));
    void *loader_start = (void *) loader_phdr->p_vaddr + hdr_adjust;
    size_t loader_size = loader_phdr->p_memsz - hdr_adjust;

    if (encryption_algorithm == AES) {
        DEBUG("[LOADER] Using AES");
        // 拿到AES的真实KEY
        struct aes_key actual_key;
        loader_outer_key_deobfuscate_aes(&obfuscated_key, &actual_key, loader_start, loader_size);
        DEBUG_FMT("realkey %s", STRINGIFY_KEY(&actual_key));
        decrypt_packed_bin((void *) packed_bin_phdr->p_vaddr, &(packed_bin_phdr->p_memsz), &actual_key);
    } else if (encryption_algorithm == DES) {
        DEBUG("[LOADER] Using DES");
        struct des_key actual_key;
        loader_outer_key_deobfuscate_des(&obfuscated_key, &actual_key, loader_start, loader_size);
        DEBUG_FMT("realkey %s", STRINGIFY_KEY(&actual_key));
        decrypt_packed_bin_des((void *) packed_bin_phdr->p_vaddr, &(packed_bin_phdr->p_memsz), &actual_key);
    } else if (encryption_algorithm == RC4) {
        struct rc4_key actual_key;
        loader_outer_key_deobfuscate_rc4(&obfuscated_key, &actual_key, loader_start, loader_size);
        DEBUG_FMT("realkey %s", STRINGIFY_KEY(&actual_key));
        decrypt_packed_bin_rc4((void *) packed_bin_phdr->p_vaddr,&(packed_bin_phdr->p_memsz), &actual_key);
    } else if (encryption_algorithm == TDEA) {
        struct des3_key actual_key;
        loader_outer_key_deobfuscate_des3(&obfuscated_key, &actual_key, loader_start, loader_size);
        DEBUG_FMT("realkey %s", STRINGIFY_KEY(&actual_key));
        decrypt_packed_bin_des3((void *) packed_bin_phdr->p_vaddr,&(packed_bin_phdr->p_memsz),&actual_key);
    }
    DEBUG("[LOADER] decrypt sucessfully");


    /* Entry point for ld.so if this is not a statically linked binary, otherwise
     * map_elf_from_mem will not touch this and it will be set below. */
    void *interp_entry = NULL;
    void *interp_base = NULL;
    // 对解密后的文件进行处理
    void *load_addr = map_elf_from_mem(packed_bin_ehdr, &interp_entry, &interp_base);
    DEBUG_FMT("binary base address is %p", load_addr);

    void *program_entry = packed_bin_ehdr->e_type == ET_EXEC ?
                          (void *) packed_bin_ehdr->e_entry : load_addr + packed_bin_ehdr->e_entry;
    // 在命令函参数之上有环境变量，环境变量之上就是辅助向量，存了一些键值对，提供给动态链接器?
    // 修改了程序入口地址，program header addr，interpreter base和program header number
    setup_auxv(argv,
               program_entry,
               (void *) (load_addr + packed_bin_ehdr->e_phoff),
               interp_base,
               packed_bin_ehdr->e_phnum);

    DEBUG("finished mapping binary into memory");

    /* load returns the initial address entry code should jump to. If we have a
     * dynamic linker, this is its entry address, otherwise, it's the address
     * specified in the binary itself.
     */
    void *initial_entry = interp_entry == NULL ? program_entry : interp_entry;
    DEBUG_FMT("control will be passed to packed app at %p", initial_entry);
    // 如果我们的elf是静态链接的，就直接返回entry，否则会交给动态链接器处理
    return initial_entry;
}