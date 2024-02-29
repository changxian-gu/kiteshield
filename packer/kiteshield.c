#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <termios.h>

#include "common/include/defs.h"
#include "common/include/inner_rc4.h"
#include "common/include/obfuscation.h"
#include "common/include/random.h"
#include "loader/out/generated_loader_no_rt.h"
#include "loader/out/generated_loader_rt.h"
#include "packer/include/elfutils.h"

// include encryption headers
#include "cipher/aes.h"
#include "cipher/des.h"
#include "cipher/des3.h"
#include "cipher/rc4.h"
#include "cipher_modes/ecb.h"
#include "pkc/rsa.h"
#include "rng/yarrow.h"
#include "ecc/ecc.h"
// include compression headers
#include "compression/lzma/Lzma.h"
#include "compression/lzo/minilzo.h"
#include "compression/ucl/include/ucl.h"
#include "compression/zstd/zstd.h"


unsigned char serial_key[16];

static HEAP_ALLOC(wrkmem, LZO1X_1_MEM_COMPRESS);

YarrowContext yarrowContext;

void printBytes(const char *msg, unsigned long len) {
    for (int i = 0; i < len; i++) {
        ks_printf(1, "0x%x(", (unsigned char)(msg[i]));
        ks_printf(1, "%d) ", (unsigned char)(msg[i]));
    }
    ks_printf(1, "%s", "\n");
}

enum Encryption encryption_algorithm = AES;
enum PubEncryption pub_algorithm = RSA;
enum Compression compression_algorithm = ZSTD;

/* Convenience macro for error checking libc calls */
#define CK_NEQ_PERROR(stmt, err) \
    do {                         \
        if ((stmt) == err) {     \
            perror(#stmt);       \
            return -1;           \
        }                        \
    } while (0)

#define STRINGIFY_KEY(key)                                \
    ({                                                    \
        char buf[(sizeof(key.bytes) * 2) + 1];            \
        for (int i = 0; i < sizeof(key.bytes); i++) {     \
            sprintf(&buf[i * 2], "%02hhx", key.bytes[i]); \
        };                                                \
        buf;                                              \
    })

static int log_verbose = 0;

static void err(char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    vfprintf(stderr, fmt, args);
    printf("\n");
}

static void info(char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    vprintf(fmt, args);
    printf("\n");
}

static void verbose(char *fmt, ...) {
    if (!log_verbose)
        return;

    va_list args;
    va_start(args, fmt);

    vprintf(fmt, args);
    printf("\n");
}


static int read_input_elf(char *path, struct mapped_elf *elf) {
    void *elf_buf;
    size_t size;

    FILE *file;
    // 只读方式打开
    CK_NEQ_PERROR(file = fopen(path, "r"), NULL);
    // 将文件指针指向文件的末尾，偏移0字节
    CK_NEQ_PERROR(fseek(file, 0L, SEEK_END), -1);
    // 返回位置标识符的当前值(获取文件字节大小)
    CK_NEQ_PERROR(size = ftell(file), -1);
    // 申请空间, 多申请128字节用来保存shuffle等需要的信息
    CK_NEQ_PERROR(elf_buf = malloc(size + 128), NULL);
    // 将文件指针指向文件开头，偏移0字节
    CK_NEQ_PERROR(fseek(file, 0L, SEEK_SET), -1);
    /**
     * size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
     * 从给定流 stream 读取数据到 ptr
     * ptr -- 这是指向带有最小尺寸 size*nmemb 字节的内存块的指针。
     * size -- 这是要读取的每个元素的大小，以字节为单位。
     * nmemb -- 这是元素的个数，每个元素的大小为 size 字节。
     * stream -- 这是指向 FILE 对象的指针，该 FILE 对象指定了一个输入流
     */
    CK_NEQ_PERROR(fread(elf_buf, size, 1, file), 0);
    // 关闭文件
    CK_NEQ_PERROR(fclose(file), EOF);

    parse_mapped_elf(elf_buf, size, elf);

    return 0;
}

static int produce_output_elf(FILE *output_file, struct mapped_elf *elf,
                              void *loader, size_t loader_size) {
    /* The entry address is located right after the struct des_key (used for
     * passing decryption key and other info to loader), which is the first
     * sizeof(struct des_key) bytes of the loader code (guaranteed by the linker
     * script) */
    // 跳过打包后的ELF头和两个prog
    // header和placeholder的大小，正好到达loader的.text的第一个字节处
    Elf64_Addr entry_vaddr = LOADER_ADDR + sizeof(Elf64_Ehdr) +
                             (sizeof(Elf64_Phdr) * 2) + KEY_SIZE_AFTER_ALIGN;

    Elf64_Ehdr ehdr;
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
    ehdr.e_ident[EI_ABIVERSION] = 0;
    memset(ehdr.e_ident + EI_PAD, 0, EI_NIDENT - EI_PAD);

    ehdr.e_type = ET_EXEC;
    ehdr.e_machine = EM_X86_64;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_entry = entry_vaddr;
    ehdr.e_phoff = sizeof(Elf64_Ehdr);
    ehdr.e_shoff = 0;
    ehdr.e_flags = 0;
    ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = 2;
    ehdr.e_shentsize = sizeof(Elf64_Shdr);
    ehdr.e_shnum = 1;
    ehdr.e_shstrndx = SHN_UNDEF;
    // 写入ELF头
    CK_NEQ_PERROR(fwrite(&ehdr, sizeof(ehdr), 1, output_file), 0);

    /* Size of the first segment include the size of the ehdr and two phdrs */
    // 意思是说第一个segment要包含ELF的头和所有的program
    // header吗？好像有道理，因为程序加载需要用到program header？
    size_t hdrs_size = sizeof(Elf64_Ehdr) + (2 * sizeof(Elf64_Phdr));

    /* Program header for loader */
    // int loader_offset = ftell(output_file) + 2 * sizeof(Elf64_Phdr);
    Elf64_Phdr loader_phdr;
    loader_phdr.p_type = PT_LOAD;
    // 为什么偏移量是0？？？不需要跳过两个program header 和 ELF
    // header吗？？？？还是说不重要？？
    //  懂了，是没有必要，
    //  因为入口地址就设置的是loader的地址，这个填不填无所谓了，当然，也可以计算
    //  ELF header + 2 * program header
    //  并不是上面说的这样，第一个segment负责包含ELF header 和所有的 program
    //  header
    loader_phdr.p_offset = 0;
    loader_phdr.p_vaddr = LOADER_ADDR;
    loader_phdr.p_paddr = loader_phdr.p_vaddr;
    // loader本身带有的一个头和两个program header??
    // 并不是啊，因为使用了objcopy生成了bin文件，里面不含ELF头部和program
    // header啊啊？？ 第一个segment负责包含ELF header 和所有的 program
    // header（暂时的推断）
    loader_phdr.p_filesz = loader_size + hdrs_size;
    loader_phdr.p_memsz = loader_size + hdrs_size;
    loader_phdr.p_flags = PF_R | PF_W | PF_X;
    loader_phdr.p_align = 0x200000;
    // 写入loader program header
    CK_NEQ_PERROR(fwrite(&loader_phdr, sizeof(loader_phdr), 1, output_file), 0);

    /* Program header for packed application */
    int app_offset = ftell(output_file) + sizeof(Elf64_Phdr) + loader_size;
    Elf64_Phdr app_phdr;
    app_phdr.p_type = PT_LOAD;
    // 这个就很正常，ELF header + 2 * program header + loader Segment的长度
    app_phdr.p_offset = app_offset;
    app_phdr.p_vaddr = PACKED_BIN_ADDR + app_offset; /* Keep vaddr aligned */
    app_phdr.p_paddr = app_phdr.p_vaddr;
    app_phdr.p_filesz = elf->size + PROGRAM_AUX_LEN;
    app_phdr.p_memsz = elf->origin_size;
    app_phdr.p_flags = PF_R | PF_W;
    app_phdr.p_align = 0x200000;
    // 写入app program header
    CK_NEQ_PERROR(fwrite(&app_phdr, sizeof(app_phdr), 1, output_file), 0);

    /* Loader code/data */
    CK_NEQ_PERROR(fwrite(loader, loader_size, 1, output_file), 0);

    /* Packed application contents */
    // 写入处理后的文件，写入shuffled，写入swap_infos, 写入sections_arr
    CK_NEQ_PERROR(fwrite(elf->start, elf->size, 1, output_file), 0);
    // void *app = malloc(elf->size);
    // CK_NEQ_PERROR(fwrite(app, elf->origin_size, 1, output_file), 0);

    return 0;
}

static int get_key_from_serial(void* buf, size_t len) {
    unsigned char *p = (unsigned char *)buf;
    int index = 0;
    for (int i = 0; i < len; i++) {
        p[index++] = serial_key[i % 16];
    }
    return 0;
}

static void encrypt_memory_range(struct rc4_key *key, void *start, size_t len) {
    struct rc4_state rc4;
    rc4_init(&rc4, key->bytes, sizeof(key->bytes));

    uint8_t *curr = start;
    for (size_t i = 0; i < len; i++) {
        *curr = *curr ^ rc4_get_byte(&rc4);
        curr++;
    }
}

static void encrypt_memory_range_aes(struct aes_key *key, void *start,
                                     size_t len) {
    size_t key_len = sizeof(struct aes_key);
    printf("aes key_len : %d\n", key_len);
    unsigned char *out = (unsigned char *)malloc((len) * sizeof(char));
    // 使用DES加密后密文长度可能会大于明文长度怎么办?
    // 目前解决方案，保证加密align倍数的明文长度，有可能会剩下一部分字节，不做处理
    unsigned long actual_encrypt_len = len - len % key_len;
    printf("actual encrypt len : %lu\n", actual_encrypt_len);
    if (actual_encrypt_len == 0)
        return;
    AesContext aes_context;
    aesInit(&aes_context, key->bytes, key_len);
    ecbEncrypt(AES_CIPHER_ALGO, &aes_context, start, out, actual_encrypt_len);
    memcpy(start, out, actual_encrypt_len);
    aesDeinit(&aes_context);
}

static void encrypt_memory_range_rc4(struct rc4_key *key, void *start,
                                     size_t len) {
    size_t key_len = sizeof(struct rc4_key);
    unsigned char *out = (unsigned char *)malloc((len) * sizeof(char));
    unsigned long actual_encrypt_len = len;
    if (actual_encrypt_len == 0)
        return;
    Rc4Context rc4_context;
    rc4Init(&rc4_context, key->bytes, key_len);
    rc4Cipher(&rc4_context, start, out, actual_encrypt_len);
    memcpy(start, out, actual_encrypt_len);
    rc4Deinit(&rc4_context);
}

static void encrypt_memory_range_des(struct des_key *key, void *start,
                                     size_t len) {
    size_t key_len = sizeof(struct des_key);
    unsigned char *out = (unsigned char *)malloc(len);
    unsigned long actual_encrypt_len = len - len % key_len;
    if (actual_encrypt_len == 0)
        return;
    DesContext des_context;
    desInit(&des_context, key->bytes, key_len);
    ecbEncrypt(DES_CIPHER_ALGO, &des_context, start, out, actual_encrypt_len);
    memcpy(start, out, actual_encrypt_len);
    desDeinit(&des_context);
}

static void encrypt_memory_range_des3(struct des3_key *key, void *start,
                                      size_t len) {
    size_t key_len = sizeof(struct des3_key);
    unsigned char *out = (unsigned char *)malloc(len);
    unsigned long actual_encrypt_len = len - len % key_len;
    if (actual_encrypt_len == 0)
        return;
    Des3Context des3_context;
    des3Init(&des3_context, key->bytes, key_len);
    ecbEncrypt(DES3_CIPHER_ALGO, &des3_context, start, out, actual_encrypt_len);
    memcpy(start, out, actual_encrypt_len);
    des3Deinit(&des3_context);
}

static uint64_t get_base_addr(Elf64_Ehdr *ehdr) {
    /* Return the base address that the binary is to be mapped in at runtime. If
     * statically linked, use absolute addresses (ie. base address = 0).
     * Otherwise, everything is relative to DYN_PROG_BASE_ADDR. */
    return ehdr->e_type == ET_EXEC ? 0ULL : DYN_PROG_BASE_ADDR;
}

/* Determines if the given jmp instruction requires replacement by an int3 and
 * thus a trap into the runtime at program execution time. JMPs that do leave
 * or have the potential to leave their containing function require
 * instrumentation as otherwise program control would could be handed to
 * encrypted code.
 *
 * While not normally generated by C compilers for average C code, binaries can
 * and do have these kinds of jmps. setjmp/longjmp is one example. glibc
 * additionally contains several of these jumps as a result of handwritten asm
 * or other nonstandard internal constructs.
 */
// static int is_instrumentable_jmp(
//     INSTRUX *ix,
//     uint64_t fcn_start,
//     size_t fcn_size,
//     uint64_t ix_addr)
//{
//   /* Indirect jump (eg. jump to value stored in register or at memory
//   location.
//    * These must always be instrumented as we have no way at pack-time of
//    * knowing where they will hand control, thus the runtime must check them
//    * each time and encrypt/decrypt/do nothing as needed.
//    */
//   if (ix->Instruction == ND_INS_JMPNI)
//     return 1;
//
//   /* Jump with (known at pack-time) relative offset, check if it jumps out of
//    * its function, if so, it requires instrumentation. */
//   if (ix->Instruction == ND_INS_JMPNR || ix->Instruction == ND_INS_Jcc) {
//     /* Rel is relative to next instruction so we must add the length */
//     int64_t displacement =
//       (int64_t) ix->Operands[0].Info.RelativeOffset.Rel + ix->Length;
//     uint64_t jmp_dest = ix_addr + displacement;
//     if (jmp_dest < fcn_start || jmp_dest >= fcn_start + fcn_size)
//       return 1;
//   }
//
//   return 0;
// }

/* Instruments all appropriate points in the given function (function entry,
 * ret instructions, applicable jmp instructions) with int3 instructions and
 * encrypts it with a newly generated key.
 */
/* elf是一个映射elf文件的结构体指针
 * func_sym 是一个symbol表象的指针
 * rt_info 是在加密函数过程中用来记录信息的
 * func_arr
 * 是一个指向结构体的指针，其中包含了函数的开始地址、长度以及加密用的key tp_arr
 * 保存了函数的入口点
 */
static int process_func(struct mapped_elf *elf, Elf64_Sym *func_sym,
                        struct runtime_info *rt_info, struct function *func_arr,
                        struct trap_point *tp_arr) {
    uint8_t *func_start = elf_get_sym_location(elf, func_sym);
    uint64_t base_addr = get_base_addr(elf->ehdr);
    struct function *fcn = &func_arr[rt_info->nfuncs];

    fcn->id = rt_info->nfuncs;
    fcn->start_addr = base_addr + func_sym->st_value;
    fcn->len = func_sym->st_size;
    CK_NEQ_PERROR(get_random_bytes(fcn->key.bytes, sizeof(fcn->key.bytes)), -1);
#ifdef DEBUG_OUTPUT
    strncpy(fcn->name, elf_get_sym_name(elf, func_sym), sizeof(fcn->name));
    fcn->name[sizeof(fcn->name) - 1] = '\0';
#endif

    info("encrypting function %s with key %s", elf_get_sym_name(elf, func_sym),
         STRINGIFY_KEY(fcn->key));

    /* Instrument entry point */
    struct trap_point *tp = (struct trap_point *)&tp_arr[rt_info->ntraps++];
    tp->addr = base_addr + func_sym->st_value;
    tp->type = TP_FCN_ENTRY;
    tp->value = *func_start;
    tp->fcn_i = rt_info->nfuncs;

    encrypt_memory_range(&fcn->key, func_start, func_sym->st_size);

    *func_start = INT3;

    rt_info->nfuncs++;

    return 0;
}

/* Individually encrypts every function in the input ELF with their own keys
 * and instruments function entry and exit points as appropriate such that
 * the runtime can encrypt/decrypt during execution.
 */
static int apply_inner_encryption(struct mapped_elf *elf,
                                  struct runtime_info **rt_info) {
    info("applying inner encryption");

    /**
     * 如果section的偏移为0，符号表为空，则无法加密内部加密
     */
    if (elf->ehdr->e_shoff == 0 || !elf->symtab) {
        info("binary is stripped, not applying inner encryption");
        return -1;
    }

    if (!elf->strtab) {
        err("could not find string table, not applying inner encryption");
        return -1;
    }

    CK_NEQ_PERROR(*rt_info = malloc(sizeof(**rt_info)), NULL);
    (*rt_info)->nfuncs = 0;
    (*rt_info)->ntraps = 0;

    /* "16 MiB ought to be enough for anybody" */
    /**
     * 2^24 = 2^10 * 2^10 * 2^4
     *      = 1024 * 1024 * 16
     *      = 1M * 16
     *
     */
    struct function *fcn_arr;
    CK_NEQ_PERROR(fcn_arr = malloc(1 << 24), NULL);

    struct trap_point *tp_arr;
    CK_NEQ_PERROR(tp_arr = malloc(1 << 24), NULL);

    // 遍历符号表
    ELF_FOR_EACH_SYMBOL(elf, sym) {
        // 加密func
        if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
            continue;

        /* Statically linked binaries contain several function symbols that
         * alias each other (_IO_vfprintf and fprintf in glibc for instance).
         * Furthermore, there can occasionally be functions that overlap other
         * functions at the ELF level due to weird optimizations and/or custom
         * linker logic (confirmed present in the CentOS 7 glibc-static package)
         *
         * Detect and skip them here as to not double-encrypt.
         */
        uint64_t base = get_base_addr(elf->ehdr);
        struct function *alias = NULL;
        for (size_t i = 0; i < (*rt_info)->nfuncs; i++) {
            struct function *fcn = &fcn_arr[i];

            /* If there's any overlap at all between something we've already
             * encrypted, abort */
            if ((fcn->start_addr < (base + sym->st_value + sym->st_size)) &&
                ((fcn->start_addr + fcn->len) > base + sym->st_value)) {
                alias = fcn;
                break;
            }
        }

        if (alias) {
            /* We have alias->name if DEBUG_OUTPUT is set, so output it for a
             * bit more useful info */
#ifndef DEBUG_OUTPUT
            verbose(
                "not encrypting function %s at %p as it aliases or overlaps "
                "one already encrypted at %p of len %u",
                elf_get_sym_name(elf, sym), alias->start_addr, alias->len);
#else
            verbose(
                "not encrypting function %s at %p as it aliases or overlaps %s "
                "at %p of len %u",
                elf_get_sym_name(elf, sym), base + sym->st_value, alias->name,
                alias->start_addr, alias->len);
#endif

            continue;
        }

        /* Skip instrumenting/encrypting functions in cases where it simply will
         * not work or has the potential to mess things up. Specifically, this
         * means we don't instrument functions that:
         *
         *  * Are not in .text (eg. stuff in .init)
         *
         *  * Have an address of 0 (stuff that needs to be relocated, this
         * should be covered by the point above anyways, but check to be safe)
         *
         *  * Have a size of 0 (stuff in crtstuff.c that was compiled with
         *  -finhibit-size-directive has a size of 0, thus we can't instrument)
         *
         *  * Have a size less than 2 (superset of above point). Instrumentation
         *  requires inserting at least two int3 instructions, each of which is
         * one byte.
         *
         *  * Start with an instruction that modifies control flow (ie. jmp/ret)
         *  kiteshield instruments the start of every function AND every out of
         *  function jmp/return, so instrumenting these would require putting
         * two trap points at the same address. It's theoretically possible to
         * support this in the runtime, but would add a large amount of
         * complexity to it in order to support encrypting the small amount of
         * hand coded asm functions in glibc that are like this.
         */
        if (!elf_sym_in_text(elf, sym)) {
            verbose("not encrypting function %s as it's not in .text",
                    elf_get_sym_name(elf, sym));
            continue;
        } else if (sym->st_value == 0 || sym->st_size < 2) {
            verbose("not encrypting function %s due to its address or size",
                    elf_get_sym_name(elf, sym));
            continue;
        }

        if (process_func(elf, sym, *rt_info, fcn_arr, tp_arr) == -1) {
            err("error instrumenting function %s", elf_get_sym_name(elf, sym));
            return -1;
        }
    }

    size_t tp_arr_sz = sizeof(struct trap_point) * (*rt_info)->ntraps;
    size_t fcn_arr_sz = sizeof(struct function) * (*rt_info)->nfuncs;
    CK_NEQ_PERROR(*rt_info = realloc(*rt_info, sizeof(struct runtime_info) +
                                                   tp_arr_sz + fcn_arr_sz),
                  NULL);

    memcpy((*rt_info)->data, tp_arr, tp_arr_sz);
    memcpy((*rt_info)->data + tp_arr_sz, fcn_arr, fcn_arr_sz);

    free(tp_arr);
    free(fcn_arr);

    return 0;
}

static int apply_sections_encryption(struct mapped_elf *elf, uint64_t rand[]) {
    if (encryption_algorithm == AES) {
        printf("[Packer] Using AES...\n");
        struct aes_key key;
        CK_NEQ_PERROR(get_key_from_serial(key.bytes, sizeof(key.bytes)), -1);
        info("applying outer encryption with key %s", STRINGIFY_KEY(key));
        /* Encrypt the actual binary */
        encrypt_memory_range_aes(&key, (void *)(elf->start + rand[0]), rand[1]);
        encrypt_memory_range_aes(&key, (void *)(elf->start + rand[2]), rand[3]);
    } else if (encryption_algorithm == DES) {
        printf("[Packer] Using DES...\n");
        struct des_key key;
        CK_NEQ_PERROR(get_key_from_serial(key.bytes, sizeof(key.bytes)), -1);
        info("applying outer encryption with key %s", STRINGIFY_KEY(key));
        /* Encrypt the actual binary */
        encrypt_memory_range_des(&key, (void *)(elf->start + rand[0]), rand[1]);
        encrypt_memory_range_des(&key, (void *)(elf->start + rand[2]), rand[3]);
    } else if (encryption_algorithm == RC4) {
        printf("[Packer] Using RC4...\n");
        struct rc4_key key;
        CK_NEQ_PERROR(get_key_from_serial(key.bytes, sizeof(key.bytes)), -1);
        info("applying outer encryption with key %s", STRINGIFY_KEY(key));
        /* Encrypt the actual binary */
        encrypt_memory_range_rc4(&key, (void *)(elf->start + rand[0]), rand[1]);
        encrypt_memory_range_rc4(&key, (void *)(elf->start + rand[2]), rand[3]);
    } else if (encryption_algorithm == TDEA) {
        printf("[Packer] Using TDEA...\n");
        struct des3_key key;
        CK_NEQ_PERROR(get_key_from_serial(key.bytes, sizeof(key.bytes)), -1);
        info("applying outer encryption with key %s", STRINGIFY_KEY(key));
        /* Encrypt the actual binary */
        encrypt_memory_range_des3(&key, (void *)(elf->start + rand[0]),
                                  rand[1]);
        encrypt_memory_range_des3(&key, (void *)(elf->start + rand[2]),
                                  rand[3]);
    }
    return 0;
}

/* Encrypts the input binary as a whole injects the outer key into the loader
 * code so the loader can decrypt.
 */
static int apply_outer_encryption(struct mapped_elf *elf, void *loader_start,
                                  size_t loader_size) {
    if (encryption_algorithm == AES) {
        printf("[Packer] Using AES...\n");
        struct aes_key key;
        CK_NEQ_PERROR(get_key_from_serial(key.bytes, sizeof(key.bytes)), -1);
        info("applying outer encryption with key %s", STRINGIFY_KEY(key));
        /* Encrypt the actual binary */
        encrypt_memory_range_aes(&key, elf->start, elf->size);

        // 把key写入loader
        struct key_placeholder m_key_placeholder = *(struct key_placeholder *)loader_start;
        memcpy(m_key_placeholder.bytes, key.bytes, sizeof(key));
        m_key_placeholder.encryption = AES;
        memcpy(loader_start, &m_key_placeholder, sizeof(struct key_placeholder));
    } else if (encryption_algorithm == DES) {
        printf("[Packer] Using DES...\n");
        struct des_key key;
        CK_NEQ_PERROR(get_key_from_serial(key.bytes, sizeof(key.bytes)), -1);
        info("applying outer encryption with key %s", STRINGIFY_KEY(key));
        /* Encrypt the actual binary */
        encrypt_memory_range_des(&key, elf->start, elf->size);
        /* Obfuscate Key */
        struct des_key obfuscated_key;
        obf_deobf_outer_key_des(&key, &obfuscated_key, loader_start,
                                loader_size);
        info("obfuscated_key %s", STRINGIFY_KEY(obfuscated_key));
        // 把混淆后的key写入loader
        struct key_placeholder m_key_placeholder =
            *(struct key_placeholder *)loader_start;
        memset(m_key_placeholder.bytes, 0, sizeof(m_key_placeholder.bytes));
        memcpy(m_key_placeholder.bytes, obfuscated_key.bytes,
               sizeof(obfuscated_key));
        m_key_placeholder.encryption = DES;
        memcpy(loader_start, &m_key_placeholder,
               sizeof(struct key_placeholder));
    } else if (encryption_algorithm == RC4) {
        printf("[Packer] Using RC4...\n");
        struct rc4_key key;
        CK_NEQ_PERROR(get_key_from_serial(key.bytes, sizeof(key.bytes)), -1);
        info("applying outer encryption with key %s", STRINGIFY_KEY(key));
        /* Encrypt the actual binary */
        // 修改elf长度
        encrypt_memory_range_rc4(&key, elf->start, elf->size);
        /* Obfuscate Key */
        struct rc4_key obfuscated_key;
        obf_deobf_outer_key_rc4(&key, &obfuscated_key, loader_start,
                                loader_size);
        info("obfuscated_key %s", STRINGIFY_KEY(obfuscated_key));
        // 把混淆后的key写入loader
        struct key_placeholder m_key_placeholder =
            *(struct key_placeholder *)loader_start;
        memset(m_key_placeholder.bytes, 0, sizeof(m_key_placeholder.bytes));
        memcpy(m_key_placeholder.bytes, obfuscated_key.bytes,
               sizeof(obfuscated_key));
        m_key_placeholder.encryption = RC4;
        memcpy(loader_start, &m_key_placeholder,
               sizeof(struct key_placeholder));
    } else if (encryption_algorithm == TDEA) {
        printf("[Packer] Using TDEA...\n");
        struct des3_key key;
        CK_NEQ_PERROR(get_key_from_serial(key.bytes, sizeof(key.bytes)), -1);
        info("applying outer encryption with key %s", STRINGIFY_KEY(key));
        /* Encrypt the actual binary */
        // 修改elf长度
        encrypt_memory_range_des3(&key, elf->start, elf->size);
        /* Obfuscate Key */
        struct des3_key obfuscated_key;
        obf_deobf_outer_key_des3(&key, &obfuscated_key, loader_start,
                                 loader_size);
        info("obfuscated_key %s", STRINGIFY_KEY(obfuscated_key));
        // 把混淆后的key写入loader
        struct key_placeholder m_key_placeholder =
            *(struct key_placeholder *)loader_start;
        memset(m_key_placeholder.bytes, 0, sizeof(m_key_placeholder.bytes));
        memcpy(m_key_placeholder.bytes, obfuscated_key.bytes,
               sizeof(obfuscated_key));
        m_key_placeholder.encryption = TDEA;
        memcpy(loader_start, &m_key_placeholder,
               sizeof(struct key_placeholder));
    }
    return 0;
}

static void *inject_rt_info(void *loader, struct runtime_info *rt_info,
                            size_t old_size, size_t *new_size) {
    size_t rt_info_size = sizeof(struct runtime_info) +
                          sizeof(struct trap_point) * rt_info->ntraps +
                          sizeof(struct function) * rt_info->nfuncs;
    void *loader_rt_info = malloc(old_size + rt_info_size);
    info(
        "sizeof runtime_info %u, sizeof trap_point %u, sizeof function:%u the "
        "rt_info_size : %u",
        sizeof(struct runtime_info), sizeof(struct trap_point),
        sizeof(struct function), rt_info_size);
    info("rt_info->ntraps : %u, rt_info->nfuncs : %u", rt_info->ntraps,
         rt_info->nfuncs);
    // obf_deobf_rt_info(rt_info);
    info("the runtime_info address : %p", loader_rt_info + old_size);
    memcpy(loader_rt_info, loader, old_size);
    *new_size = old_size + rt_info_size;

    info("injected runtime info into loader (old size: %u new size: %u)",
         old_size, *new_size);

    /* subtract sizeof(struct runtime_info) here to ensure we overwrite the
     * non flexible-array portion of the struct that the linker actually puts
     * inG the code. */
    memcpy(loader_rt_info + old_size - sizeof(struct runtime_info), rt_info,
           rt_info_size);

    return loader_rt_info;
}

/* Removes everything not needed for program execution from the binary, note
 * that this differs from the standard system strip utility which just discards
 * the .symtab section. This strips everything not covered by a segment as
 * described in the program header table to ensure absolutely no debugging
 * information is left over to aid a reverse engineer. */
static int full_strip(struct mapped_elf *elf) {
    Elf64_Phdr *curr_phdr = elf->phdr_tbl;
    size_t new_size = 0;
    info("stripping input binary");

    /* Calculate minimum size needed to contain all program headers */
    for (int i = 0; i < elf->ehdr->e_phnum; i++) {
        size_t seg_end = curr_phdr->p_offset + curr_phdr->p_filesz;
        if (seg_end > new_size)
            new_size = seg_end;
        curr_phdr++;
    }

    if (elf->ehdr->e_shoff >= new_size) {
        elf->ehdr->e_shoff = 0;
        elf->ehdr->e_shnum = 0;
        elf->ehdr->e_shstrndx = 0;
    } else {
        info("warning: could not strip out all section info from binary");
        info("output binary may be corrupt!");
    }

    void *new_elf = malloc(new_size);
    CK_NEQ_PERROR(new_elf, NULL);
    memcpy(new_elf, elf->start, new_size);
    free(elf->start);
    parse_mapped_elf(new_elf, new_size, elf);

    return 0;
}

int apply_outer_compression(struct mapped_elf *elf, void *loader_start) {
    if (compression_algorithm == ZSTD) {
        printf("[Packer] Using ZSTD Compressing...\n");
        uint8_t *input = elf->start;
        int size = elf->size;
        hexdump(input, size);
        uint32_t compressedSize = ZSTD_compressBound(size);
        uint8_t *compressedBlob = malloc(compressedSize);
        compressedSize =
            ZSTD_compress(compressedBlob, compressedSize, input, size, 1);
        if (compressedBlob) {
            printf("Compressed: %d to %d\n", size, compressedSize);
        } else {
            printf("Nope, we screwed it\n");
            return;
        }
        memcpy(elf->start, compressedBlob, compressedSize);
        elf->size = compressedSize;
        struct key_placeholder m_key_placeholder =
            *(struct key_placeholder *)loader_start;
        m_key_placeholder.compression = ZSTD;
        memcpy(loader_start, &m_key_placeholder,
               sizeof(struct key_placeholder));
    } else if (compression_algorithm == LZO) {
        printf("[Packer] Using LZO Compressing...\n");
        int r;
        lzo_uint in_len;
        lzo_uint out_len;
        if (lzo_init() != LZO_E_OK) {
            printf("internal error - lzo_init() failed !!!\n");
            printf(
                "(this usually indicates a compiler bug - try "
                "recompiling\nwithout optimizations, and enable '-DLZO_DEBUG' "
                "for diagnostics)\n");
            return 3;
        }
        in_len = elf->size;
        out_len = in_len + in_len / 16 + 64 + 3;

        const unsigned char *in = elf->start;
        uint8_t *out = malloc(out_len);

        r = lzo1x_1_compress(in, in_len, out, &out_len, wrkmem);
        if (r == LZO_E_OK) {
            printf("compressed %lu bytes into %lu bytes\n",
                   (unsigned long)in_len, (unsigned long)out_len);
        } else {
            /* this should NEVER happen */
            printf("internal error - compression failed: %d\n", r);
            return 2;
        }
        /* check for an incompressible block */
        if (out_len >= in_len) {
            printf("This block contains incompressible data.\n");
            return 0;
        }
        memcpy(elf->start, out, out_len);
        free(out);
        elf->size = out_len;
        struct key_placeholder m_key_placeholder =
            *(struct key_placeholder *)loader_start;
        m_key_placeholder.compression = LZO;
        memcpy(loader_start, &m_key_placeholder,
               sizeof(struct key_placeholder));
    } else if (compression_algorithm == LZMA) {
        printf("[Packer] Using LZMA Compressing...\n");
        uint8_t *input = elf->start;
        int size = elf->size;
        hexdump(input, size);
        uint32_t compressedSize;
        uint8_t *compressedBlob = lzmaCompress(input, size, &compressedSize);
        if (compressedBlob) {
            printf("Compressed: %d to %d\n", size, compressedSize);
            // hexdump(compressedBlob, compressedSize);
        } else {
            printf("Nope, we screwed it\n");
            return;
        }
        memcpy(elf->start, compressedBlob, compressedSize);
        elf->size = compressedSize;
        struct key_placeholder m_key_placeholder =
            *(struct key_placeholder *)loader_start;
        m_key_placeholder.compression = LZMA;
        memcpy(loader_start, &m_key_placeholder,
               sizeof(struct key_placeholder));
    } else if (compression_algorithm == UCL) {
        printf("[Packer] Using UCL Compressing...\n");
        int level = 5;
        uint8_t *input = elf->start;
        uint32_t size = elf->size;
        uint32_t compressedSize = size + size / 8 + 256;
        uint8_t *compressedBlob = ucl_malloc(compressedSize);
        if (ucl_init() != UCL_E_OK) {
            ks_printf(1, "internal error - ucl_init() failed !!!\n");
            return 1;
        }
        int r = ucl_nrv2b_99_compress(input, size, compressedBlob,
                                      &compressedSize, NULL, level, NULL, NULL);
        if (r == UCL_E_OUT_OF_MEMORY) {
            ks_printf(1, "out of memory in compress\n");
            return 3;
        }
        if (r == UCL_E_OK)
            ks_printf(1, "compressed %d bytes into %d bytes\n",
                      (unsigned long)size, (unsigned long)compressedSize);

        /* check for an incompressible block */
        if (compressedSize >= size) {
            ks_printf(1, "This block contains incompressible data.\n");
            return 0;
        }
        memcpy(elf->start, compressedBlob, compressedSize);
        ucl_free(compressedBlob);
        elf->size = compressedSize;
        struct key_placeholder m_key_placeholder =
            *(struct key_placeholder *)loader_start;
        m_key_placeholder.compression = UCL;
        memcpy(loader_start, &m_key_placeholder,
               sizeof(struct key_placeholder));
    }
    return 0;
}

int hexToDec(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else {
        return -1;
    }
}

void shuffle(unsigned char *arr, int n, unsigned char swap_infos[]) {
    unsigned char index[n];
    get_random_bytes(index, n);

    // 洗牌算法
    for (int i = n - 1; i >= 0; i--) {
        int j = index[i] % (i + 1);
        unsigned char temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
        swap_infos[i] = j;
    }
}

void reverse_shuffle(unsigned char *arr, int n,
                     const unsigned char swap_infos[]) {
    for (int k = 0; k < n; k++) {
        unsigned char temp = arr[k];
        arr[k] = arr[swap_infos[k]];
        arr[swap_infos[k]] = temp;
    }
}

int hexStringToByteArray(const char *hexString, unsigned char *byteArray, int byteArraySize) {
    int count = 0;
    const char *pos = hexString;

    // 转换16进制字符串为字节数组
    while (count < byteArraySize && sscanf(pos, "%2hhx", &byteArray[count]) == 1) {
        pos += 2;
        count++;
    }

    return count; // 返回转换的字节数
}

int main(int argc, char *argv[]) {
    char *input_path, *output_path;
    int layer_one_only = 0;
    int c;
    int ret;
    const char* puf_path;
    input_path = argv[1];
    encryption_algorithm = atoi(argv[2]);
    pub_algorithm = atoi(argv[3]);
    compression_algorithm = atoi(argv[4]);
    output_path = argv[5];
    int mac_enable = atoi(argv[6]);
    const char* mac_path = argv[7];
    int proctect_mode = atoi(argv[8]);

    // 创建字节数组
    const int serial_length = 39;
    unsigned char puf_key[serial_length];
    memset(puf_key, 0, serial_length);
    unsigned char puf_value[serial_length];
    memset(puf_value, 0, serial_length);
    printf("[STATE] node:2 ; message:获取密钥\n");
    if (proctect_mode == 1) {
        puf_path = argv[9];
        FILE *file = fopen(puf_path, "r");
        if (file == NULL) {
            perror("Failed to open file");
            return EXIT_FAILURE;
        }
        char line1[256];
        char line2[256];
        char line3[256];

        // 读取第一行
        if (fgets(line1, sizeof(line1), file) == NULL) {
            perror("Failed to read line 1");
            fclose(file);
            return EXIT_FAILURE;
        }

        // 读取第二行
        if (fgets(line2, sizeof(line2), file) == NULL) {
            perror("Failed to read line 2");
            fclose(file);
            return EXIT_FAILURE;
        }

        // 读取第三行
        if (fgets(line3, sizeof(line3), file) == NULL) {
            perror("Failed to read line 3");
            fclose(file);
            return EXIT_FAILURE;
        }

        printf("[STATE] node:1 ; message:PUF交互\n");
        // 打印读取的内容
        printf("Line 1: %s", line1);
        printf("Line 2: %s", line2);
        printf("Line 3: %s", line3);

        // 关闭文件
        fclose(file);
        

        // 转换字符串为字节数组
        int convertedCount2 = hexStringToByteArray(line2, puf_key, serial_length);
        int convertedCount3 = hexStringToByteArray(line3, puf_value, serial_length);

        // 检查转换的结果
        if (convertedCount2 != serial_length || convertedCount3 != serial_length) {
            printf("Conversion error\n");
            return EXIT_FAILURE;
        }
    }
    // 是否使用PUF
    if (proctect_mode == 1)
        memcpy(serial_key, puf_value + 4, 16);
    else
        get_random_bytes(serial_key, 16);
    /* Read ELF to be packed */
    info("reading input binary %s", input_path);
    struct mapped_elf elf;
    ret = read_input_elf(input_path, &elf);
    if (ret == -1) {
        err("error reading input ELF: %s", strerror(errno));
        return -1;
    }

    /* Select loader to use based on the presence of the -n flag. Use the
     * no-runtime version if we're only applying layer 1 or the runtime version
     * if we're applying layer 1 and 2 encryption.
     */
    ks_malloc_init();
    void *loader;
    size_t loader_size;
    // 是否需要对内层加密
    if (!layer_one_only) {
        struct runtime_info *rt_info = NULL;
        printf("[STATE] node:5 ; message:函数加密\n");
        ret = apply_inner_encryption(&elf, &rt_info);
        if (ret == -1) {
            err("could not apply inner encryption");
            return -1;
        }

        loader = inject_rt_info(GENERATED_LOADER_RT, rt_info,
                                sizeof(GENERATED_LOADER_RT), &loader_size);
    } else {
        info("not applying inner encryption and omitting runtime (-n)");

        loader = GENERATED_LOADER_NO_RT;
        loader_size = sizeof(GENERATED_LOADER_NO_RT);
    }

    uint64_t sections[4] = {elf.data->sh_offset, elf.data->sh_size,
                        elf.text->sh_offset, elf.text->sh_size};
    printf("[STATE] node:3 ; message:段加密\n");
    ret = apply_sections_encryption(&elf, sections);
    printf("[STATE] node:6 ; message:压缩\n");

    ret = apply_outer_compression(&elf, loader);
    if (ret != 0) {
        printf("[compression]: something wrong!\n");
    }
    printf("[STATE] node:4 ; message:整体加密\n");
    /* Apply outer encryption */
    ret = apply_outer_encryption(&elf, loader, loader_size);
    if (ret == -1) {
        err("could not apply outer encryption");
        return -1;
    }

    if (pub_algorithm == RSA) {
        printf("Using RSA encrypting...\n");
        struct key_placeholder place_holder = *((struct key_placeholder *)loader);
        uint8_t seed[32];
        yarrowInit(&yarrowContext);
        yarrowSeed(&yarrowContext, seed, sizeof(seed));

        RsaPublicKey publicKey;
        RsaPrivateKey privateKey;
        rsaInitPublicKey(&publicKey);
        rsaInitPrivateKey(&privateKey);
        rsaGenerateKeyPair(&yarrowPrngAlgo, &yarrowContext, 1024, 65537, &privateKey, &publicKey);
        rsaPrivateKeyFormat(&privateKey, place_holder.my_rsa_key, &place_holder.rsa_key_args_len);
        // 用Rsa加密对称密钥
        char cipher[128];
        int cipher_len;
        int t = rsaesPkcs1v15Encrypt(&yarrowPrngAlgo, &yarrowContext, &publicKey, 
                            place_holder.bytes, 117, cipher, &cipher_len); 
        memcpy(place_holder.bytes, cipher, 128);
        place_holder.pub_encryption = RSA;
        memcpy(loader, &place_holder, sizeof(struct key_placeholder));
    } else if (pub_algorithm == ECC) {
        printf("Using ECC encrypting...\n");
        struct key_placeholder place_holder = *((struct key_placeholder *)loader);
        uint8_t pub_key[ECC_KEYSIZE];
        uint8_t prv_key[ECC_KEYSIZE];
        uint8_t cipher[128];
        ecc_init_keys(pub_key,prv_key);
        uint32_t out_size;
        ecc_encrypt(pub_key, place_holder.bytes, 128, cipher, &out_size);
        memcpy(place_holder.bytes, cipher, 128);
        memcpy(place_holder.my_ecc_key, prv_key, ECC_KEYSIZE);
        place_holder.pub_encryption = ECC;
        memcpy(loader, &place_holder, sizeof(struct key_placeholder));
    }

    struct key_placeholder place_holder = *((struct key_placeholder *)loader);
    strcpy(place_holder.name, argv[5]);
    memcpy(loader, &place_holder, sizeof(struct key_placeholder));

    char mac_array[10][18];
    memset(mac_array, 0, 180);
    if (mac_enable == 1) {
        // 从本地文件中读取MAC地址
        int mac_fd = open(mac_path, O_RDONLY);
        if (mac_fd <= 0) {
            printf("mac_fd : %d\n", mac_fd);
            printf("本地未找到MAC地址列表文件\n");
            return -1;
        }
        int mac_idx = 0;
        while (mac_idx < 10 && (ret = read(mac_fd, mac_array[mac_idx], 18)) > 0) {
            mac_idx++;
        }
        close(mac_fd);
    } else {
        mac_array[0][0] = 'P';
    }
    unsigned char swap_infos[SERIAL_SIZE];
    shuffle(puf_key, SERIAL_SIZE, swap_infos);
    /* Write output ELF */
    FILE *output_file;
    CK_NEQ_PERROR(output_file = fopen(output_path, "w"), NULL);
    printf("[STATE] node:7 ; message:加壳\n");

    ret = produce_output_elf(output_file, &elf, loader, loader_size);
    // 写入sections, swap_infos, puf_key
    fwrite(sections, sizeof(sections), 1, output_file);
    fwrite(swap_infos, sizeof(swap_infos), 1, output_file);
    // 如果不使用PUF，把serial_key拷贝到puf_key中
    if (proctect_mode == 0) {
        memcpy(puf_key, serial_key, 16);
    }
    fwrite(puf_key, sizeof(puf_key), 1, output_file);
    fwrite(mac_array, sizeof(mac_array), 1, output_file);

    if (ret == -1) {
        err("could not produce output ELF");
        return -1;
    }

    CK_NEQ_PERROR(fclose(output_file), EOF);
    CK_NEQ_PERROR(
        chmod(output_path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH),
        -1);

    info("output ELF has been written to %s", output_path);
    printf("[STATE] node:8 ; message:成功\n");
    ks_malloc_deinit();
    return 0;
}

/*
    持久化方案：
    检测当前文件夹有没有program文件，如果没有则从packed_bin中读取然后写入磁盘继续执行，如果有的话，
    就拷贝到packed_bin中正常执行

    program 文件的结构： 加密的文件本体  shuffed_arr  swap_infos sections 四个部分组成
    注意事项： 加壳过程中给app segment多分配一点空间用来存储其他的信息（暂定128字节）
*/

/*
    多MAC地址方案：
    同持久化方案类似，开辟一块内存空间，存储MAC地址，在运行时遍历/sys/class/net/中所有的网卡的address，看是否在这些
    MAC地址中，选择运行或者终止运行

    program 文件的结构： 加密的文件本体  shuffed_arr  swap_infos sections mac_array 五个部分组成
    * 注意需要修改elf中的filesz
*/
