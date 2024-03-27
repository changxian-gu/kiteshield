#include <elf.h>

#include "common/include/defs.h"
#include "common/include/obfuscation.h"
#include "loader/include/termios.h"
#include "common/include/random.h"
#include "loader/include/anti_debug.h"
#include "loader/include/debug.h"
#include "loader/include/elf_auxv.h"
#include "loader/include/string.h"
#include "loader/include/syscalls.h"
#include "loader/include/types.h"

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

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGE_MASK (~0 << PAGE_SHIFT)

#define PAGE_ALIGN_DOWN(ptr) ((ptr) & PAGE_MASK)
#define PAGE_ALIGN_UP(ptr) ((((ptr)-1) & PAGE_MASK) + PAGE_SIZE)
#define PAGE_OFFSET(ptr) ((ptr) & ~(PAGE_MASK))

unsigned char serial_key[16];

// 编译的时候存的key其实还没有初始化，在packer里面用混淆后的key覆盖了
// .text段是64位对齐的，key存储的位置偏移是b0，.text段会自动对齐到0xc0（key的长度小于等于16字节）,
// 0x100(如果key的长度大于16字节)
struct key_placeholder obfuscated_key
    __attribute__((aligned(1), section(".key")));

// struct aes_key obfuscated_key __attribute__((aligned(1), section(".key")));

static void *map_load_section_from_mem(void *elf_start, Elf64_Phdr phdr) {
  uint64_t base_addr =
      ((Elf64_Ehdr *)elf_start)->e_type == ET_DYN ? DYN_PROG_BASE_ADDR : 0;

  /* Same rounding logic as in map_load_section_from_fd, see comment below.
   * Note that we don't need a separate mmap here for bss if memsz > filesz
   * as we map an anonymous region and copy into it rather than mapping from
   * an fd (ie. we can just not touch the remaining space and it will be full
   * of zeros by default).
   */
  void *addr = sys_mmap((void *)(base_addr + PAGE_ALIGN_DOWN(phdr.p_vaddr)),
                        phdr.p_memsz + PAGE_OFFSET(phdr.p_vaddr), PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  DIE_IF((long)addr < 0, "mmap failure");
  DEBUG_FMT("mapping LOAD section from packed binary at %p", addr);

  /* Copy data from the packed binary */
  char *curr_addr = addr;
  for (Elf64_Off f_off = PAGE_ALIGN_DOWN(phdr.p_offset);
       f_off < phdr.p_offset + phdr.p_filesz; f_off++) {
    (*curr_addr++) = *((char *)elf_start + f_off);
  }

  /* Set correct permissions (change from -w-) */
  int prot = (phdr.p_flags & PF_R ? PROT_READ : 0) |
             (phdr.p_flags & PF_W ? PROT_WRITE : 0) |
             (phdr.p_flags & PF_X ? PROT_EXEC : 0);
  DIE_IF(sys_mprotect(addr, phdr.p_memsz + PAGE_OFFSET(phdr.p_vaddr), prot) < 0,
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
  void *addr =
      sys_mmap((void *)(base_addr + PAGE_ALIGN_DOWN(phdr.p_vaddr)),
               phdr.p_filesz + PAGE_OFFSET(phdr.p_vaddr), prot,
               MAP_PRIVATE | MAP_FIXED, fd, PAGE_ALIGN_DOWN(phdr.p_offset));
  DIE_IF((long)addr < 0, "mmap failure while mapping load section from fd");

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
        (void *)PAGE_ALIGN_UP(base_addr + phdr.p_vaddr + phdr.p_filesz);

    if (bss_already_mapped < (phdr.p_memsz - phdr.p_filesz)) {
      size_t extra_space_needed =
          (size_t)(phdr.p_memsz - phdr.p_filesz) - bss_already_mapped;

      void *extra_space =
          sys_mmap(extra_pages_start, extra_space_needed, prot,
                   MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

      DIE_IF((long)extra_space < 0,
             "mmap failure while mapping extra space for static vars");

      DEBUG_FMT("mapped extra space for static data (.bss) at %p len %u",
                extra_space, extra_space_needed);
    }

    /* While any extra pages mapped will be zeroed by default, this is not the
     * case for the part of the original page corresponding to
     * bss_already_mapped (it will contain junk from the file) so we zero it
     * here.  */
    uint8_t *bss_ptr = (uint8_t *)(base_addr + phdr.p_vaddr + phdr.p_filesz);
    if (!(prot & PROT_WRITE)) {
      DIE_IF(sys_mprotect(bss_ptr, bss_already_mapped, PROT_WRITE) < 0,
             "mprotect error");
    }

    for (size_t i = 0; i < bss_already_mapped; i++)
      *(bss_ptr + i) = 0;

    if (!(prot & PROT_WRITE)) {
      DIE_IF(sys_mprotect(bss_ptr, bss_already_mapped, prot) < 0,
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

  *entry = ehdr.e_type == ET_EXEC
               ? (void *)ehdr.e_entry
               : (void *)(DYN_INTERP_BASE_ADDR + ehdr.e_entry);
  int base_addr_set = 0;
  for (int i = 0; i < ehdr.e_phnum; i++) {
    Elf64_Phdr curr_phdr;

    off_t lseek_res =
        sys_lseek(interp_fd, ehdr.e_phoff + i * sizeof(Elf64_Phdr), SEEK_SET);
    DIE_IF(lseek_res < 0, "lseek failure while mapping interpreter");

    size_t read_res = sys_read(interp_fd, &curr_phdr, sizeof(curr_phdr));
    DIE_IF(read_res < 0, "read failure while mapping interpreter");

    /* We shouldn't be dealing with any non PT_LOAD segments here */
    if (curr_phdr.p_type != PT_LOAD)
      continue;

    void *addr =
        map_load_section_from_fd(interp_fd, curr_phdr, ehdr.e_type == ET_EXEC);

    if (!base_addr_set) {
      DEBUG_FMT("interpreter base address is %p", addr);
      *interp_base = addr;
      base_addr_set = 1;
    }
  }

  DIE_IF(sys_close(interp_fd) < 0, "could not close interpreter binary");
}

static void *map_elf_from_mem(void *elf_start, void **interp_entry,
                              void **interp_base) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_start;

  int load_addr_set = 0;
  void *load_addr = NULL;

  Elf64_Phdr *curr_phdr = elf_start + ehdr->e_phoff;
  Elf64_Phdr *interp_hdr = NULL;
  for (int i = 0; i < ehdr->e_phnum; i++) {
    void *seg_addr = NULL;

    if (curr_phdr->p_type == PT_LOAD)
      seg_addr = map_load_section_from_mem(elf_start, *curr_phdr);
    else if (curr_phdr->p_type == PT_INTERP)
      interp_hdr = curr_phdr;

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
  while (*curr_ent != label && *curr_ent != AT_NULL)
    curr_ent += 2;
  DIE_IF_FMT(*curr_ent == AT_NULL, "could not find auxv entry %d", label);

  *(++curr_ent) = value;
  DEBUG_FMT("replaced auxv entry %llu with value %llu (0x%p)", label, value,
            value);
}

static void setup_auxv(void *argv_start, void *entry, void *phdr_addr,
                       void *interp_base, unsigned long long phnum) {
  unsigned long long *auxv_start = argv_start;

#define ADVANCE_PAST_NEXT_NULL(ptr)                                            \
  while (*(++ptr) != 0);                                                       \
  ptr++;

  ADVANCE_PAST_NEXT_NULL(auxv_start) /* argv */
  ADVANCE_PAST_NEXT_NULL(auxv_start) /* envp */

  DEBUG_FMT("taking %p as auxv start", auxv_start);
  replace_auxv_ent(auxv_start, AT_ENTRY, (unsigned long long)entry);
  replace_auxv_ent(auxv_start, AT_PHDR, (unsigned long long)phdr_addr);
  replace_auxv_ent(auxv_start, AT_BASE, (unsigned long long)interp_base);
  replace_auxv_ent(auxv_start, AT_PHNUM, phnum);
}

static void decrypt_packed_bin_aes(
        void *packed_bin_start,
        size_t packed_bin_size,
        struct aes_key *key) {

    DEBUG_FMT("AES decrypting binary with key %s", STRINGIFY_KEY(key));
    DEBUG_FMT("the packed_bin_size : %u\n", packed_bin_size);
    DEBUG_FMT("the address of packed_bin_start: %p\n", packed_bin_start);

    // DEBUG_FMT("open serial %d\n", serial_communication());
    // 只解密密钥整数倍的长度的密文
    unsigned long t = packed_bin_size - packed_bin_size % sizeof(struct aes_key);
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
        size_t packed_bin_size,
        struct des_key *key) {

    DEBUG_FMT("DES decrypting binary with key %s", STRINGIFY_KEY(key));
    DEBUG_FMT("the packed_bin_size : %u\n", packed_bin_size);
    DEBUG_FMT("the address of packed_bin_start: %p\n", packed_bin_start);

    // DEBUG_FMT("open serial %d\n", serial_communication());

    unsigned long t = packed_bin_size - packed_bin_size % sizeof(struct des_key);
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
        size_t packed_bin_size,
        struct des3_key *key) {

    DEBUG_FMT("DES3 decrypting binary with key %s", STRINGIFY_KEY(key));
    DEBUG_FMT("the packed_bin_size : %u\n", packed_bin_size);
    DEBUG_FMT("the address of packed_bin_start: %p\n", packed_bin_start);

    // DEBUG_FMT("open serial %d\n", serial_communication());

    unsigned long t = packed_bin_size - packed_bin_size % sizeof(struct des3_key);
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
        size_t packed_bin_size,
        struct rc4_key *key) {

    DEBUG_FMT("RC4 decrypting binary with key %s", STRINGIFY_KEY(key));
    DEBUG_FMT("the packed_bin_size : %u\n", packed_bin_size);
    DEBUG_FMT("the address of packed_bin_start: %p\n", packed_bin_start);

    // DEBUG_FMT("open serial %d\n", serial_communication());

    unsigned long t = packed_bin_size;
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
        new_key->bytes[key_index] ^= loader_bin[loader_index];
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
        new_key->bytes[key_index] ^= loader_bin[loader_index];
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
        new_key->bytes[key_index] ^= loader_bin[loader_index];
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
        new_key->bytes[key_index] ^= loader_bin[loader_index];
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
        new_key->bytes[key_index] ^= loader_bin[loader_index];
        loader_index++;
        key_index = (key_index + 1) % sizeof(struct des3_key);
}

// /* Convenience wrapper around obf_deobf_outer_key to automatically pass in
//  * correct loader code offsets. */
// void loader_outer_key_deobfuscate(struct rc4_key *old_key,
//                                   struct rc4_key *new_key) {
//   /* "our" EHDR (ie. the one in the on-disk binary that was run) */
//   Elf64_Ehdr *us_ehdr = (Elf64_Ehdr *)LOADER_ADDR;

//   /* The PHDR in our binary corresponding to the loader (ie. this code) */
//   Elf64_Phdr *loader_phdr = (Elf64_Phdr *)(LOADER_ADDR + us_ehdr->e_phoff);

//   /* The first ELF segment (loader code) includes the ehdr and two phdrs,
//    * adjust loader code start and size accordingly */
//   size_t hdr_adjust = sizeof(Elf64_Ehdr) + (2 * sizeof(Elf64_Phdr));

//   void *loader_start = (void *)loader_phdr->p_vaddr + hdr_adjust;
//   size_t loader_size = loader_phdr->p_memsz - hdr_adjust;

//   obf_deobf_outer_key(old_key, new_key, loader_start, loader_size);
// }

int hexToDec(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else {
        return -1;
    }
}

void printBytes1(const char* msg, unsigned long len) {
    for (int i = 0; i < len; i++) {
        ks_printf(1, "0x%x(", (unsigned char)(msg[i]));
        ks_printf(1, "%d) ", (unsigned char)(msg[i]));
    }
    ks_printf(1, "%s", "\n");
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

static int get_key(void *buf, size_t len) {
    unsigned char *p = (unsigned char *)buf;
    int index = 0;
    for (int i = 0; i < len; i++) {
        p[index++] = serial_key[i % 16];
    }
    return 0;
}

static void encrypt_memory_range_aes(struct aes_key *key, void *start,
                                     size_t len) {
    size_t key_len = sizeof(struct aes_key);
    DEBUG_FMT("aes key_len : %d\n", key_len);
    unsigned char *out = (unsigned char *)ks_malloc((len) * sizeof(char));
    DEBUG_FMT("before enc, len : %d\n", len);
    // 使用DES加密后密文长度可能会大于明文长度怎么办?
    // 目前解决方案，保证加密align倍数的明文长度，有可能会剩下一部分字节，不做处理
    unsigned long actual_encrypt_len = len - len % key_len;
    DEBUG_FMT("actual encrypt len : %d\n", actual_encrypt_len);
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
    DEBUG_FMT("rc4 key_len : %d\n", key_len);
    unsigned char *out = (unsigned char *)ks_malloc((len) * sizeof(char));
    DEBUG_FMT("before enc, len : d\n", len);
    unsigned long actual_encrypt_len = len;
    DEBUG_FMT("actual encrypt len : d\n", actual_encrypt_len);
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
    DEBUG_FMT("des key_len : %d\n", key_len);
    unsigned char *out = (unsigned char *)ks_malloc(len);
    DEBUG_FMT("before enc, len : d\n", len);
    unsigned long actual_encrypt_len = len - len % key_len;
    DEBUG_FMT("actual encrypt len : d\n", actual_encrypt_len);
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
    DEBUG_FMT("des3 key_len : %d\n", key_len);
    unsigned char *out = (unsigned char *)ks_malloc(len);
    DEBUG_FMT("before enc, len : d\n", len);
    unsigned long actual_encrypt_len = len - len % key_len;
    DEBUG_FMT("actual encrypt len : d\n", actual_encrypt_len);
    if (actual_encrypt_len == 0)
        return;
    Des3Context des3_context;
    des3Init(&des3_context, key->bytes, key_len);
    ecbEncrypt(DES3_CIPHER_ALGO, &des3_context, start, out, actual_encrypt_len);
    memcpy(start, out, actual_encrypt_len);
    des3Deinit(&des3_context);
}

void *load(void *entry_stacktop) {
    char* prog_name = obfuscated_key.name;
    // 拷贝一个临时文件
    char rand_tmp_filename[25];
    strncpy(rand_tmp_filename, "/tmp/", 5);
    get_random_bytes(rand_tmp_filename + 6, 19);
    for (int i = 5; i < 24; i++) {
        rand_tmp_filename[i] = (rand_tmp_filename[i] & 0xFF) % 26 + 65;
    }
    rand_tmp_filename[24] = '\0';
    DEBUG_FMT("%s\n", rand_tmp_filename);

    int pid = sys_fork();
    int wstatus;
    if (pid == 0) {
        const char *shell = "/bin/sh";
        char true_shell[200] = "/bin/cp ";
        int s_idx = strlen(true_shell);
        strncpy(true_shell + s_idx, prog_name, strlen(prog_name));
        s_idx += strlen(prog_name);
        true_shell[s_idx++] = ' ';

        strncpy(true_shell + s_idx, rand_tmp_filename, strlen(rand_tmp_filename));
        s_idx += strlen(rand_tmp_filename);
        char *const args[] = {"/bin/sh", "-c", true_shell, NULL};
        char *const env[] = {NULL};
        sys_exec(shell, args, env);
    } else {
        sys_wait4(pid, &wstatus, __WALL);
    }

    
    ks_malloc_init();
    // 反调试功能, 具体怎么反调试的?
    if (antidebug_proc_check_traced())
        DIE(TRACED_MSG);

    /* As per the SVr4 ABI */
    /* int argc = (int) *((unsigned long long *) entry_stacktop); */
    // char* 类型的指针
    char **argv = ((char **)entry_stacktop) + 1;
    enum Encryption encryption_algorithm = AES;
    enum Compression compression_algorithm = ZSTD;
    // get the alogorithm type
    encryption_algorithm = obfuscated_key.encryption;
    compression_algorithm = obfuscated_key.compression;

    /* "our" EHDR (ie. the one in the on-disk binary that was run) */
    // hello_world_pak
    Elf64_Ehdr *us_ehdr = (Elf64_Ehdr *)LOADER_ADDR;

    /* The PHDR in our binary corresponding to the loader (ie. this code) */
    Elf64_Phdr *loader_phdr = (Elf64_Phdr *)(LOADER_ADDR + us_ehdr->e_phoff);

    /* The PHDR in our binary corresponding to the encrypted app */
    Elf64_Phdr *packed_bin_phdr = loader_phdr + 1;

    /* The EHDR of the actual application to be run (encrypted until
     * decrypt_packed_bin is called)
     */
    Elf64_Ehdr *packed_bin_ehdr = (Elf64_Ehdr *)(packed_bin_phdr->p_vaddr);
    // 去掉辅助变量的位置，为后面解密与解压提供正确的文件大小
    packed_bin_phdr->p_filesz -= PROGRAM_AUX_LEN;
    // DEBUG_FMT("obkey %s", STRINGIFY_KEY(&obfuscated_key));

    unsigned char swap_infos[SERIAL_SIZE];
    unsigned char old_puf_key[SERIAL_SIZE];
    uint64_t sections[4];
    char mac_array[10][18];
    // 获取program中的部分信息
    uint8_t* tmp_p = (uint8_t*)packed_bin_phdr->p_vaddr + packed_bin_phdr->p_filesz;
    memcpy(sections, tmp_p, sizeof(sections));
    tmp_p += sizeof(sections);
    // 与非PUF唯一区别为：密钥换成了一个替换数组和激励
    memcpy(swap_infos, tmp_p, SERIAL_SIZE);
    tmp_p += SERIAL_SIZE;
    memcpy(old_puf_key, tmp_p, SERIAL_SIZE);
    tmp_p += SERIAL_SIZE;
    // 读取MAC地址
    memcpy(mac_array, tmp_p, sizeof(mac_array));

    // 是否使用PUF
    int protect_mode = 1;
    if (old_puf_key[38] == 0)
        protect_mode = 0;

    /*
        读取mac.txt文件，看其中的地址是否在白名单mac_array中
        check mac begin
    */
    int mac_enable = 1;
    if (mac_array[0][0] == 'P')
        mac_enable = 0;
    if (mac_enable) {
        // 新建一个子进程用来获取本机上的所有的MAC地址，写入mac.txt文件中
        int pid = sys_fork();
        int wstatus;
        if (pid == 0) {
            const char *shell = "/bin/sh";
            char *const args[] = {"/bin/sh", "-c", "/bin/cat /sys/class/net/*/address > /tmp/kt_mac.txt", NULL};
            char *const env[] = {NULL};
            sys_exec(shell, args, env);
        } else {
            sys_wait4(pid, &wstatus, __WALL);
        }

        int mac_fd = sys_open("/tmp/kt_mac.txt", O_RDONLY, 0);
        if (mac_fd <= 0) {
            DEBUG("获取MAC地址错误!");
            return 0;
        }
        char mac_buff[18];
        int mac_valid = 0;
        int ret;
        while ((ret = sys_read(mac_fd, mac_buff, 18)) > 0) {
            if (strncmp("00:00:00:00:00:00", mac_buff, 17) == 0)
                continue;
            if (mac_valid == 1)
                break;
            for (int i = 0; i < 10; i++) {
                if (strncmp(mac_array[i], mac_buff, 17) == 0) {
                    mac_valid = 1;
                    break;
                }
            }
        }
        sys_close(mac_fd);
        if (mac_valid == 0) {
            DEBUG("MAC地址非法, 正在退出");
            return 0;
        }
    }
    /*
        check mac end
    */

    ser_data snd_data, rec_data;
    int usb_fd;
    if (protect_mode == 1) {
        char *device = "/dev/ttyUSB0";
        usb_fd = sys_open(device, O_RDWR | O_NOCTTY | O_NDELAY, 0777);
        if (usb_fd < 0) {
            DEBUG_FMT("%s open failed\r\n", device);
            sys_close(usb_fd);
            sys_exit(-1);
        } else {
            DEBUG("connection device /dev/ttyUSB0 successful");
        }
        reverse_shuffle(old_puf_key, SERIAL_SIZE, swap_infos);

        // 发送之前初始化
        memcpy(snd_data.data_buf, old_puf_key, SERIAL_SIZE);
        term_init(usb_fd);
        snd_data.ser_fd = usb_fd;
        rec_data.ser_fd = usb_fd;

        send(&snd_data);
        receive(&rec_data);
        get_serial_key(serial_key, &rec_data);
    } else {
        memcpy(serial_key, old_puf_key, 16);
    }

    /* The first ELF segment (loader code) includes the ehdr and two phdrs,
     * adjust loader code start and size accordingly */
    size_t hdr_adjust = sizeof(Elf64_Ehdr) + (2 * sizeof(Elf64_Phdr));
    void *loader_start = (void *)loader_phdr->p_vaddr + hdr_adjust;
    size_t loader_size = loader_phdr->p_memsz - hdr_adjust;

    if (encryption_algorithm == AES) {
        DEBUG("[LOADER] Using AES Decrypting...");
        // 拿到AES的真实KEY
        struct aes_key actual_key;
        get_key(actual_key.bytes, sizeof(actual_key.bytes));
        DEBUG_FMT("realkey %s", STRINGIFY_KEY(&actual_key));
        decrypt_packed_bin_aes((void *)packed_bin_phdr->p_vaddr,
                               packed_bin_phdr->p_filesz, &actual_key);
    } else if (encryption_algorithm == DES) {
        DEBUG("[LOADER] Using DES Decrypting...");
        struct des_key actual_key;
        get_key(actual_key.bytes, sizeof(actual_key.bytes));
        DEBUG_FMT("realkey %s", STRINGIFY_KEY(&actual_key));
        decrypt_packed_bin_des((void *)packed_bin_phdr->p_vaddr,
                               packed_bin_phdr->p_filesz, &actual_key);
    } else if (encryption_algorithm == RC4) {
        DEBUG("[LOADER] Using RC4 Decrypting...");
        struct rc4_key actual_key;
        get_key(actual_key.bytes, sizeof(actual_key.bytes));
        // loader_outer_key_deobfuscate_rc4(&obfuscated_key, &actual_key,
        // loader_start, loader_size);
        DEBUG_FMT("realkey %s", STRINGIFY_KEY(&actual_key));
        decrypt_packed_bin_rc4((void *)packed_bin_phdr->p_vaddr,
                               packed_bin_phdr->p_filesz, &actual_key);
    } else if (encryption_algorithm == TDEA) {
        DEBUG("[LOADER] Using TDEA Decrypting...");
        struct des3_key actual_key;
        get_key(actual_key.bytes, sizeof(actual_key.bytes));
        DEBUG_FMT("realkey %s", STRINGIFY_KEY(&actual_key));
        decrypt_packed_bin_des3((void *)packed_bin_phdr->p_vaddr,
                                packed_bin_phdr->p_filesz, &actual_key);
    }
    DEBUG("[LOADER] decrypt sucessfully");
    // 把解密后的内容复制一份
    uint8_t* bin_new = ks_malloc(packed_bin_phdr->p_filesz);
    memcpy(bin_new, packed_bin_phdr->p_vaddr, packed_bin_phdr->p_filesz);

    if (compression_algorithm == ZSTD) {
        DEBUG("[LOADER] Using ZSTD Decompressing...");
        uint8_t *compressedBlob = packed_bin_phdr->p_vaddr;
        uint32_t compressedSize = packed_bin_phdr->p_filesz;
        uint32_t decompressedSize = packed_bin_phdr->p_memsz;
        uint8_t *decompressedBlob = ks_malloc(decompressedSize);
        DEBUG_FMT("Decompress: from %d to %d", compressedSize,
                  decompressedSize);
        decompressedSize = ZSTD_decompress(decompressedBlob, decompressedSize,
                                           compressedBlob, compressedSize);
        memcpy((void *)packed_bin_phdr->p_vaddr, decompressedBlob,
               decompressedSize);
    } else if (compression_algorithm == LZO) {
        DEBUG("[LOADER] Using LZO Decompressing...");
        uint8_t *compressedBlob = packed_bin_phdr->p_vaddr;
        uint32_t compressedSize = packed_bin_phdr->p_filesz;
        uint32_t decompressedSize = packed_bin_phdr->p_memsz;
        uint8_t *decompressedBlob = ks_malloc(decompressedSize);
        DEBUG_FMT("Decompress: from %d to %d", compressedSize,
                  decompressedSize);
        int ret = lzo1x_decompress(compressedBlob, compressedSize,
                                   decompressedBlob, &decompressedSize, NULL);
        if (ret != 0) {
            ks_printf(1, "[decompression]: something wrong!\n");
        }
        memcpy((void *)packed_bin_phdr->p_vaddr, decompressedBlob,
               decompressedSize);
        ks_free(decompressedBlob);
        DEBUG("LZO FINISHED");
    } else if (compression_algorithm == LZMA) {
        DEBUG("[LOADER] Using LZMA Decompressing...");
        // lzma decompression
        uint8_t *compressedBlob = packed_bin_phdr->p_vaddr;
        uint32_t compressedSize = packed_bin_phdr->p_filesz;
        uint32_t decompressedSize;
        DEBUG_FMT("Decompress: from %d to %d", compressedSize,
                  decompressedSize);
        uint8_t *decompressedBlob =
            lzmaDecompress(compressedBlob, compressedSize, &decompressedSize);
        if (!decompressedBlob) {
            DEBUG("Nope, we screwed it (part 2)\n");
            return;
        }
        memcpy((void *)packed_bin_phdr->p_vaddr, decompressedBlob,
               decompressedSize);
    } else if (compression_algorithm == UCL) {
        DEBUG("[LOADER] Using UCL Decompressing...");
        uint8_t *compressedBlob = packed_bin_phdr->p_vaddr;
        uint32_t compressedSize = packed_bin_phdr->p_filesz;
        uint32_t decompressedSize = packed_bin_phdr->p_memsz;
        uint8_t *decompressedBlob = ks_malloc(decompressedSize);
        int r =
            ucl_nrv2b_decompress_8(compressedBlob, compressedSize,
                                   decompressedBlob, &decompressedSize, NULL);
        if (r != UCL_E_OK)
            DEBUG("UCL DECOMPRESS ERROR!!!\n");
        memcpy((void *)packed_bin_phdr->p_vaddr, decompressedBlob,
               decompressedSize);
    }
    if (obfuscated_key.pub_encryption == RSA) {
        DEBUG("Using RSA decrypting...");
        // 解析出Rsa私钥，并对对称密钥解密
        RsaPrivateKey private_key;
        rsaInitPrivateKey(&private_key);
        obfuscated_key.rsa_key_args_len.data = obfuscated_key.my_rsa_key;
        rsaPrivateKeyParse(&obfuscated_key.rsa_key_args_len, &private_key);
        uint8_t output[128];
        /*
            C 语言中传参一定要类型相同，尽量避免类型转换，message_len
            定义为int*与形参size_t*不同，会导致严重错误
            如果函数内使用指针解引用message_len,会把后面4个与自己无关的字节包含，导致值错误
        */
        size_t message_len = 117;
        char* cipher = obfuscated_key.bytes;
        int cipher_len = 128;
        error_t error = rsaesPkcs1v15Decrypt(&private_key, cipher, cipher_len, output, 128, &message_len);
        DEBUG_FMT("decrypt error:%d", error);
        memcpy(obfuscated_key.bytes, output,message_len);
    } else if (obfuscated_key.pub_encryption == ECC) {
        DEBUG("Using ECC decrypting...");
        uint8_t output[128];
        int out_size;
        uint8_t prv_key[ECC_KEYSIZE];
        memcpy(prv_key, obfuscated_key.my_ecc_key, ECC_KEYSIZE);
        ecc_decrypt(prv_key, obfuscated_key.bytes, 128, output, &out_size);
        memcpy(obfuscated_key.bytes, output, out_size);
    }
    // text start, text len, data start, data len
    // 段解密
    if (encryption_algorithm == AES) {
        DEBUG("[LOADER] Using AES Decrypting sections...");
        // 拿到AES的真实KEY
        struct aes_key actual_key;
        memcpy(actual_key.bytes, obfuscated_key.bytes, sizeof(actual_key.bytes));     
        // get_key(actual_key.bytes, sizeof(actual_key.bytes));
        decrypt_packed_bin_aes((void *)(packed_bin_phdr->p_vaddr + sections[0]),
                               sections[1], &actual_key);
        decrypt_packed_bin_aes((void *)(packed_bin_phdr->p_vaddr + sections[2]),
                               sections[3], &actual_key);
    } else if (encryption_algorithm == DES) {
        DEBUG("[LOADER] Using DES Decrypting sections...");
        struct des_key actual_key;
        memcpy(actual_key.bytes, obfuscated_key.bytes, sizeof(actual_key.bytes));     
        // get_key(actual_key.bytes, sizeof(actual_key.bytes));
        decrypt_packed_bin_des((void *)(packed_bin_phdr->p_vaddr + sections[0]),
                               sections[1], &actual_key);
        decrypt_packed_bin_des((void *)(packed_bin_phdr->p_vaddr + sections[2]),
                               sections[3], &actual_key);
    } else if (encryption_algorithm == RC4) {
        DEBUG("[LOADER] Using RC4 Decrypting sections...");
        struct rc4_key actual_key;
        memcpy(actual_key.bytes, obfuscated_key.bytes, sizeof(actual_key.bytes));     
        // get_key(actual_key.bytes, sizeof(actual_key.bytes));
        decrypt_packed_bin_rc4((void *)(packed_bin_phdr->p_vaddr + sections[0]),
                               sections[1], &actual_key);
        decrypt_packed_bin_rc4((void *)(packed_bin_phdr->p_vaddr + sections[2]),
                               sections[3], &actual_key);
    } else if (encryption_algorithm == TDEA) {
        DEBUG("[LOADER] Using TDEA Decrypting sections...");
        struct des3_key actual_key;
        memcpy(actual_key.bytes, obfuscated_key.bytes, sizeof(actual_key.bytes));     
        // get_key(actual_key.bytes, sizeof(actual_key.bytes));
        decrypt_packed_bin_des3((void *)(packed_bin_phdr->p_vaddr + sections[0]),
                                sections[1], &actual_key);
        decrypt_packed_bin_des3((void *)(packed_bin_phdr->p_vaddr + sections[2]),
                                sections[3], &actual_key);
    }

    /*
        持久化---begin
        方案：只改变外部加密所用的密钥，外部解密后使用新的密钥进行加密
    */
    if (protect_mode == 1) {
        // 与PUF通信获取密钥
        uint8_t rand[32];
        get_random_bytes(rand, 32);
        snd_data_init(&snd_data, rand);
        snd_data.ser_fd = usb_fd;
        rec_data.ser_fd = usb_fd;
        send(&snd_data);
        receive(&rec_data);
        sys_close(usb_fd);
        // 从PUF通信拿到的数据初始化key
        get_serial_key(serial_key, &rec_data);
    } else {
        get_random_bytes(serial_key, 16);
    }

    // 外部加密
    if (encryption_algorithm == AES) {
        DEBUG("[Packer] Using AES...");
        struct aes_key key;
        get_key(key.bytes, sizeof(key.bytes));
        DEBUG_FMT("applying outer encryption with key %s", STRINGIFY_KEY(&key));
        /* Encrypt the actual binary */
        encrypt_memory_range_aes(&key, bin_new, packed_bin_phdr->p_filesz);
    } else if (encryption_algorithm == DES) {
        DEBUG("[Packer] Using DES...");
        struct des_key key;
        get_key(key.bytes, sizeof(key.bytes));
        DEBUG_FMT("applying outer encryption with key %s", STRINGIFY_KEY(&key));
        /* Encrypt the actual binary */
        encrypt_memory_range_des(&key, bin_new, packed_bin_phdr->p_filesz);
    } else if (encryption_algorithm == RC4) {
        DEBUG("[Packer] Using RC4...");
        struct rc4_key key;
        get_key(key.bytes, sizeof(key.bytes));
        DEBUG_FMT("applying outer encryption with key %s", STRINGIFY_KEY(&key));
        /* Encrypt the actual binary */
        encrypt_memory_range_rc4(&key, bin_new, packed_bin_phdr->p_filesz);
    } else if (encryption_algorithm == TDEA) {
        DEBUG("[Packer] Using TDEA...");
        struct des3_key key;
        get_key(key.bytes, sizeof(key.bytes));
        DEBUG_FMT("applying outer encryption with key %s", STRINGIFY_KEY(&key));
        /* Encrypt the actual binary */
        encrypt_memory_range_des3(&key, bin_new, packed_bin_phdr->p_filesz);
    }

    // 写回program
    int prog_fd = sys_open(rand_tmp_filename, O_RDWR, 0777);
    sys_lseek(prog_fd, sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr) * 2 + loader_size, SEEK_SET);
    sys_write(prog_fd, bin_new, packed_bin_phdr->p_filesz);
    sys_write(prog_fd, (char*)sections, sizeof(sections));
    shuffle(snd_data.data_buf, SERIAL_SIZE, swap_infos);
    sys_write(prog_fd, swap_infos, SERIAL_SIZE);
    if (protect_mode == 0) {
        memset(snd_data.data_buf, 0, SERIAL_SIZE);
        memcpy(snd_data.data_buf, serial_key, 16);
    }
    sys_write(prog_fd, snd_data.data_buf, SERIAL_SIZE);
    sys_write(prog_fd, (char*)mac_array, sizeof(mac_array));
    sys_close(prog_fd);

    pid = sys_fork();
    if (pid == 0) {
        char true_shell[200] = "/bin/mv ";
        int s_idx = strlen(true_shell);
        strncpy(true_shell + s_idx, rand_tmp_filename, strlen(rand_tmp_filename));
        s_idx += strlen(rand_tmp_filename);
        true_shell[s_idx++] = ' ';
        strncpy(true_shell + s_idx, prog_name, strlen(prog_name));
        const char *shell = "/bin/sh";
        char *const args[] = {"/bin/sh", "-c", true_shell, NULL};
        char *const env[] = {NULL};
        sys_exec(shell, args, env);
    } else {
        sys_wait4(pid, &wstatus, __WALL);
    }
    /*
        持久化---end
    */


    /* Entry point for ld.so if this is not a statically linked binary,
     * otherwise map_elf_from_mem will not touch this and it will be set below.
     */
    void *interp_entry = NULL;
    void *interp_base = NULL;
    // 对解密后的文件进行处理
    void *load_addr =
        map_elf_from_mem(packed_bin_ehdr, &interp_entry, &interp_base);
    DEBUG_FMT("binary base address is %p", load_addr);

    void *program_entry = packed_bin_ehdr->e_type == ET_EXEC
                              ? (void *)packed_bin_ehdr->e_entry
                              : load_addr + packed_bin_ehdr->e_entry;
    // 在命令函参数之上有环境变量，环境变量之上就是辅助向量，存了一些键值对，提供给动态链接器?
    // 修改了程序入口地址，program header addr，interpreter base和program header
    // number
    setup_auxv(argv, program_entry,
               (void *)(load_addr + packed_bin_ehdr->e_phoff), interp_base,
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