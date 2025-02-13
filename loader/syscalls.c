#include "loader/include/syscalls.h"
#include "loader/include/types.h"

ssize_t sys_write(int fd, const char *s, size_t count) {
    ssize_t ret = 0;

    asm volatile (
            "mov $1, %%rax\n"
            "mov %1, %%edi\n"
            "mov %2, %%rsi\n"
            "mov %3, %%rdx\n"
            "syscall\n"
            "mov %%rax, %0"
            :   "=rm" (ret)
            :   "rm" (fd), "rm" (s), "rm" (count)
            :   "rax", "edi", "rsi", "rdx");

    return ret;
}

ssize_t sys_read(int fd, void *buf, size_t count) {
    ssize_t ret = 0;

    asm volatile (
            "mov $0, %%rax\n"
            "mov %1, %%edi\n"
            "mov %2, %%rsi\n"
            "mov %3, %%rdx\n"
            "syscall\n"
            "mov %%rax, %0"
            :   "=rm" (ret)
            :   "rm" (fd), "rm" (buf), "rm" (count)
            :   "rax", "edi", "rsi", "rdx");

    return ret;
}

off_t sys_lseek(int fd, off_t offset, int whence) {
    off_t ret = 0;

    asm volatile (
            "mov $8, %%rax\n"
            "mov %1, %%edi\n"
            "mov %2, %%rsi\n"
            "mov %3, %%edx\n"
            "syscall\n"
            "mov %%rax, %0"
            :   "=rm" (ret)
            :   "rm" (fd), "rm" (offset), "rm" (whence)
            :   "rax", "edi", "rsi", "edx");

    return ret;
}

int sys_open(const char *pathname, int flags, int mode) {
    int ret = 0;

    asm volatile (
            "mov $2, %%rax\n"
            "mov %1, %%rdi\n"
            "mov %2, %%esi\n"
            "mov %3, %%edx\n"
            "syscall\n"
            "mov %%eax, %0"
            :   "+rm" (ret)
            :   "rm" (pathname), "rm" (flags), "rm" (mode)
            :   "rax", "rdi", "esi", "edx");

    return ret;
}

int sys_close(int fd) {
    int ret = 0;

    asm volatile (
            "mov $3, %%rax\n"
            "mov %1, %%edi\n"
            "syscall\n"
            "mov %%eax, %0"
            :   "+rm" (ret)
            :   "rm" (fd)
            :   "rax", "edi");

    return ret;
}

void sys_exit(int status) {
    asm volatile (
            "mov $60, %%rax\n"
            "mov %0, %%edi\n"
            "syscall"
            :
            :   "rm" (status)
            :   "rax", "edi");

    /* Required so GCC accepts __attribute__((noreturn)) on this function */
    while (1) {}
}

void *sys_mmap(
        void *addr,
        size_t length,
        int prot,
        int flags,
        int fd,
        off_t offset) {
    void *ret = NULL;

    asm volatile (
            "mov $9, %%rax\n"
            "mov %1, %%rdi\n"
            "mov %2, %%rsi\n"
            "mov %3, %%edx\n"
            "mov %4, %%r10d\n"
            "mov %5, %%r8d\n"
            "mov %6, %%r9\n"
            "syscall\n"
            "mov %%rax, %0"
            :   "+rm" (ret)
            :   "rm" (addr), "rm" (length), "rm" (prot), "rm" (flags), "rm" (fd),
    "rm" (offset)
            :   "rax", "rdi", "rsi", "edx", "r10", "r8", "r9");

    return ret;
}

int sys_munmap(
        void *addr,
        size_t length) {
    int ret = 0;

    asm volatile (
            "mov $11, %%rax\n"
            "mov %1, %%rdi\n"
            "mov %2, %%rsi\n"
            "syscall\n"
            "mov %%eax, %0"
            :   "+rm" (ret)
            :   "rm" (addr), "rm" (length)
            :   "rax", "rdi", "rsi");

    return ret;
}

int sys_mprotect(void *addr, size_t len, int prot) {
    int ret = 0;

    asm volatile (
            "mov $10, %%rax\n"
            "mov %1, %%rdi\n"
            "mov %2, %%rsi\n"
            "mov %3, %%edx\n"
            "syscall\n"
            "mov %%eax, %0\n"
            :   "+rm" (ret)
            :   "rm" (addr), "rm" (len), "rm" (prot)
            :   "rax", "rdi", "rsi", "edx");

    return ret;
}

long sys_ptrace(
        enum __ptrace_request request,
        pid_t pid,
        void *addr,
        void *data) {
    long ret = 0;

    /* Note that the raw kernel-level ptrace interface differs from the one
     * exposed by glibc with regards to the PTRACE_PEEK requests. Glibc *returns*
     * the data, while the kernel-level interface stores it in *data.
     *
     * This function exposes the kernel-level interface.
     */
    asm volatile (
            "mov $101, %%rax\n"
            "mov %1, %%edi\n"
            "mov %2, %%esi\n"
            "mov %3, %%rdx\n"
            "mov %4, %%r10\n"
            "syscall\n"
            "mov %%rax, %0\n"
            :   "+rm" (ret)
            :   "rm" (request), "rm" (pid), "rm" (addr), "rm" (data)
            :   "rax", "edi", "esi", "rdx", "r10");

    return ret;
}

pid_t sys_wait4(pid_t pid, int *wstatus, int options) {
    pid_t ret = 0;

    /* We pass NULL for rusage to simpify the function signature (no need for
     * that parameter currently)
     */
    asm volatile (
            "mov $61, %%rax\n"
            "mov %1, %%edi\n"
            "mov %2, %%rsi\n"
            "mov %3, %%edx\n"
            "mov $0, %%r10\n"
            "syscall\n"
            "mov %%eax, %0\n"
            :   "+rm" (ret)
            :   "rm" (pid), "rm" ((uint64_t) wstatus), "rm" (options)
            :   "rax", "edi", "esi", "rdx", "r10");

    return ret;
}

pid_t sys_fork() {
    pid_t ret = 0;

    asm volatile (
            "mov $57, %%rax\n"
            "syscall\n"
            "mov %%eax, %0\n"
            :   "+rm" (ret)
            :
            :   "rax");

    return ret;
}

int sys_kill(pid_t pid, int sig) {
    pid_t ret = 0;

    asm volatile (
            "mov $62, %%rax\n"
            "mov %1, %%edi\n"
            "mov %2, %%esi\n"
            "syscall\n"
            "mov %%eax, %0\n"
            :   "+rm" (ret)
            :   "rm" (pid), "rm" (sig)
            :   "rax", "edi", "esi");

    return ret;
}

int sys_tgkill(pid_t tgid, pid_t tid, int sig) {
    pid_t ret = 0;

    asm volatile (
            "mov $234, %%rax\n"
            "mov %1, %%edi\n"
            "mov %2, %%esi\n"
            "mov %3, %%edx\n"
            "syscall\n"
            "mov %%eax, %0\n"
            :   "+rm" (ret)
            :   "rm" (tgid), "rm" (tid), "rm" (sig)
            :   "rax", "edi", "esi", "edx");

    return ret;
}

pid_t sys_getpid() {
    pid_t ret = 0;

    asm volatile (
            "mov $39, %%rax\n"
            "syscall\n"
            "mov %%eax, %0\n"
            :   "+rm" (ret)
            :
            :   "rax");

    return ret;
}

int sys_rt_sigaction(
        int sig,
        const struct kernel_sigaction *act,
        const struct kernel_sigaction *oact) {
    int ret = 0;
    size_t sigsetsize = sizeof(act->sa_mask);

    asm volatile (
            "mov $13, %%rax\n"
            "mov %1, %%edi\n"
            "mov %2, %%rsi\n"
            "mov %3, %%rdx\n"
            "mov %4, %%r10\n"
            "syscall\n"
            "mov %%eax, %0\n"
            :   "+rm" (ret)
            :   "rm" (sig), "rm" (act), "rm" (oact), "rm" (sigsetsize)
            :   "rax", "edi", "rsi", "rdx", "r10");

    return ret;
}

int sys_prctl(
        int option,
        unsigned long arg2,
        unsigned long arg3,
        unsigned long arg4,
        unsigned long arg5) {
    int ret = 0;

    asm volatile (
            "mov $157, %%rax\n"
            "mov %1, %%edi\n"
            "mov %2, %%rsi\n"
            "mov %3, %%rdx\n"
            "mov %4, %%r10\n"
            "mov %5, %%r8\n"
            "syscall\n"
            "mov %%eax, %0\n"
            :   "+rm" (ret)
            :   "rm" (option), "rm" (arg2), "rm" (arg3), "rm" (arg4), "rm" (arg5)
            :   "rax", "edi", "rsi", "rdx", "r10", "r8");

    return ret;
}

int sys_stat(const char *pathname, struct stat *statbuf) {
    int ret = 0;

    asm volatile (
            "mov $4, %%rax\n"
            "mov %1, %%rdi\n"
            "mov %2, %%rsi\n"
            "syscall\n"
            "mov %%eax, %0\n"
            :   "+rm" (ret)
            :   "rm" (pathname), "rm" (statbuf)
            :   "rax", "rdi", "rsi");

    return ret;
}

int sys_setrlimit(int resource, struct rlimit *rlim) {
    int ret = 0;

    asm volatile (
            "mov $160, %%rax\n"
            "mov %1, %%edi\n"
            "mov %2, %%rsi\n"
            "syscall\n"
            "mov %%eax, %0\n"
            :   "+rm" (ret)
            :   "rm" (resource), "rm" (rlim)
            :   "rax", "edi", "rsi");

    return ret;
}

// malloc
// char memory[2000];
// struct block {
//     //区块大小
//     size_t size;
//     //是否已使用
//     int free;
//     //指向下一个区块
//     struct block *next;
// };

// struct block *freeList = (void *) memory;

// void malloc_init() {
//     freeList->size = 2000 - sizeof(struct block);  //可用空间大小
//     freeList->free = 1;                        //1：空闲 0：使用
//     freeList->next = NULL;                      //指向空
// }

// void malloc_split(struct block *fitting_slot, size_t size) {
//     struct block *new = (void *) (fitting_slot + size + sizeof(struct block));          //定义new的地址
//     new->size = (fitting_slot->size) - size - sizeof(struct block);                   //定义size大小
//     new->free = 1;                                                                //设置是否工作
//     new->next = fitting_slot->next;                                               //独立出去，形成新的块
//     fitting_slot->size = size;
//     fitting_slot->free = 0;
//     fitting_slot->next = new;
// }

// void *malloc(size_t size) {
//     struct block *curr, *prev;
//     void *result;
//     sys_write(1, "malloc1\n", 9);
//     if (!(freeList->size)) malloc_init();
//     sys_write(1, "malloc2\n", 9);
//     curr = freeList;
//     while (((curr->size < size) || (curr->free == 0)) && (curr->next != NULL)) {
//         prev = curr;
//         curr = curr->next;
//     }
//     if (curr->size == size) {
//     sys_write(1, "malloc3\n", 9);
//         curr->free = 0;
//         result = (void *) (++curr);
//         return result;
//     } else if (curr->size > size + sizeof(struct block)) {            //所需要的内存大小小于区块大小
//     sys_write(1, "malloc4\n", 9);
//         malloc_split(curr, size);                            //分割区块函数
//     sys_write(1, "malloc41\n", 10);
//         result = (void *) (++curr);                                   //使用的位置
//         return result;
//     } else {
//     sys_write(1, "malloc5\n", 9);
//         result = NULL;
//         return result;
//     }
// }


// void malloc_merge() {
//     struct block *curr, *prev;
//     curr = freeList;
//     while (curr != NULL && curr->next != NULL) {
//         if (curr->free && curr->next->free) {
//             curr->size += (curr->next->size) + sizeof(struct block);
//             curr->next = curr->next->next;
//         }
//         prev = curr;
//         curr = curr->next;
//     }
// }

// void free(void *ptr) {
//     if (((void *) memory <= ptr) && (ptr <= (void *) (memory + 2000))) {
//         struct block *curr = ptr;
//         curr--;
//         curr->free = 1;
//         malloc_merge();
//     } else
//         return;
// }


