#include "./include/random.h"
#include "loader/include/syscalls.h"
int get_random_bytes(void *buf, int len) {
    int fd = sys_open("/dev/urandom", 0, 0);
    sys_read(fd, buf, len);
    sys_close(fd);
    return 0;
}