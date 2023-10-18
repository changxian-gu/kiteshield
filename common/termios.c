#include "./include/termios.h"
#include "loader/include/syscalls.h"

int my_tcflush(int fd, int queue_selector)
{
    return sys_ioctl(fd, TCFLSH, queue_selector);
}

int my_tcsetattr(int fd, int optional_actions, const struct termios *term)
{
    return sys_ioctl(fd, TCSETS, term);
}

int my_cfsetispeed(struct termios *term, speed_t speed) {
    term->c_ispeed = speed;
    return my_tcsetattr(0, TCSANOW, term);  // 这里假设文件描述符为0，表示标准输入
}

int my_cfsetospeed(struct termios *term, speed_t speed) {
    term->c_ospeed = speed;
    return my_tcsetattr(0, TCSANOW, term);  // 这里假设文件描述符为0，表示标准输入
}