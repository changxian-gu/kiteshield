#include "./include/termios.h"

int my_tcflush(int fd, int queue_selector)
{
    return sys_ioctl(fd, TCFLSH, queue_selector);
}

int my_tcgetattr(int fd, struct termios *term)
{
    struct termios tmp;
    int ret;

    ret = sys_ioctl(fd, TCGETS, &tmp);
    if (ret < 0)
        return ret;

    *term = tmp;

    return 0;
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

unsigned short int CRC16_Check(const unsigned char *data, unsigned char len) {
    unsigned short int CRC16 = 0xFFFF;
    for (unsigned char i = 0; i < len; i++) {
        CRC16 ^= data[i];
        for (unsigned char j = 0; j < 8; j++) {
            unsigned char state = CRC16 & 0x01;
            CRC16 >>= 1;
            if (state) {
                CRC16 ^= 0xA001;
            }
        }
    }
    return CRC16;
}

void send(ser_data* snd) {
    ssize_t ret = sys_write(snd->ser_fd, snd->data_buf, sizeof snd->data_buf);
    if (ret > 0) {
        DEBUG_FMT("send %d bytes", ret);
        DEBUG("send success.");
    } else {
        DEBUG("send error!");
    }
    sleep(1);
}

void get_serial_key(uint8_t* serial_key, ser_data* rec_data) {
    memcpy(serial_key, rec_data->data_buf + 4, 16);
}

void receive(ser_data* rec) {
    DEBUG("receiving!!!");
    int index = 0;
    while (index < 39) {
        unsigned char buf[39];
        ssize_t ret = sys_read(rec->ser_fd, (rec->data_buf) + index, 39 - index);
        if (ret > 0) {
            DEBUG_FMT("receive success, receive size is %d", ret);
            index += ret;
        }
    }
}

int term_init(int fd) {
    struct termios tty;
    if (my_tcgetattr (fd, &tty) != 0) {
        return -1;
    }
    tty.c_ispeed = B115200;
    tty.c_ospeed = B115200;
    tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;     // 8-bit chars
    tty.c_lflag = 0;                // no signaling chars, no echo,
    tty.c_oflag = 0;                // no remapping, no delays
    tty.c_cc[VMIN]  = 0;            // read doesn't block
    tty.c_cc[VTIME] = 0;            // no timeout
    tty.c_cflag &= ~PARENB;
    tty.c_cflag |= (CLOCAL | CREAD);// ignore modem controls,
    tty.c_cflag &= ~CSTOPB;         // 1位停止位

    if (my_tcsetattr (fd, TCSANOW, &tty) != 0){
        return -1;
    }
    sleep(1);
    return 0;
}

int common(ser_data* snd_data, ser_data* rec_data) {
    char *device = "/dev/ttyUSB0";
    int fd = sys_open(device, O_RDWR | O_NOCTTY | O_NDELAY, 0777);
    if (fd < 0) {
        DEBUG_FMT("%s open failed", device);
        return -1;
    } else {
        DEBUG("connection device /dev/ttyUSB0 successful");
    }

    term_init(fd);

    snd_data->ser_fd = fd;
    rec_data->ser_fd = fd;

    send(snd_data);
    receive(rec_data);
    sys_close(fd);
    return 0;
}

void snd_data_init(ser_data* snd_data, uint8_t* rand) {
    snd_data->data_buf[0] = 0xA5;
    snd_data->data_buf[1] = 0x5A;
    snd_data->data_buf[2] = 0x20;
    snd_data->data_buf[3] = 0x00;
    for (int i = 4; i < 36; i++) snd_data->data_buf[i] = rand[i - 4] % 2;

    unsigned short int CRC16re = CRC16_Check(snd_data->data_buf, 4 + 32);
    int sum = 0;
    for (int i = 7; i >= 0; i--) {
        sum = sum * 2 + (CRC16re >> i & 1);
    }

    snd_data->data_buf[36] = CRC16re >> 8;
    snd_data->data_buf[37] = sum;
    snd_data->data_buf[38] = 0xFF;
}