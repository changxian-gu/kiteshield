#include "./include/termios.h"

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

void term_init(int fd) {
    // 进行串口参数设置
    termios_t term;
    term.c_cflag |= CLOCAL | CREAD;  // 激活本地连接与接受使能
    term.c_cflag &= ~CSIZE;          // 失能数据位屏蔽
    term.c_cflag |= CS8;             // 8位数据位
    term.c_cflag &= ~CSTOPB;         // 1位停止位
    term.c_cflag &= ~PARENB;         // 无校验位
    term.c_cc[VTIME] = 0;
    term.c_cc[VMIN] = 0;
    term.c_ispeed = B115200;
    term.c_ospeed = B115200;
    my_tcflush(fd, TCIFLUSH);        // 刷清未处理的输入和/或输出
    if (my_tcsetattr(fd, TCSANOW, &term) != 0) {
        DEBUG("com set error!");
    }
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