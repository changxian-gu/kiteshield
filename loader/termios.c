#include "./include/termios.h"

int my_tcflush(int fd, int queue_selector)
{
    return sys_ioctl(fd, TCFLSH, queue_selector);
}

int my_tcgetattr(int fd, struct termios *termios_p) {
    if (termios_p == NULL) {
        return -1; // 如果 termios_p 是 NULL，返回错误
    }
    return sys_ioctl(fd, TCGETS, termios_p);
}

int my_cfsetispeed(struct termios *termios_p, speed_t speed) {
    if (termios_p == NULL) {
        return -1;
    }
    termios_p->c_ispeed = speed;
    return 0;
}

int my_cfsetospeed(struct termios *termios_p, speed_t speed) {
    if (termios_p == NULL) {
        return -1;
    }
    termios_p->c_ospeed = speed;
    return 0;
}

int my_tcsetattr(int fd, int optional_actions, const struct termios *termios_p) {
    if (termios_p == NULL) {
        return -1;
    }
    return sys_ioctl(fd, TCSETS, (void *)termios_p);
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
    ssize_t ret = sys_write(snd->ser_fd, snd->data_buf, 39);
    if (ret > 0) {
        DEBUG_FMT("send %d bytes", ret);
        DEBUG("send success.");
    } else {
        DEBUG("send error!");
    }
    sys_usleep(100000);
}

void get_serial_key(uint8_t* serial_key, ser_data* rec_data) {
    memcpy(serial_key, rec_data->data_buf + 4, 16);
}

int receive(ser_data* rec)
{
  int n = sys_read(rec->ser_fd, rec->data_buf, 39);
  if (n < 0) {
    DEBUG("serial_recv");
    return -1;
  } else {
    DEBUG_FMT("receive %d bytes", n);
  }
  return n;
}

int term_init(int fd) {
  struct termios options;
  my_tcgetattr(fd, &options);

  my_cfsetispeed(&options, B115200);
  my_cfsetospeed(&options, B115200);

  options.c_cflag &= ~PARENB;
  options.c_cflag &= ~CSTOPB;
  options.c_cflag &= ~CSIZE;
  options.c_cflag |= CS8;
  options.c_cflag &= ~CRTSCTS;

  options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

  my_tcsetattr(fd, TCSANOW, &options);
  sys_usleep(100000);
  return 0;
}

int open_serial_port(const char *device) {
    // 打开串口设备文件
    int fd = sys_open(device, O_RDWR | O_NOCTTY, 0666); // 不使用O_NDELAY或O_NONBLOCK
    if (fd < 0) {
        DEBUG("open");
        return -1;
    }
    term_init(fd);
    return fd;
}

void snd_data_init(ser_data* snd_data, uint8_t* rand) {
    snd_data->data_buf[0] = 0xA5;
    snd_data->data_buf[1] = 0x5A;
    snd_data->data_buf[2] = 0x20;
    snd_data->data_buf[3] = 0x00;
    for (int i = 4; i < 36; i++) snd_data->data_buf[i] = rand[i - 4];

    unsigned short int CRC16re = CRC16_Check(snd_data->data_buf, 4 + 32);
    int sum = 0;
    for (int i = 7; i >= 0; i--) {
        sum = sum * 2 + (CRC16re >> i & 1);
    }

    snd_data->data_buf[36] = CRC16re >> 8;
    snd_data->data_buf[37] = sum;
    snd_data->data_buf[38] = 0xFF;
}