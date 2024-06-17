#include "./include/termios.h"

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

int send(ser_data* snd) {
    ssize_t ret = sys_write(snd->ser_fd, snd->data_buf, 41);
    if (ret > 0) {
        DEBUG_FMT("send %d bytes", ret);
    } else {
        return -1;
    }
    usleep(100000);
}

void get_serial_key(uint8_t* serial_key, ser_data* rec_data) {
    memcpy(serial_key, rec_data->data_buf + 4, 16);
}

int receive(ser_data* rec)
{
    int total_bytes_read = 0;
    int bytes_left = 41;
    int n = 0;

    while (bytes_left > 0) {
        n = sys_read(rec->ser_fd, rec->data_buf + total_bytes_read, bytes_left);
        if (n < 0) {
            // 错误处理: 你可以检查errno来看是什么错误发生了
            return -1;
        } else if (n == 0) {
            // EOF，设备文件关闭
            DEBUG("EOF or device file closed");
            break;
        }

        total_bytes_read += n;
        bytes_left -= n;
    }

    if (total_bytes_read == 41) {
        DEBUG_FMT("receive %d bytes", total_bytes_read);
    } else {
        DEBUG_FMT("receive error, not enough bytes: %d", total_bytes_read);
    }

    if (verify(rec) == -1) {
        DEBUG("PUF receive wrong data, exiting...");
        return -1;
    }

    return total_bytes_read;
}

int verify(ser_data* data) {
    uint8_t header[4] = {0xa5, 0x5a, 0x20, 0x00};
    for (int i = 0; i < 4; i++) {
        if (data->data_buf[i] != header[i]) {
            DEBUG("header error");
            return -1;
        }
    }
    uint16_t CRC16 = CRC16_Check(data->data_buf, 4 + 32);
    if ((CRC16 >> 8) != data->data_buf[36] || (CRC16 & 0xFF) != data->data_buf[37]) {
        DEBUG("CRC16 error");
        return -1;
    }
    if (data->data_buf[38] != 0xFF)
        return -1;
    return 0;
}

int term_init() {
    int pid = sys_fork();
    int wstatus;
    if (pid == 0) {
        const char *shell = "/bin/sh";
        char *const args[] = {"/bin/sh", "-c", "stty -F /dev/ttyUSB0 115200 cs8 -parenb -cstopb -ixon -crtscts raw", NULL};
        char *const env[] = {NULL};
        sys_exec(shell, args, env);
    } else {
        sys_wait4(pid, &wstatus, __WALL);
    }
  return 0;
}

int open_serial_port(const char *device) {
    // 打开串口设备文件
    int fd = sys_open(device, O_RDWR | O_NOCTTY, 0666); // 不使用O_NDELAY或O_NONBLOCK
    if (fd <= 0) {
        DEBUG("open failed");
        return 0;
    }
    usleep(100000);
    term_init();
    return fd;
}

void snd_data_init(ser_data* snd_data, uint8_t* rand) {
    snd_data->data_buf[0] = 0xA5;
    snd_data->data_buf[1] = 0x5A;
    snd_data->data_buf[2] = 0x20;
    snd_data->data_buf[3] = 0x00;
    for (int i = 4; i < 36; i++) snd_data->data_buf[i] = rand[i - 4];

    unsigned short int CRC16re = CRC16_Check(snd_data->data_buf, 4 + 32);

    snd_data->data_buf[36] = CRC16re >> 8;
    snd_data->data_buf[37] = CRC16re & 0xFF;
    snd_data->data_buf[38] = 0xFF;
    snd_data->data_buf[39] = 0x0D;
    snd_data->data_buf[40] = 0x0A;
}
