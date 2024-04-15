#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>

typedef struct serial_data {
    unsigned char data_buf[39];
    int ser_fd;
} ser_data;

void printBytes(const char *msg, unsigned long len) {
    for (int i = 0; i < len; i++) {
        printf("0x%x(", (unsigned char)(msg[i]));
        printf("%d) ", (unsigned char)(msg[i]));
    }
    printf("%s", "\n");
}

int get_random_bytes(void *buf, int len) {
    int fd = open("/dev/urandom", O_RDONLY, 0);
    read(fd, buf, len);
    close(fd);
    return 0;
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

int send(ser_data* snd) {
    int ret = write(snd->ser_fd, snd->data_buf, 39);
    if (ret > 0) {
        printf("send %d bytes\n", ret);
    } else {
        return -1;
    }
}

void get_serial_key(uint8_t* serial_key, ser_data* rec_data) {
    memcpy(serial_key, rec_data->data_buf + 4, 16);
}

int receive(ser_data* rec)
{
    int total_bytes_read = 0;
    int bytes_left = 39;
    int n = 0;

    while (bytes_left > 0) {
        n = read(rec->ser_fd, rec->data_buf + total_bytes_read, bytes_left);
        if (n < 0) {
            // 错误处理: 你可以检查errno来看是什么错误发生了
            return -1;
        } else if (n == 0) {
            // EOF，设备文件关闭
            printf("EOF or device file closed\n");
            break;
        }

        total_bytes_read += n;
        bytes_left -= n;
    }

    if (total_bytes_read == 39) {
        printf("receive %d bytes\n", total_bytes_read);
    } else {
        printf("receive error, not enough bytes: %d\n", total_bytes_read);
    }
    return total_bytes_read;
}

int term_init() {
    int pid = fork();
    int wstatus;
    if (pid == 0) {
        const char *shell = "/bin/sh";
        char *cmd = "stty -F /dev/ttyUSB0 115200 cs8 -cstopb -parenb -crtscts \
                    -ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr -icrnl -ixon -ixoff \
                    -iuclc -ixany -imaxbel -iutf8 \
                    -opost -olcuc -ocrnl -onlcr -onocr -onlret -ofill -ofdel \
                    -isig -icanon -iexten -echo -echoe -echok -echonl -noflsh -xcase -tostop -echoprt -echoctl -echoke -flusho -extproc";
        char *const args[] = {"/bin/sh", "-c", cmd, NULL};
        execv(shell, args);
    } else {
        waitpid(pid, &wstatus, __WALL);
    }

  return 0;
}

int open_serial_port(const char *device) {
    printf("file name is %s\n", device);
    // 打开串口设备文件
    int fd = open(device, O_RDWR | O_NOCTTY, 0666); // 不使用O_NDELAY或O_NONBLOCK
    if (fd <= 0) {
        printf("open failed\n");
        return -1;
    }
    term_init();
    return fd;
}

void snd_data_init(ser_data* snd_data, uint8_t* rand) {
    snd_data->data_buf[0] = 0xA5;
    snd_data->data_buf[1] = 0x5A;
    snd_data->data_buf[2] = 0x20;
    snd_data->data_buf[3] = 0x00;
    for (int i = 4; i < 36; i++) snd_data->data_buf[i] = rand[i - 4];

    uint16_t CRC16re = CRC16_Check(snd_data->data_buf, 4 + 32);
    snd_data->data_buf[36] = CRC16re >> 8;
    snd_data->data_buf[37] = CRC16re & 0xFF;
    snd_data->data_buf[38] = 0xFF;
}

int verify(ser_data* data) {
    uint8_t header[4] = {0xa5, 0x5a, 0x20, 0x00};
    for (int i = 0; i < 4; i++) {
        if (data->data_buf[i] != header[i]) {
            printf("header error\n");
            return -1;
        }
    }
    uint16_t CRC16 = CRC16_Check(data->data_buf, 4 + 32);
    if ((CRC16 >> 8) != data->data_buf[36] || (CRC16 & 0xFF) != data->data_buf[37]) {
        printf("CRC16 error\n");
        return -1;
    }
    if (data->data_buf[38] != 0xFF)
        return -1;
    return 0;
}

int main() {
    char* device = "/dev/ttyUSB0";
    int fd = open_serial_port(device);
    if (fd <= 0)
        return -1;
    ser_data snd_data = {{}, fd};
    ser_data rec_data = {{}, fd};

    char rand[39];
    get_random_bytes(rand, 39);
    snd_data_init(&snd_data, rand);
    printBytes(snd_data.data_buf, 39);
    send(&snd_data);

    int ret = verify(&snd_data);
    if (ret == -1) {
        printf("puf data verify error\n");
        return 0;
    }
    receive(&rec_data);
    verify(&rec_data);
    printBytes(rec_data.data_buf, 39);
    return 0;
}