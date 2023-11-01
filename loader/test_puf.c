// #include "common/include/termios.h"
// #include "types.h"
// #include "common/include/defs.h"
// #include "loader/include/debug.h"
// #include "loader/include/string.h"
// #include "loader/include/malloc.h"

// typedef struct termios termios_t;
// typedef struct serial_data {
//     unsigned char data_buf[39];
//     int ser_fd;
// } ser_data;

// uint8_t serial_key1[39];

// static int get_random_bytes_v1(void *buf, size_t len) {
//     int fd = sys_open("/dev/urandom", O_RDONLY, 0);
//     sys_read(fd, buf, len);
//     sys_close(fd);
//     return 0;
// }

// static unsigned short int CRC16_Check(const unsigned char *data, unsigned char len) {
//     unsigned short int CRC16 = 0xFFFF;
//     for (unsigned char i = 0; i < len; i++) {
//         CRC16 ^= data[i];
//         for (unsigned char j = 0; j < 8; j++) {
//             unsigned char state = CRC16 & 0x01;
//             CRC16 >>= 1;
//             if (state) {
//                 CRC16 ^= 0xA001;
//             }
//         }
//     }
//     return CRC16;
// }
// void send1(ser_data snd) {
//     ssize_t ret = sys_write(snd.ser_fd, snd.data_buf, sizeof snd.data_buf);
//     if (ret > 0) {
//         DEBUG_FMT("send %d bytes", ret);
//         ks_printf(1, "send success.");
//     } else {
//         ks_printf(1, "send error!");
//     }
// }

// void receive1(ser_data rec) {
//     ks_printf(1, "receiving!!!");
//     unsigned char res[39];
//     int index = 0;
//     while (1) {
//         unsigned char buf[39];
//         ssize_t ret = sys_read(rec.ser_fd, buf, 39);
//         if (ret > 0) {
//             DEBUG_FMT("receive success, receive size is %d", ret);
//             for (int i = 0; i < ret; i++) {
//                 res[index++] = buf[i];
//             }
//         }
//         if (index == 39) {
//             break;
//         }
//     }
//     for (int i = 4, j = 0; i < 4 + 16; i++, j++) {
//         serial_key1[j] = res[i];
//     }
// }

// int common1(unsigned char temp[]) {
//     // 进行串口参数设置
//     termios_t *ter_s = ks_malloc(sizeof(*ter_s));
//     // 不成为控制终端程序，不受其他程序输出输出影响
//     char *device = "/dev/ttyUSB0";
//     int fd = sys_open(device, O_RDWR | O_NOCTTY | O_NDELAY, 0777);
//     if (fd < 0) {
//         DEBUG_FMT("%s open failed", device);
//         return -1;
//     } else {
//         ks_printf(1, "connection device /dev/ttyUSB0 successful");
//     }
//     memset(ter_s, sizeof(*ter_s), 0);

//     ter_s->c_cflag |= CLOCAL | CREAD;  // 激活本地连接与接受使能
//     ter_s->c_cflag &= ~CSIZE;          // 失能数据位屏蔽
//     ter_s->c_cflag |= CS8;             // 8位数据位
//     ter_s->c_cflag &= ~CSTOPB;         // 1位停止位
//     ter_s->c_cflag &= ~PARENB;         // 无校验位
//     ter_s->c_cc[VTIME] = 0;
//     ter_s->c_cc[VMIN] = 0;
//     /*
//         1 VMIN> 0 && VTIME> 0
//         VMIN为最少读取的字符数，当读取到一个字符后，会启动一个定时器，在定时器超时事前，如果已经读取到了VMIN个字符，则read返回VMIN个字符。如果在接收到VMIN个字符之前，定时器已经超时，则read返回已读取到的字符，注意这个定时器会在每次读取到一个字符后重新启用，即重新开始计时，而且是读取到第一个字节后才启用，也就是说超时的情况下，至少读取到一个字节数据。
//         2 VMIN > 0 && VTIME== 0
//         在只有读取到VMIN个字符时，read才返回，可能造成read被永久阻塞。
//         3 VMIN == 0 && VTIME> 0
//         和第一种情况稍有不同，在接收到一个字节时或者定时器超时时，read返回。如果是超时这种情况，read返回值是0。
//         4 VMIN == 0 && VTIME== 0
//         这种情况下read总是立即就返回，即不会被阻塞。----by 解释粘贴自博客园
//     */
//     my_cfsetispeed(ter_s, B115200);  // 设置输入波特率
//     my_cfsetospeed(ter_s, B115200);  // 设置输出波特率
//     // my_tcflush(fd, TCIFLUSH);        // 刷清未处理的输入和/或输出
//     if (my_tcsetattr(fd, TCSANOW, ter_s) != 0) {
//         ks_printf(1, "com set error!");
//     }

//     ser_data snd_data;
//     ser_data rec_data;
//     snd_data.ser_fd = fd;
//     rec_data.ser_fd = fd;

//     memcpy(snd_data.data_buf, temp, SERIAL_SIZE);

//     send1(snd_data);
//     receive1(rec_data);
//     ks_free(ter_s);
//     sys_close(fd);
//     return 0;
// }

// int common2(unsigned char temp[]) {
//     termios_t origin_term;

//     if (my_tcgetattr(0, &origin_term) != 0) {
//         ks_printf(1, "com get error!\r\n");
//     }
//     // 进行串口参数设置
//     termios_t *ter_s = ks_malloc(sizeof(*ter_s));
//     // 不成为控制终端程序，不受其他程序输出输出影响
//     char *device = "/dev/ttyUSB0";
//     int fd = sys_open(device, O_RDWR | O_NOCTTY | O_NDELAY, 0777);
//     if (fd < 0) {
//         ks_printf(1, "%s open failed\r\n", device);
//         return -1;
//     } else {
//         ks_printf(1, "connection device /dev/ttyUSB0 successful\n");
//     }
//     memset(ter_s, 0, sizeof(*ter_s));

//     ter_s->c_cflag |= CLOCAL | CREAD;  // 激活本地连接与接受使能
//     ter_s->c_cflag &= ~CSIZE;          // 失能数据位屏蔽
//     ter_s->c_cflag |= CS8;             // 8位数据位
//     ter_s->c_cflag &= ~CSTOPB;         // 1位停止位
//     ter_s->c_cflag &= ~PARENB;         // 无校验位
//     ter_s->c_cc[VTIME] = 0;
//     ter_s->c_cc[VMIN] = 0;
//     my_cfsetispeed(ter_s, B115200);  // 设置输入波特率
//     my_cfsetospeed(ter_s, B115200);  // 设置输出波特率
//     my_tcflush(fd, TCIFLUSH);        // 刷清未处理的输入和/或输出
    

//     if (my_tcsetattr(fd, TCSANOW, ter_s) != 0) {
//         ks_printf(1, "com set error!\r\n");
//     }

//     my_tcflush(fd, TCIFLUSH);        // 刷清未处理的输入和/或输出

//     unsigned char rand[32];
//     get_random_bytes_v1(rand, sizeof rand);
//     temp[0] = 0xA5;
//     temp[1] = 0x5A;
//     temp[2] = 0x20;
//     temp[3] = 0x00;
//     for (int i = 4; i < 36; i++) temp[i] = rand[i - 4] % 2;

//     unsigned short int CRC16re = CRC16_Check(temp, 4 + 32);
//     ks_printf(1, "%x\n", CRC16re);
//     ks_printf(1, "%x\n", CRC16re >> 8);
//     int sum = 0;
//     for (int i = 7; i >= 0; i--) {
//         sum = sum * 2 + (CRC16re >> i & 1);
//     }
//     ks_printf(1, "%x\n", sum);

//     temp[36] = CRC16re >> 8;
//     temp[37] = sum;
//     temp[38] = 0xFF;

//     ks_printf(1, "send data\n");
//     for (int i = 0; i < 39; i++) ks_printf(1, "%x", temp[i]);
//     ks_printf(1, "\n");

//     ser_data snd_data;
//     ser_data rec_data;
//     snd_data.ser_fd = fd;
//     rec_data.ser_fd = fd;

//     memcpy(snd_data.data_buf, temp, SERIAL_SIZE);

//     send1(snd_data);
//     receive1(rec_data);
//     ks_free(ter_s);
//     if (my_tcsetattr(0, TCSANOW, &origin_term) != 0) {
//         ks_printf(1, "com set error!\r\n");
//     }
//     return 0;
// }

// int main() {
//     ks_malloc_init();

//     unsigned char temp[SERIAL_SIZE];
//     common2(temp);

//     ks_malloc_deinit();
//     sys_exit(0);
// }