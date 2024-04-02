/* Serial communication open func constant defines */
#include <stdint.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>

void printBytes(const char *msg, unsigned long len) {
  for (int i = 0; i < len; i++) {
    printf("%02x", (unsigned char)(msg[i]));
  }
  printf("%s", "\n");
}

void snd_data_init(unsigned char* snd_buff, uint8_t *rand);

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

int term_init(int fd) {
  struct termios options;
  tcgetattr(fd, &options);

  cfsetispeed(&options, B115200);
  cfsetospeed(&options, B115200);

  options.c_cflag &= ~PARENB;
  options.c_cflag &= ~CSTOPB;
  options.c_cflag &= ~CSIZE;
  options.c_cflag |= CS8;
  options.c_cflag &= ~CRTSCTS;

  options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

  tcsetattr(fd, TCSANOW, &options);
  usleep(100000);
  return 0;
}

// 发送数据
int serial_send(int fd, char *data, int len)
{
  int n = write(fd, data, len);
  if (n < 0) {
    perror("serial_send");
    return -1;
  }
    usleep(100000);

  return n;
}

// 接收数据
int serial_recv(int fd, char *data, int len)
{
  int n = read(fd, data, len);
  if (n < 0) {
    perror("serial_recv");
    return -1;
  }
  return n;
}

void snd_data_init(unsigned char* snd_buff, uint8_t *rand) {
  snd_buff[0] = 0xA5;
  snd_buff[1] = 0x5A;
  snd_buff[2] = 0x20;
  snd_buff[3] = 0x00;
  for (int i = 4; i < 36; i++) snd_buff[i] = rand[i - 4];
  unsigned short int CRC16re = CRC16_Check(snd_buff, 4 + 32);
  int sum = 0;
  for (int i = 7; i >= 0; i--) {
    sum = sum * 2 + (CRC16re >> i & 1);
  }
  snd_buff[36] = CRC16re >> 8;
  snd_buff[37] = sum;
  snd_buff[38] = 0xFF;
}

int main() {
  char *device = "/dev/ttyUSB0";
  unsigned char snd_buff[39] = {0}, recv_buff[39] = {0};

  uint8_t random[32] = {0};

  snd_data_init(snd_buff, random);

  int fd = open(device, O_RDWR | O_NOCTTY, 0777);
  if (fd < 0) {
    printf("%s open failed\n", device);
    return -1;
  } else {
    printf("connection device /dev/ttyUSB0 successful\n");
  }

  term_init(fd);

  printBytes(snd_buff, 39);
  // serial_send(fd, snd_buff, 39);
  // serial_recv(fd, recv_buff, 39);
  close(fd);

  printBytes(recv_buff, 39);
  printf("\n");
}