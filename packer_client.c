#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define END_FLAG "##END##"
#define FLAG_LEN 7
#define BUF_SIZE 1024

void error_handling(char *message);

/*
    协议格式：
    args\r\n
    file_size\r\n
    file
*/

// 发送给socket服务端的参数应该包括：需要加密的文件名，加密参数，压缩参数，MAC地址
int main(int argc, char *argv[])
{
    int sock;
    char* filename = "hello_world";
    long file_size, read_size, sent_size;
    char buffer[BUF_SIZE];
    memset(buffer, 0, BUF_SIZE);
    struct sockaddr_in serv_addr;

    // 创建socket, 设置服务器的的ip和端口
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        error_handling("socket() error");
    serv_addr.sin_family = AF_INET;
    // serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    // serv_addr.sin_port = htons(atoi(argv[2]));
    serv_addr.sin_addr.s_addr = inet_addr("172.24.48.144");
    serv_addr.sin_port = htons(8080);
    // 打开文件，获得文件大小
    FILE* fp = fopen(filename, "rb");
    if (fp == NULL)
        error_handling("File open error");
    fseek(fp, 0L, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    // 连接服务器
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
        error_handling("connect() error");

    // 需要传递的参数

    char* args = "hello_world 4 1 hello_world_pak 11:22:33:44:55:66";
    sprintf(buffer, "%s\r\n%d\r\n", args, file_size);
    
    // 发送参数和文件长度
    send(sock, buffer, strlen(buffer), 0);

    // 发送二进制文件
    int bytes_read;
    while (true) {
        bytes_read = fread(buffer, 1, BUF_SIZE, fp);
        sent_size = send(sock, buffer, bytes_read, 0);
        if (bytes_read <= 0)
            break;
    }
    // 发送文件截止符号
    send(sock, END_FLAG, FLAG_LEN, 0);
    // printf("sent END FLAG\n");

    memset(buffer, 0, sizeof(buffer));
    fclose(fp);
    // 二进制形式打开文件
    fp = fopen("./received_file", "wb");

    // 接收文件
    // printf("recving file");
    while (true) {
        int recv_size = recv(sock, buffer, BUF_SIZE, 0);
        if (recv_size > 0) {
            fwrite(buffer, sizeof(char), recv_size, fp);
        } else {
            break;
        }
        if (memcmp(buffer, END_FLAG, FLAG_LEN) == 0)
            break;
    }

    printf("\nreceive ok\n");
    fclose(fp);
    close(sock);
    return 0;
}

void error_handling(char *message)
{
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}
