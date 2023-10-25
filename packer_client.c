#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "myargs.h"

#define END_FLAG "##END##"
#define FLAG_LEN 7

void error_handling(char *message);


// args {
//     char name[32];
//     byte enc;
//     byte compress;
//     byte mac[6];
//     int filesize;
// }

// 发送给socket服务端的参数应该包括：需要加密的文件名，加密参数，压缩参数，MAC地址
int main(int argc, char *argv[]) {
    char* filename = "hello_world";
    struct m_args args;
    strcpy(args.name, filename);
    printf("name: %s\n", args.name);
    args.encryption = 4;
    args.compression = 4;
    printf("enc: %x\n", args.encryption);
    printf("com: %x\n", args.compression);

    // 打开文件，获得文件大小
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL)
        error_handling("File open error");
    fseek(fp, 0L, SEEK_END);
    int file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    args.filesize = file_size;

    int buffer_size = 1024 + file_size;
    char* buffer = malloc(buffer_size);
    // 填充buffer
    memcpy(buffer, &args, sizeof(args));


    // socket参数设置
    int read_size, sent_size;
    struct sockaddr_in serv_addr;
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        error_handling("socket() error");
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("10.170.14.43");
    serv_addr.sin_port = htons(8080);

    // 连接服务器
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
        error_handling("connect() error");

    fread(buffer + 1024, 1, file_size, fp);
    struct m_args args2;
    args2 = *(struct m_args*) buffer;
    printf("%s, %x, %x, %d\n", args2.name, args2.encryption, args2.compression, args2.filesize);
    send(sock, buffer, 1024 + file_size, 0);
    fclose(fp);

    // 接收处理后的文件
    memset(buffer, 0, buffer_size);
    int rd_idx = 0;
    while (true) {
        int recv_size = recv(sock, buffer + rd_idx, file_size - rd_idx, 0);
        if (recv_size <= 0)
            break;
        rd_idx += recv_size;
    }

    fp = fopen("./client_folder/received_file", "wb");
    fwrite(buffer, 1, rd_idx, fp);
    fclose(fp);
    close(sock);
    return 0;
}

void error_handling(char *message) {
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}
