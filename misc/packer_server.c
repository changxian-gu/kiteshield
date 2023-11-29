#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include "myargs.h"

void error_handling(char *message);

int main(int argc, char *argv[])
{
    int serv_sock, clnt_sock;
    char buffer[BUF_SIZE];
    memset(buffer, 0, BUF_SIZE);
    struct sockaddr_in serv_addr, clnt_addr;
    socklen_t clnt_addr_size;

    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (serv_sock == -1)
        error_handling("socket() error");

    int opt = 1;
    if (setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        error_handling("set socketopt error");
    }

    serv_addr.sin_family = AF_INET;
    // serv_addr.sin_addr.s_addr = inet_addr("10.170.14.43");
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(8080);

    if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
        error_handling("bind() error");

    while (true) {
        int recv_size = 0;
        if (listen(serv_sock, 5) == -1)
            error_handling("listen() error");

        clnt_addr_size = sizeof(clnt_addr);
        clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);

        // 首先读前1024个字节，取出参数
        int rd_idx = 0;
        while (rd_idx < 1024) {
            recv_size = recv(clnt_sock, buffer + rd_idx, BUF_SIZE - rd_idx, 0);
            if (recv_size <= 0)
                return 0;
            rd_idx += recv_size;
            printf("rd_idx is %d\n", rd_idx);
        }

        struct m_args args;
        memcpy(&args, buffer, sizeof(args));
        printf("%s, %x, %x, %d\n", args.name, args.encryption, args.compression, args.filesize);

        // 之后读取剩下的可执行文件，把可执行文件写入磁盘
        char* file_buffer = malloc(args.filesize);
        rd_idx = 0;
        while (rd_idx < args.filesize) {
            recv_size = recv(clnt_sock, file_buffer + rd_idx, args.filesize - rd_idx, 0);
            if (recv_size <= 0)
                return 0;
            rd_idx += recv_size;
        }

        printf("filename : %s, filesize: %d\n", args.name, args.filesize);
        // 打开文件
        FILE* fp = fopen("received_file", "wb");
        if (fp == NULL) {
            error_handling("File open error");
        }
        fwrite(file_buffer, sizeof(char), args.filesize, fp);

        printf("\nreceive ok\n");
        fclose(fp);
        free(file_buffer);

    // 加壳
        int pid = fork();
        if (pid == 0) {
            int count = 0;
            char* my_args[10];
            my_args[count++] = "./packer/kiteshield";
            my_args[count++] = (char*) args.name;
            char enc_method[2];
            enc_method[0] = '0' + args.encryption;
            enc_method[1] = 0;
            my_args[count++] = enc_method;
            char com_method[2];
            com_method[0] = '0' + args.compression;
            com_method[1] = 0;
            my_args[count++] = com_method;
            my_args[count++] = "./packed_exe";
            my_args[count++] = "11:22:33:44:55:66";
            my_args[count] = 0;

            execv("./hello_world", my_args);
            perror("execv failed");
            printf("加壳完毕\n");
            exit(0);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        }
        
        // 把加壳后的文件传送给客户端
        fp = fopen("hello_world_pak", "rb");
        if (fp == NULL) {
            error_handling("file open failed");
        }
        fseek(fp, 0L, SEEK_END);
        int file_size = ftell(fp);
        fseek(fp, 0L, SEEK_SET);
        file_buffer = malloc(file_size);
        fread(file_buffer, 1, file_size, fp);
        send(clnt_sock, file_buffer, file_size, 0);
        fclose(fp);
        close(clnt_sock);
    }
    close(serv_sock);
    return 0;
}

void error_handling(char *message)
{
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}
