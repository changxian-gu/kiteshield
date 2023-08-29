#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#define END_FLAG "##END##"
#define FLAG_LEN 7
#define BUF_SIZE 1024

void error_handling(char *message);

int main(int argc, char *argv[])
{
    int serv_sock, clnt_sock;
    char filename[256];
    int file_size;
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
    serv_addr.sin_addr.s_addr = inet_addr("172.24.48.144");
    serv_addr.sin_port = htons(8080);

    if (bind(serv_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
        error_handling("bind() error");

    while (true) {
        int remain_size = file_size, write_size = 0, recv_size = 0;
        if (listen(serv_sock, 5) == -1)
            error_handling("listen() error");

        clnt_addr_size = sizeof(clnt_addr);
        clnt_sock = accept(serv_sock, (struct sockaddr *)&clnt_addr, &clnt_addr_size);

        recv_size = recv(clnt_sock, buffer, BUF_SIZE, 0);
        if (recv_size <= 0)
            return 0;
        char my_args[128];
        sscanf(buffer, "%[^\r\n]\r\n%d\r\n", my_args, &file_size);
        sscanf(my_args, "%s", filename);
        filename[0] = 'r';
        filename[1] = 'e';

        printf("filename : %s, filesize: %d\n", filename, file_size);
        // 打开文件
        FILE* fp = fopen(filename, "wb");
        if (fp == NULL) {
            error_handling("File open error");
        }
        // 接收文件
        while (true) {
            recv_size = recv(clnt_sock, buffer, BUF_SIZE, 0);
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

        // 加壳
        int pid = fork();
        if (pid == 0) {
            int count = 0;
            char* args[10];
            args[count++] = "./packer/kiteshield";
            char* token = strtok(my_args, " ");
            while (token != NULL) {
                args[count++] = token;
                token = strtok(NULL, " ");
            }
            args[count] = NULL;
            for (int i = 0; i < count; i++) {
                printf("%s ", args[i]);
            }

            execv("./packer/kiteshield", args);
            perror("execv failed");
            exit(0);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
            printf("加壳完毕\n");
        }
        
        // 把加壳后的文件传送给客户端
        fp = fopen("hello_world_pak", "rb");
        if (fp == NULL) {
            error_handling("file open failed");
        }
        // // 发送二进制文件
        int bytes_read;
        while (true) {
            bytes_read = fread(buffer, 1, BUF_SIZE, fp);
            int sent_size = send(clnt_sock, buffer, bytes_read, 0);
            if (bytes_read <= 0)
                break;
        }
        send(clnt_sock, END_FLAG, FLAG_LEN, 0);
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
