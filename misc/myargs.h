#ifndef ARGS_H
#define ARGS_H

#define BUF_SIZE 1024
struct m_args {
    char name[32];
    char encryption;
    char compression;
    char mac[6];
    int filesize;
};

#endif