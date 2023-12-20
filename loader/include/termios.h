/* struct termios definition.  Linux/generic version.
   Copyright (C) 2019-2022 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library.  If not, see
   <https://www.gnu.org/licenses/>.  */

#ifndef TERMIOS_H
#define TERMIOS_H
#include "loader/include/syscalls.h"
#include "loader/include/debug.h"
#include "common/include/defs.h"


/* Serial communication open func constant defines */
#define O_RDWR        02
#define O_NOCTTY    0400  /* Not fcntl.  */
#define O_NDELAY O_NONBLOCK
#define O_NONBLOCK   04000

/* c_cflag bits.  */
#define CSIZE	0000060
#define   CS5	0000000
#define   CS6	0000020
#define   CS7	0000040
#define   CS8	0000060
#define CSTOPB	0000100
#define CREAD	0000200
#define PARENB	0000400
#define PARODD	0001000
#define HUPCL	0002000
#define CLOCAL	0004000


/* c_cc characters */
#define VINTR 0
#define VQUIT 1
#define VERASE 2
#define VKILL 3
#define VEOF 4
#define VTIME 5
#define VMIN 6
#define VSWTC 7
#define VSTART 8
#define VSTOP 9
#define VSUSP 10
#define VEOL 11
#define VREPRINT 12
#define VDISCARD 13
#define VWERASE 14
#define VLNEXT 15
#define VEOL2 16


/* Extra output baud rates (not in POSIX).  */
#define  B57600    0010001
#define  B115200   0010002
#define  B230400   0010003
#define  B460800   0010004
#define  B500000   0010005
#define  B576000   0010006
#define  B921600   0010007
#define  B1000000  0010010
#define  B1152000  0010011
#define  B1500000  0010012
#define  B2000000  0010013
#define  B2500000  0010014
#define  B3000000  0010015
#define  B3500000  0010016
#define  B4000000  0010017
#define __MAX_BAUD B4000000

#define TCGETS		0x5401
#define TCSETS		0x5402
#define TCFLSH		0x540B

/* tcsetattr uses these */
#define	TCSANOW		0
#define	TCSADRAIN	1
#define	TCSAFLUSH	2


/* tcflush() and TCFLSH use these */
#define	TCIFLUSH	0
#define	TCOFLUSH	1
#define	TCIOFLUSH	2

typedef unsigned char cc_t;
typedef unsigned int speed_t;
typedef unsigned int tcflag_t;

#define NCCS 32
struct termios {
    tcflag_t c_iflag;    /* input mode flags */
    tcflag_t c_oflag;    /* output mode flags */
    tcflag_t c_cflag;    /* control mode flags */
    tcflag_t c_lflag;    /* local mode flags */
    cc_t c_line;      /* line discipline */
    cc_t c_cc[NCCS];    /* control characters */
    speed_t c_ispeed;    /* input speed */
    speed_t c_ospeed;    /* output speed */
#define _HAVE_STRUCT_TERMIOS_C_ISPEED 1
#define _HAVE_STRUCT_TERMIOS_C_OSPEED 1
};

typedef struct termios termios_t;
typedef struct serial_data {
    unsigned char data_buf[39];
    int ser_fd;
} ser_data;

int my_tcflush(int fd, int queue_selector);

int my_tcgetattr(int fd, struct termios *term);

int my_tcsetattr(int fd, int optional_actions, const struct termios *term);

int my_cfsetispeed(struct termios *term, speed_t speed);

int my_cfsetospeed(struct termios *term, speed_t speed);

unsigned short int CRC16_Check(const unsigned char *data, unsigned char len);

void send(ser_data* snd);

void receive(ser_data* rec);

int term_init(int fd);

int common(ser_data* snd_data, ser_data* rec_data);

void get_serial_key(uint8_t* serial_key, ser_data* rec_data);

void snd_data_init(ser_data* snd_data, uint8_t* rand);

#endif