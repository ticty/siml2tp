/***************************************************************************
 *            misc.h
 *            2012-3-8
 *
 *  Copyright  2012  guofeng
 *  <dev.guofeng@gmail.com>
 ****************************************************************************/
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor Boston, MA 02110-1301,  USA
 */



#ifndef MISC_H
#define MISC_H

#include "defines.h"
#include <stdio.h>
#include <termios.h>



/* maxium ip address length */
#define MAX_ADDRESS_LEN	128

/* maxium username length */
#define MAX_USERNAME_LEN	20

/* maxium password length */
#define MAX_PASSWORD_LEN	25

/* maxium path len */
#define MAX_PATH_LEN	1024

/* general maxium string length */
#define MAX_STRLEN_LEN	1024

/* HOST_NAME_MAX */
#define MAX_HOSTNAME_LEN	256

/* maxium packet length, in octet*/
#define MAX_PACKET_LEN	2048

/*
 * maxium file number that a process can open
 * this will be used when sysconf() return a wrong value
 */
#define MAX_FD	1024

/* msg_log level */
#define LEVEL_INFO	1
#define LEVEL_WARN	2
#define LEVEL_ERR	3



/* buf struct */
struct buffer
{
    _u8 packet[MAX_PACKET_LEN];
    _u8 *current;
    _u8 *end;

    _u16 ns;             /* this packet ns value, for send and cancal */
    int retry_times;    /* normally init with 0, if need to retransmit, begin set it to 1 */

    struct tunnel *t;
} ATTR(packed);



/* receive windows buffer */
struct  rw_buffer
{
    struct buffer *head;      /* packet vector */

    int size;       /* rws, the max length of head*/
    int count;      /* current number in head list */
};

extern int msg_log( int , const char *, ... ) ATTR(format(printf, 2, 3));
extern char * set_home_path( char *, int );
extern char *get_bin_path( const char *, char *, int );
extern char *fix_path_prefix( const char *, char *, int );
extern void init_buf( struct buffer * );
extern struct buffer *new_buf();
extern int nwrite( int , const char *, int  );
extern int xread( int , char *, int  );
extern int xfgets( char *, int , FILE * );
extern void print_packet( const char *, int );

extern void close_echo( struct termios * );
extern void restore_termconf( const struct termios * );

extern int get_pty(char *, int );

extern int is_vaild_ip( const char * );


#endif // MISC_H
