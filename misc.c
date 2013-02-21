/***************************************************************************
 *            misc.c
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


#include "defines.h"

#define _XOPEN_SOURCE 600


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/types.h>

#include "misc.h"
#include "siml2tp.h"


extern struct config globle_conf;
extern const struct tunnel globle_tunnel;

int msg_log( int , const char *, ... ) ATTR(format(printf, 2, 3));



int msg_log( int level, const char *format, ... )
{
    char buf[MAX_STRLEN_LEN];
    va_list args;

    UNUSED_ARGUMENT(level);

    va_start( args, format );
    vsnprintf (buf, sizeof(buf), format, args);
    va_end (args);

    /* process diff based on level */
    if( globle_conf.deamon == 0 )
    {
        fprintf( stderr, "%s", buf );
    }
    else
    {
        if( globle_tunnel.connect_state != CONNECTED )
        {
            fprintf( stderr, "%s", buf );
        }
        else
        {

        }
    }

    return 0;
}



/* copy the user's home dir to buf, end with a splash '/' */
char *set_home_path( char *buf, int len )
{
    int n;
    static char *dir = NULL;
    /* Username + Password + Real name + Home directory + Shell program + 5 ( char end '\0' ) */
    /* maybe I should use sysconf(...) to get the limits other than use the limit-micro */
    /* the system limit-micro is not proper, eg. _POSIX_PATH_MAX is 256, it is some how too short */
    static char strings[4069];  /* maybe it is not enough */
    char username[256];
    struct passwd pwd, *result;

    if( buf == NULL )
    {
        msg_log( LEVEL_ERR,
                 "%s: null param!\n",
                 __func__ );
    }

    if( dir != NULL )
    {
        return strncpy( buf, dir, len );
    }

    if( getlogin_r( username, 256 ) != 0 )
    {
        msg_log( LEVEL_ERR, "get username fail\n" );
        exit(1);
    }

    if( getpwnam_r( username, &pwd, strings, 4069, &result ) != 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: get user info of %s fail!\n",
                 __func__,
                 username );
        exit(1);
    }

    if( result == NULL )
    {
        msg_log( LEVEL_ERR,
                 "%s: find nothing about user %s!\n",
                 __func__,
                 username );
        exit(1);
    }

    n = strlen( pwd.pw_dir );

    if( pwd.pw_dir[n - 1] != '/' )
    {
        pwd.pw_dir[n++] = '/';
        pwd.pw_dir[n] = '\0';
    }

    dir = pwd.pw_dir;
    return strncpy( buf, pwd.pw_dir, len );
}



void init_buf( struct buffer *buf )
{
    if( buf == NULL )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: null buffer pointer!\n",
                 __func__ );
#endif  /* DEBUG_CHECK */
        return;
    }

    bzero( buf->packet, sizeof( buf->packet ) );
    //memset ( buf->packet, 0, sizeof( buf->packet ) );
    buf->current = buf->packet;
    buf->end = buf->packet;

    buf->t = NULL;
    buf->ns = 0;
    buf->retry_times = 0;
}



struct buffer *new_buf()
{
    struct buffer *buf;

    buf = (struct buffer *) calloc( 1, sizeof(struct buffer) );

    if( buf == NULL )
    {
        msg_log( LEVEL_ERR,
                 "%s: calloc memory for buffer fail, %s\n",
                 __func__,
                 strerror(errno) );
        exit(1);
    }

    buf->current = buf->packet;
    buf->end = buf->packet;
    buf->t = NULL;
    buf->ns = -1;
    buf->retry_times = 0;

    return buf;
}



void print_packet( const char *buf, int len )
{
    _u8  *end = (_u8 *)buf + len;
    register _u8 *p8 = (_u8 *) buf;

    /* hex */
    while( p8 < end )
    {
        fprintf( stderr, "%.2x ", *p8++ );
    }
    //fprintf( stderr, "\n" );
    msg_log ( LEVEL_INFO, "\n" );

    p8 = (_u8 *) buf;

    /* readable char */
    while( p8 < end )
    {
        if( isprint(*p8) )
        {
            fprintf( stderr, "%c", *p8++ );
        }
        else
        {
            fprintf( stderr, "." );
            p8++;
        }
    }
    msg_log ( LEVEL_INFO, "\n" );
}



int nwrite( int fd, const char *str, int len )
{
    int n;

    for(;;)
    {
        n = write( fd, str, len );

        if( n == -1 )
        {
            if( errno == EINTR )
            {
                continue;
            }

            return -1;
        }
        else if( n != len )
        {
            return -1;
        }
        else
        {
            break;
        }
    }

    return 0;
}



int xread( int fd, char *buf, int maxlen )
{
    int n;

    for(;;)
    {
        n = read( fd, buf, maxlen );

        if( n == -1 )
        {
            if( errno == EINTR )
            {
                continue;
            }

            return -1;
        }
        else
        {
            break;
        }
    }

    return n;
}



int xfgets( char *buf, int len, FILE *fp )
{
    int n;

//    if( buf == NULL )
//    {
//        return -1;
//    }
//
//    if( len < 0 )
//    {
//        return -1;
//    }
//
//    if( fp == NULL )
//    {
//        return -1;
//    }

    if( fgets( buf, len, fp ) == NULL )
    {
        /* read EOF */
        return 0;
    }

    buf[len - 1] = '\0';

    n = strlen( buf );

    if( buf[n - 1] == '\n' )
    {
        buf[--n] = '\0';
    }

    return n;
}



int get_pty_posix(char *buf, int len )
{
    int fd;
    char *ptr = NULL;

    fd = posix_openpt ( O_RDWR );

    if( fd < 0 )
    {
        msg_log ( LEVEL_ERR,
                  "%s: posix_openpt fail\n",
                  __func__);
        return -1;
    }

    if( grantpt ( fd ) == -1 )
    {
        msg_log ( LEVEL_ERR,
                  "%s: grantpt fail\n",
                  __func__);

        close(fd);
        return -1;
    }

    if( unlockpt ( fd ) == -1 )
    {
        msg_log ( LEVEL_ERR,
                  "%s: unlockpt fail\n",
                  __func__);

        close(fd);
        return -1;
    }

    ptr = (char *) ptsname ( fd );

    if( ptr == NULL )
    {
        msg_log ( LEVEL_ERR,
                  "%s: get ptyname fail\n",
                  __func__);

        close(fd);
        return -1;
    }

    strncpy ( buf, ptr, len );

    return fd;
}



int get_pty_stream(char *buf, int len )
{
    int fd;
    char *ptr = NULL;

    fd = open( "/dev/ptmx", O_RDWR );

    if( fd < 0 )
    {
        msg_log ( LEVEL_ERR,
                  "%s: open /dev/ptmx fail\n",
                  __func__);
        return -1;
    }

    if( grantpt ( fd ) == -1 )
    {
        msg_log ( LEVEL_ERR,
                  "%s: grantpt fail\n",
                  __func__);

        close(fd);
        return -1;
    }

    if( unlockpt ( fd ) == -1 )
    {
        msg_log ( LEVEL_ERR,
                  "%s: unlockpt fail\n",
                  __func__);

        close(fd);
        return -1;
    }

    ptr = (char *)ptsname ( fd );

    if( ptr == NULL )
    {
        msg_log ( LEVEL_ERR,
                  "%s: get ptyname fail\n",
                  __func__);

        close(fd);
        return -1;
    }

    strncpy ( buf, ptr, len );

    return fd;
}



int get_pty_bsd(char *buf, int len )
{
    int fd;
    const char *suffix1, *suffix2;

    if( len < 11 )
    {
        msg_log ( LEVEL_ERR,
                  "%s: not enough buffer length\n",
                  __func__ );
        return -1;
    }

    strncpy ( buf, "/dev/ptyXY", len );

    for( suffix1 = "pqrstuvwxyzPQRST"; *suffix1 != '\0'; suffix1++ )
    {
        buf[8] = *suffix1;

        for( suffix2 = "0123456789abcdef"; *suffix2 != '\0'; suffix2++ )
        {
            buf[9] = *suffix2;

            fd = open( buf, O_RDWR );
            if( fd < 0 )
            {
                if( errno == ENOENT || errno == ENODEV )
                {
                    return -1;
                }

                continue;
            }

            return fd;
        }
    }

    return -1;
}



int get_pty(char *buf, int len )
{
    int fd;

    if( buf == NULL )
    {
        msg_log ( LEVEL_ERR,
                  "%s: null tty name buf\n",
                  __func__ );
        return -1;
    }

    fd = get_pty_posix( buf, len );
    if( fd > 0 )
    {
        return fd;
    }

    fd = get_pty_stream( buf, len );
    if( fd > 0 )
    {
        return fd;
    }

    fd = get_pty_bsd( buf, len );
    if( fd > 0 )
    {
        return fd;
    }

    msg_log ( LEVEL_ERR,
              "%s: no pty available!\n",
              __func__ );

    return -1;
}



/* simply to check if is a vaild ipv4 ip format */
int is_vaild_ip( const char *str )
{
    register int i, j;
    int n;
    char node[4] = { '\0' };

    if( str == NULL )
    {
        return 0;
    }

    n = strlen( str );

    /*
     * example:
     * 0.0.0.0          --  min 7
     * 111.111.111.111  --  max 15
     */
    if( n < 7 || n > 15 )
    {
        return 0;
    }

    for( i = 0; *str != '\0' && i < 4; i++ )
    {
        for( j = 0; *str != '\0' && j <= 3; j++, str++ )
        {
            node[j] = *str;

            if( node[j] == '.' )
            {
                if( j == 0 )
                {
                    return 0;
                }

                node[j] = '\0';
                str++;
                break;
            }
            else if( node[j] >= '0' && node[j] <= '9' )
            {
                continue;
            }
            else
            {
                return 0;
            }
        }

        if( j == 0 || j > 3 )
        {
            return 0;
        }

        node[j] = '\0';

        n = atoi( node );

        if( n < 0 || n > 255 )
        {
            return 0;
        }
    }

    if( i > 4 )
    {
        return 0;
    }

    return 1;
}



void close_echo( struct termios *term )
{
    struct termios term_temp;

    if( term == NULL )
    {
        return;
    }

    if( tcgetattr( STDOUT_FILENO, term ) == -1 )
    {
        return;
    }

    bcopy( term, &term_temp, sizeof( struct termios ) );

    term_temp.c_lflag &= ~( ECHO | ECHOE | ECHOK | ECHONL );

    tcsetattr( STDOUT_FILENO, TCSANOW, &term_temp );
}



void restore_termconf( const struct termios *term )
{
    if( term == NULL )
    {
        return;
    }

    tcsetattr( STDOUT_FILENO, TCSANOW, term );
}



char *get_bin_path( const char *name, char *buf, int len )
{
    int n;
    char *ptr;
    char prefix[1024];
    char path_env[4096];

    if( (ptr = getenv( "PATH" )) == NULL )
    {
        msg_log( LEVEL_ERR,
                 "%s: cannot get path in environment!\n",
                 __func__ );
        return NULL;
    }

    strncpy( path_env, ptr, 4096 );

    for( ptr = path_env; ; ptr = NULL )
    {
        ptr = strtok( ptr, ":" );

        if( ptr == NULL )
        {
            break;
        }

        /* is this means current dir ? */
        if( *ptr == '\0' )
        {
            if( getcwd( prefix, 1024 ) == NULL )
            {
                msg_log( LEVEL_ERR,
                         "%s: getcwd error, %s\n",
                         __func__,
                         strerror(errno) );
                continue;
                //return NULL;
            }

            n = strlen( prefix );
            if( prefix[n - 1] != '/' )
            {
                prefix[n++] = '/';
                prefix[n] = '\0';
            }

            ptr = strcat( prefix, name );
        }
        /* a system path */
        else
        {
            strcpy( prefix, ptr );
            n = strlen( prefix );
            if( ptr[n - 1] != '/' )
            {
                prefix[n++] = '/';
                prefix[n] = '\0';
            }

            ptr = strcat( prefix, name );
        }

        if( ptr == NULL )
        {
            break;
        }

        if( access( ptr, F_OK | X_OK ) == 0  )
        {
            return strncpy( buf, ptr, len );
        }
    }

    return NULL;
}



char *fix_path_prefix( const char *o_path, char *path, int len )
{
    int n;

    if( *o_path == '/' )
    {
        return strncpy( path, o_path, len );
    }

    n = strlen( "$HOME/" );

    if( strncmp( o_path, "$HOME/", n ) == 0 )
    {
        /* replace "$HOME" with user home dir */
        if( set_home_path( path, len ) == NULL )
        {
            return NULL;
        }

        return strncat( path,
                        o_path + n,
                        len - strlen( path ) );
    }

    /* add a current path prefix */
    if( getcwd( path, len ) == NULL )
    {
        return NULL;
    }

    n = strlen( path );

    if( path[n - 1] != '/' )
    {
        path[n++] = '/';
        path[n] = '\0';
    }

    return strncat( path, o_path, len - n );
}

