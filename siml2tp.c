/***************************************************************************
 *            siml2tp.c
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/types.h>
#include <signal.h>
#include <arpa/inet.h>

#include "misc.h"
#include "siml2tp.h"
#include "network.h"
#include "schedule.h"
#include "avp.h"


extern struct config globle_conf;
extern struct tunnel globle_tunnel;

extern void force_exit( void * );


const _u16 ppp_crc16_table[256] = {
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};




void restore_config( struct config *conf )
{
    if( conf == NULL )
    {
        msg_log( LEVEL_ERR, "globle config arg is null!\n" );
        exit(1);
    }

    if( conf->interface == NULL )
    {
        msg_log( LEVEL_ERR, "interface of globle config is null!\n" );
        exit(1);
    }
    else
    {
        bzero( conf->interface, sizeof(conf->interface) );
    }

    conf->rt_head = NULL;

    if( conf->gateway == NULL )
    {
        msg_log( LEVEL_ERR, "gateway of globle config is null!\n" );
        exit(1);
    }
    else
    {
        bzero( conf->gateway, sizeof(conf->gateway) );
    }

    if( conf->rt_dev == NULL )
    {
        msg_log( LEVEL_ERR, "rt_dev of globle config is null!\n" );
        exit(1);
    }
    else
    {
        bzero( conf->rt_dev, sizeof(conf->rt_dev) );
    }

    if( conf->ppp_path == NULL )
    {
        msg_log( LEVEL_ERR, "ppp_path of globle config is null!\n" );
        exit(1);
    }
    else
    {
        bzero( conf->ppp_path, sizeof(conf->ppp_path) );
    }

    if( conf->hostname == NULL )
    {
        msg_log( LEVEL_ERR, "host1 of globle config is null!\n" );
        exit(1);
    }
    else
    {
        bzero( conf->hostname, sizeof(conf->hostname) );
    }

    if( conf->host == NULL )
    {
        msg_log( LEVEL_ERR, "host of globle config is null!\n" );
        exit(1);
    }
    else
    {
        bzero( conf->host, sizeof(conf->host) );
    }

    if( conf->username == NULL )
    {
        msg_log( LEVEL_ERR, "username of globle config is null!\n" );
        exit(1);
    }
    else
    {
        bzero( conf->username, sizeof(conf->username) );
    }

    if( conf->password == NULL )
    {
        msg_log( LEVEL_ERR, "password of globle config is null!\n" );
        exit(1);
    }
    else
    {
        bzero( conf->password, sizeof(conf->password) );
    }

    if( conf->config_path == NULL )
    {
        msg_log( LEVEL_ERR, "config_path of globle config is null!\n" );
        exit(1);
    }
    else
    {
        bzero( conf->config_path, sizeof(conf->config_path) );
        set_home_path( conf->config_path, sizeof( conf->config_path ) );
        strcat( conf->config_path,DEFAULT_CONF_PREFIX );
        strcat( conf->config_path, DEFAULT_CONF );
    }

    if( conf->ppp_conf_path == NULL )
    {
        msg_log( LEVEL_ERR, "ppp_conf_path of globle config is null!\n" );
        exit(1);
    }
    else
    {
        bzero( conf->ppp_conf_path, sizeof(conf->ppp_conf_path) );
        set_home_path( conf->ppp_conf_path, sizeof( conf->ppp_conf_path ) );
        strcat( conf->ppp_conf_path, DEFAULT_CONF_PREFIX );
        strcat( conf->ppp_conf_path, DEFAULT_PPP_CONF );
    }

    if( conf->ppp_pwdfd_path == NULL )
    {
        msg_log( LEVEL_ERR, "ppp_path of globle config is null!\n" );
        exit(1);
    }
    else
    {
        bzero( conf->ppp_pwdfd_path, sizeof(conf->ppp_pwdfd_path) );
        set_home_path( conf->ppp_pwdfd_path, sizeof( conf->ppp_pwdfd_path ) );
        strcat( conf->ppp_pwdfd_path, DEFAULT_CONF_PREFIX );
        strcat( conf->ppp_pwdfd_path, DEFAULE_PWDFD );
    }

    conf->deamon = DFL_IS_DEAMON;
    conf->port = DFL_PORT;
    //conf->is_reconnect = DFL_IS_RECONNECT;
    //conf->max_reconnect = DFL_MAX_RECONNECT;
    conf->max_resend = DLF_MAX_RESEND;
    conf->rws = DFL_RECV_WIN_SIZE;
}



void restore_call( struct call *c )
{
    if( c == NULL )
    {
#ifdef DEBUG_CHECK
        msg_log ( LEVEL_ERR,
                  "%s: call param is null\n",
                  __func__ );
#endif  /* DEBUG_CHECK */
        return;
    }

    c->tunnel = &globle_tunnel;
    c->call_state = 0;
    c->ppp_fd = -1;

    /* ppp_pid set to -1 */
    c->ppp_pid = -1;

    bzero( &c->ppp_local, sizeof( struct in_addr ) );
    bzero( &c->ppp_remote, sizeof( struct in_addr ) );

    /* default set only SYNC_FRAME support */
    //c->frame_cap = SYNC_FRAME;

    //c->peer_frame_cap = 0;

    /* default session id set to 1 */
    c->ass_sid = 1;

    /* default peer session id set to 0 */
    c->peer_sid = 0;

    c->serial_num = CALL_SERIAL_NUMBER;

    /* default Tx connect speed */
    //c->tx_con_speed = DFL_TX_CONNECT_SPEED;

    /* default Rx connect speed */
    //c->rx_con_speed = DFL_RX_CONNECT_SPEED;

    /* default proxy authen type */
    //c->proxy_auth_type = NO_AUTHEN;

    /* default call serial number set to 0 */
    //c->cid = 0;

    /* call close_state set default to 0 */
    c->close_state = 0;

    /* terminal device attr */
    c->o_termconf = NULL;

    //c->result_code = 0xffff;
    //c->error_code = 0xffff;

    //bzero( c->err_msg, MAX_ERR_MSG_LEN );
}



void clean_call( struct call *c )
{
    if( c == NULL )
    {
#ifdef DEBUG_CHECK
        msg_log ( LEVEL_ERR,
                  "%s: call param is null\n",
                  __func__ );
#endif  /* DEBUG_CHECK */
        return;
    }

    if( c->ppp_pid > 0 )
    {
        /* Ques: if pppd will terminal after recv a SIGINT signal ? */
        kill( c->ppp_pid, SIGINT );
        c->ppp_pid = -1;
    }

    if( c->ppp_fd > 0 )
    {
        if( c->o_termconf != NULL )
        {
            tcsetattr( c->ppp_fd, TCSANOW, c->o_termconf );
            free( c->o_termconf );
            c->o_termconf = NULL;
        }

        close( c->ppp_fd );
        c->ppp_fd = -1;
    }

    restore_call ( c );
}



void restore_tunnel( struct tunnel *t )
{
    if( t == NULL )
    {
        msg_log( LEVEL_ERR,
                 "%s: tunnel arg is null!\n",
                 __func__);
        exit(1);
    }

    bzero( &t->server_addr, sizeof(struct sockaddr_in) );

    t->sockfd = -1;

    t->tunnel_state = 0;
    t->connect_state = DISCONNECTED;

    t->ns = 0;
    t->nr = 0;

    /* default set only SYNC_FRAME support */
    //t->frame_cap = SYNC_FRAME;

    /* set default bearer type */
    //t->bearer_type = DFL_BEARER_TYPE;

    /* set default receive-window-size */
    t->receive_win_size = 0;

    /* self tunnel id default set to 2 */
    t->ass_tid = 2;

    /* default peer session id set to 0 */
    t->peer_tid = 0;

    /* retry times */
    //t->retry_times = 0;
    //t->max_retry_times = MAX_RETRY_TIMES;

    /* initial call belong to it */
    t->call.tunnel = t;

    t->config = &globle_conf;

    /* close state set to null */
    t->close_state = 0;

    /* init receive windows buffer */
    t->rw_buf.count = 0;
    t->rw_buf.size = 0;
    t->rw_buf.head = NULL;

    t->need_send_ack = 0;
    t->need_control = 0;

    //t->max_resend = DLF_MAX_RESEND;

    //t->result_code = 0xffff;
    //t->error_code = 0xffff;
    //bzero( t->err_msg, MAX_ERR_MSG_LEN );
}



void init_tunnel( struct tunnel *t )
{
    int err;
    struct addrinfo hints, *res;

    char temp[10];

    if( t == NULL )
    {
        msg_log( LEVEL_ERR,
                 "%s: tunnel arg is null!\n",
                 __func__);
        exit(1);
    }

    bzero( &t->server_addr, sizeof(struct sockaddr_in) );

    /* find server */
    bzero( &hints, sizeof( struct addrinfo ) );
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    snprintf( temp, 10, "%d", globle_conf.port );
    err = getaddrinfo( globle_conf.host, temp, &hints, &res );

    if( err != 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: can not get server address info, %s\n",
                 __func__,
                 gai_strerror(err) );
        exit(1);
    }

    bcopy( res->ai_addr, &t->server_addr, res->ai_addrlen );

    /* make socket */
    t->sockfd = socket( res->ai_family, res->ai_socktype, res->ai_protocol );

    if( t->sockfd < 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: socket error, %s\n",
                 __func__,
                 strerror(errno) );
        exit(1);
    }

    /* bind device */
    if( globle_conf.interface[0] != '\0' )
    {
        /* set outgoing interface */
        if( setsockopt( t->sockfd,
                        SOL_SOCKET,
                        SO_BINDTODEVICE,
                        globle_conf.interface,
                        strlen(globle_conf.interface) + 1 ) == -1 )
        {
            msg_log( LEVEL_ERR,
                     "%s: setsockopt(SO_BINDTODEVICE) fail, %s\n",
                     __func__,
                     strerror(errno) );

            exit(1);
        }
    }

    /* connect socket */
    if( connect( t->sockfd,
                 (struct sockaddr *)&t->server_addr,
                 sizeof(t->server_addr) ) == -1 )
    {
        msg_log( LEVEL_ERR,
                 "%s: connect error, %s\n",
                 __func__,
                 strerror(errno) );

        close(t->sockfd);
        t->sockfd = -1;
        exit(1);
    }

    freeaddrinfo(res);

    t->tunnel_state = 0;
    t->connect_state = DISCONNECTED;

    t->ns = 0;
    t->nr = 0;

    /* default set only SYNC_FRAME support */
    //t->frame_cap = SYNC_FRAME;

    /* set default bearer type */
    //t->bearer_type = DFL_BEARER_TYPE;

    /* set default receive-window-size */
    t->receive_win_size = globle_conf.rws;

    /* self tunnel id default set to 2 */
    t->ass_tid = 1;

    /* default peer session id set to 0 */
    t->peer_tid = 0;

    /* retry times */
    //t->retry_times = 0;
    //t->max_retry_times = MAX_RETRY_TIMES;
    //t->max_resend = DLF_MAX_RESEND;

    /* initial call belong to it */
    restore_call( &t->call );
    t->call.tunnel = t;

    t->config = &globle_conf;

    /* close state set to null */
    t->close_state = 0;

    /* init receive windows buffer */
    t->rw_buf.count = 0;
    t->rw_buf.size = t->receive_win_size;

    if( t->rw_buf.size > 0 )
    {
        t->rw_buf.head = (struct buffer *) calloc( t->rw_buf.size, sizeof(struct buffer) );

        if( t->rw_buf.head == NULL )
        {
            msg_log( LEVEL_ERR,
                     "%s: calloc fail for rw_buf\n",
                     __func__ );
            exit(1);
        }
    }
    else
    {
        t->rw_buf.head = NULL;
    }

    t->need_send_ack = 0;
    t->need_control = 0;

    //t->result_code = 0xffff;
    //t->error_code = 0xffff;
    //bzero( t->err_msg, MAX_ERR_MSG_LEN );
}



void clean_tunnel( struct tunnel *t )
{
    /*
     * since there exist only one tunnel, so exit.
     * if future add mutipy support, here just clean specialled tunnel
     */

    if( t == NULL )
    {
#ifdef  DEBUG_CHECK
        msg_log ( LEVEL_ERR,
                  "%s: null param!\n",
                  __func__ );
#endif  /* DEBUG_CHECK */
        return;
    }

    if( t->sockfd > 0 )
    {
        close ( t->sockfd );
        t->sockfd = -1;
    }

    clean_rw_buf( t );
    restore_tunnel ( t );
}



int start_pppd( struct tunnel *t )
{
    int i;
    int fd;
    int pppd_passwdfd[2];
    char pppd_passwdbuf[10];
    char pty_name[512];
    char *opt[MAX_ARG];
    struct termios ptyconf;

    t->call.ppp_fd = get_pty( pty_name, 512 );

    if( t->call.ppp_fd < 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: could not get a pty\n",
                 __func__ );
        return -1;
    }

    if( tcgetattr( t->call.ppp_fd, &ptyconf) == -1 )
    {
        msg_log( LEVEL_ERR,
                 "%s: tcgetattr fail, %s\n",
                 __func__,
                 strerror(errno) );

        close(t->call.ppp_fd);
        t->call.ppp_fd = -1;
        return -1;
    }

    t->call.o_termconf = ( struct termios * ) malloc( sizeof(struct termios) );
    if( t->call.o_termconf == NULL )
    {
        msg_log( LEVEL_ERR,
                 "%s: alloc memory for o_termconf fail, %s\n",
                 __func__,
                 strerror(errno) );

        close(t->call.ppp_fd);
        t->call.ppp_fd = -1;
        return -1;
    }

    bcopy( &ptyconf, t->call.o_termconf, sizeof(struct termios) );

    ptyconf.c_lflag &= ~( ICANON | ECHO );

    if( tcsetattr( t->call.ppp_fd, TCSANOW, &ptyconf) == -1 )
    {
        msg_log( LEVEL_ERR,
                 "%s: tcsetattr fail, %s\n",
                 __func__,
                 strerror(errno) );

        close(t->call.ppp_fd);
        t->call.ppp_fd = -1;
        return -1;
    }

    if( fcntl( t->call.ppp_fd, F_SETFL, O_NONBLOCK) != 0 )
    {
       msg_log( LEVEL_ERR,
                "%s: failed to set nonblock: %s\n",
                __func__,
                strerror(errno));

       return -1;
    }

    fd = open( pty_name, O_RDWR );
    if( fd < 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: open pty fail, %s\n",
                 __func__,
                 strerror(errno) );

        return -1;
    }

    i = 0;
    opt[i++] = strdup( globle_conf.ppp_path );

    if( globle_conf.ppp_conf_path[0] != 0 )
    {
        opt[i++] = strdup( "file" );
        opt[i++] = strdup( globle_conf.ppp_conf_path );
    }
    
    opt[i++] = strdup( "nodetach" );
    opt[i++] = strdup( "hide-password" );
    opt[i++] = strdup( "passive" );
    opt[i++] = strdup( "silent" );

    opt[i++] = strdup( pty_name );

    if( globle_conf.username[0] != 0 )
    {
        opt[i++] = strdup( "name" );
        opt[i++] = strdup( globle_conf.username );

        if( globle_conf.password[0] != 0 )
        {
            /* pass password to pppd via pipe */
            if( globle_conf.password[0] != 0 )
            {
                if ( pipe (pppd_passwdfd) == -1)
                {
                    msg_log( LEVEL_ERR,
                             "%s: Unable to create password pipe for pppd\n",
                             __func__ );
                    return -1;
                }

                if ( nwrite(pppd_passwdfd[1],
                           globle_conf.password,
                           strlen(globle_conf.password) ) == -1 )
                {
                    msg_log( LEVEL_ERR,
                            "%s: Unable to write password to pipe for pppd\n",
                            __func__);

                    close (pppd_passwdfd[1]);
                    return -1;
                }

                /* clear memory for safety */
                bzero( globle_conf.password, sizeof(globle_conf.password) );

                close (pppd_passwdfd[1]);

                /* pppd passwordfd plugin */
                opt[i++] = strdup( "plugin" );

                if( globle_conf.ppp_pwdfd_path[0] != 0 )
                {
                    opt[i++] = strdup( globle_conf.ppp_pwdfd_path );
                }
                else
                {
                    opt[i++] = strdup( "passwordfd.so" );
                }

                opt[i++] = strdup( "passwordfd" );

                snprintf( pppd_passwdbuf, 10, "%d", pppd_passwdfd[0] );
                opt[i++] = strdup( pppd_passwdbuf );
            }
        }
    }

    opt[i] = NULL;

    t->call.ppp_pid = fork();

    if( t->call.ppp_pid == 0 )
    {
        close(t->call.ppp_fd);
        close( t->sockfd );
        dup2 (fd, 0);
        dup2 (fd, 1);
        /*
         * some ppp info will print in fd 2,
         * we do not want to get them
         */
        //dup2 (fd, 2);
        close(fd);

        /* set uid to euid */
        if( getuid() != 0 )
        {
            setuid( geteuid() );
        }

        execv( globle_conf.ppp_path, opt );

        msg_log( LEVEL_ERR,
                 "%s: exec fail, %s\n",
                 __func__,
                 strerror(errno) );
        exit(1);
    }
    else if( t->call.ppp_pid < 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: fork error, %s\n",
                 __func__,
                 strerror(errno) );

        return -1;
    }

    close(fd);

    i = 0;
    while( opt[i] != NULL )
    {
        free(opt[i]);
        opt[i++] = NULL;
    }

    return 0;
}



inline void l2tp_add_data_hdr_s( struct tunnel *t, struct buffer *buf )
{
    struct l2tp_data_hdr_s *ptr = (struct l2tp_data_hdr_s *) buf->packet;

    /*  */
    ptr->head_node = htons( L2TP_VER );

    /* tunnel id */
    ptr->tid = htons( t->peer_tid );

    /* session id */
    ptr->sid = htons( t->call.peer_sid );

    buf->current = buf->packet;
    buf->retry_times = 0;
}



inline void l2tp_add_ctl_hdr( struct tunnel *t, struct buffer *buf )
{
    struct l2tp_ctl_hdr *ptr = (struct l2tp_ctl_hdr *) buf->current;
    /*  */
    ptr->head_node = htons( 0xc000 | 0x0800 | L2TP_VER );

    /* length */
    ptr->length = htons( buf->end - buf->packet );

    /* tunnel id */
    ptr->tid = htons( t->peer_tid );

    /* session id */
    ptr->sid = htons( t->call.peer_sid );

    /* Ns */
    if( t->need_send_ack == 1 )
    {
        ptr->ns = htons( t->ns );
        t->need_send_ack = 0;
    }
    else
    {
        ptr->ns = htons( t->ns++ );
    }

    /* Nr */
    ptr->nr = htons( t->nr );
}



/*
 * The following AVP MUST be present in the SCCRQ:
 *		Message Type AVP
 *		Protocol Version
 *		Host Name
 *		Framing Capabilities
 *		Assigned Tunnel ID
 *
 * The following AVP MAY be present in the SCCRQ:
 *		Bearer Capabilities
 *		Receive Window Size
 *		Challenge
 *		Tie Breaker
 *		Firmware Revision
 *		Vendor Name
 */
void tunnel_send_SCCRQ( void *tunnel )
{
    struct buffer *buf;
    struct tunnel *t = (struct tunnel *) tunnel;

    if( t == NULL )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: null tunnel pointer!\n",
                 __func__ );
#endif	/* DEBUG_CHECK */
        return;
    }

    if( t->tunnel_state != 0 )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: only tunnel state %x can send %x type control packet!\n",
                 __func__,
                 0,
                 SCCRQ );
#endif	/* DEBUG_CHECK */
        return;
    }

    buf = new_buf();

    buf->current += sizeof(struct l2tp_ctl_hdr);

    /* must contain below */
    avp_add_msg_type( SCCRQ, buf );
    avp_add_protocol_ver( buf );
    avp_add_hostname( t, buf );
    avp_add_frame_caps( t, buf );
    avp_add_ass_tid( t, buf );

    /* opt contain below */
    //avp_add_bearer_cap( t, &buf );
    //avp_add_firmware_rev( &buf );
    //avp_add_vendor_name( &buf );
    //avp_add_recv_win_size( t, &buf );

    buf->end = buf->current;
    buf->current = buf->packet;

    l2tp_add_ctl_hdr( t, buf );

    buf->t = t;
    buf->ns = t->ns;
    buf->retry_times = 1;

    send_packet( buf );
}



/*
 * The following AVP MUST be present in the SCCCN:
 *      Message Type
 *
 * The following AVP MAY be present in the SCCCN:
 *      Challenge Response
 */
void tunnel_send_SCCCN( void *tunnel )
{
    struct buffer *buf;
    struct tunnel *t = (struct tunnel *) tunnel;

    if( t == NULL )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: null tunnel pointer!\n",
                 __func__ );
#endif	/* DEBUG_CHECK */
        return;
    }

    if( t->tunnel_state != SCCRQ )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: only tunnel state %x can send %x type control packet!\n",
                 __func__,
                 SCCRQ,
                 SCCCN );
#endif  /* DEBUG_CHECK */
        return;
    }

    buf = new_buf();

    buf->current += sizeof(struct l2tp_ctl_hdr);

    avp_add_msg_type( SCCCN, buf );

    buf->end = buf->current;
    buf->current = buf->packet;

    l2tp_add_ctl_hdr( t, buf );

    buf->t = t;
    buf->ns = t->ns;
    buf->retry_times = 1;

    send_packet( buf );
}



/*
 * The following AVPs MUST be present in the StopCCN:
 *      Message Type
 *      Assigned Tunnel ID
 *      Result Code
 */
void tunnel_send_StopCCN( void *tunnel )
{
    struct buffer *buf;
    struct tunnel *t = (struct tunnel *) tunnel;

    if( t == NULL )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: null tunnel pointer!\n",
                 __func__ );
#endif	/* DEBUG_CHECK */
        exit(1);
    }

    /*
    if( t->close_state != 1 )
    {
    msg_log( LEVEL_ERR,
         "%s: only tunnel close_state %d can send %x type control packet!\n",
         __func__,
         1,
         StopCCN );
    return;
    }
    */

    t->close_state = 2;
    t->tunnel_state = StopCCN;

    buf = new_buf();

    buf->current += sizeof(struct l2tp_ctl_hdr);

    avp_add_msg_type( StopCCN, buf );
    avp_add_ass_tid( t, buf );
    avp_add_result_code( t, buf );

    buf->end = buf->current;
    buf->current = buf->packet;

    l2tp_add_ctl_hdr( t, buf );

    /* session id should be null */
    ((struct l2tp_ctl_hdr *)buf->current)->sid = 0x0000;

    buf->t = t;
    buf->ns = t->ns;
    buf->retry_times = 1;

    send_packet( buf );

    /* set up a ack timeout */
    add_schedule( 3, force_exit, NULL );
}



/*
 * Zero Length Bit message only cintain a l2tp hdr
 */
void tunnel_send_ZLB( void *tunnel )
{
    struct buffer *buf;
    struct tunnel *t = (struct tunnel *) tunnel;

    if( t == NULL )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: null tunnel pointer!\n",
                 __func__ );
#endif	/* DEBUG_CHECK */
        return;
    }

    buf = new_buf();

    buf->end += sizeof(struct l2tp_ctl_hdr);
    l2tp_add_ctl_hdr( t, buf );

    buf->t = t;
    buf->ns = t->ns;
    buf->retry_times = 0;

    send_packet( buf );

    free( buf );
    buf = NULL;
}



/*
 * The Following AVP MUST be present in the HELLO message:
 *      Message Type
 */
/*
 * as a client, we need't to send hello,
 * unless we need a function
 * that disconnect if have no data transfer for a monent,
 * but still now, I have not implement this function
 */
//void tunnel_send_HELLO( void *tunnel )
//{
//    /* not implement now */
//    /* it is mainly for l2tp server */
//}



/*
 * The following AVPs MUST be present in the ICRQ:
 *      Message Type
 *      Assigned Session ID
 *      Call Serial Number
 *
 * The following AVPs MAY be present in the ICRQ:
 *      Bearer Type
 *      Physical Channel ID
 *      Calling Number
 *      Called Number
 *      Sub-Address
 */
void call_send_ICRQ( void *call )
{
    struct buffer *buf;
    struct tunnel *t = ((struct call *) call)->tunnel;

    if( t == NULL )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: null tunnel pointer!\n",
                 __func__ );
#endif	/* DEBUG_CHECK */
        return;
    }

    if( t->tunnel_state != SCCCN || t->call.call_state != 0 )
    {
#ifdef  DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: only connected tunnel and call state %x can send %x type control packet!\n",
                 __func__,
                 0,
                 ICRQ );
#endif  /* DEBUG_CHECK */
        return;
    }

    buf = new_buf();

    buf->current += sizeof(struct l2tp_ctl_hdr);

    avp_add_msg_type( ICRQ, buf );
    avp_add_ass_sid( t, buf );
    avp_add_call_S_num( t, buf );

    buf->end = buf->current;
    buf->current = buf->packet;

    l2tp_add_ctl_hdr( t, buf );

    buf->t = t;
    buf->ns = t->ns;
    buf->retry_times = 1;

    send_packet( buf );
}



/*
 * The following AVPs MUST be present in the ICCN:
 *      Message Type
 *      (Tx) Connect Speed
 *      Framing Type
 *
 * The following AVPs MAY be present in the ICCN:
 *      Initial Received LCP CONFREQ
 *      Last Sent LCP CONFREQ
 *      Last Received LCP CONFREQ
 *      Proxy Authen Type
 *      Proxy Authen Name
 *      Proxy Authen Challenge
 *      Proxy Authen ID
 *      Proxy Authen Response
 *      Private Group ID
 *      Rx Connect Speed
 *      Sequencing Required
 */
void call_send_ICCN( void *call )
{
    struct buffer *buf;
    struct tunnel *t = ((struct call *) call)->tunnel;

    if( t == NULL )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: null tunnel pointer!\n",
                 __func__ );
#endif	/* DEBUG_CHECK */
        return;
    }

    if( t->tunnel_state != SCCCN || t->call.call_state != ICRQ )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: only connected tunnel and call state %x can send %x type control packet!\n",
                  __func__,
                 ICRQ,
                 ICCN );
#endif  /* DEBUG_CHECK */
        return;
    }

    buf = new_buf();

    buf->current += sizeof(struct l2tp_ctl_hdr);

    avp_add_msg_type( ICCN, buf );
    avp_add_Tx_con_speed( t, buf );
    avp_add_frame_type( t, buf );

    /* optional contain below */
    //avp_add_proxy_auth_type( t, &buf );
    //avp_add_Rx_con_speed( t, &buf );

    buf->end = buf->current;
    buf->current = buf->packet;

    l2tp_add_ctl_hdr( t, buf );

    buf->t = t;
    buf->ns = t->ns;
    buf->retry_times = 1;

    send_packet( buf );
}



/*
 * The following AVPs MUST be present in the CDN:
 *      Message Type
 *      Result Code
 *      Assigned Session ID
 *
 * The following AVPs MAY be present in the CDN:
 *      Cause Code
 */
void call_send_CDN( void *call )
{
    struct buffer *buf;
    struct tunnel *t = ((struct call *) call)->tunnel;

    if( t == NULL )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: null tunnel pointer!\n",
                 __func__ );
#endif	/* DEBUG_CHECK */
        return;
    }

//    if( t->call.close_state != 1 )
//    {
//        msg_log( LEVEL_ERR,
//                 "%s: only call close_state %d can send %x type control packet!\n",
//                 __func__,
//                 1,
//                 CDN );
//        return;
//    }

    t->call.close_state = 2;

    buf = new_buf();

    buf->current += sizeof(struct l2tp_ctl_hdr);

    avp_add_msg_type( CDN, buf );
    avp_add_result_code( t, buf );
    avp_add_ass_sid( t, buf );

    buf->end = buf->current;
    buf->current = buf->packet;

    l2tp_add_ctl_hdr( t, buf );

    buf->t = t;
    buf->ns = t->ns;
    buf->retry_times = 1;

    send_packet( buf );
}



/*
 *
 */
inline void l2tp_ntoh_hdr( struct buffer *buf )
{
    _u16 *head_node = (_u16 *)buf->current;
    register _u16 *ptr;

    *head_node = ntohs( *head_node );

    /* change a 12 octets l2tp control header to host order */
    if( IS_CTL( *head_node ) )
    {
        struct l2tp_ctl_hdr *hdr = (struct l2tp_ctl_hdr *) buf->current;

        hdr->length = ntohs( hdr->length );
        hdr->tid = ntohs( hdr->tid );
        hdr->sid = ntohs( hdr->sid );
        hdr->ns = ntohs( hdr->ns );
        hdr->nr = ntohs( hdr->nr );

        buf->ns = hdr->ns;
    }
    else
    {
        ptr = head_node + 1;

        if( HAS_LENGTH_FIELD(*head_node) )
        {
            /* length field */
            *ptr = ntohs( *ptr );
            ptr++;
        }

        /* tunnel ID field */
        *ptr = ntohs( *ptr );
        ptr++;

        /* session ID field */
        *ptr = ntohs( *ptr );
        ptr++;

        if( HAS_SQUENCE_FIELD(*head_node) )
        {
            /* Ns field */
            *ptr = ntohs( *ptr );
            ptr++;

            /* Nr field */
            *ptr = ntohs( *ptr );
            ptr++;
        }

        if( HAS_OFFSET_FIELD(*head_node) )
        {
            /* Offset field */
            *ptr = ntohs( *ptr );

            /* the Offset pad field depend on special condition */
        }
    }
}


/*
 *
 */
int save_rw_packet( struct tunnel *t, struct buffer *buf )
{
    int n;

    if( buf->ns > t->nr + t->receive_win_size )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: rws is too small to save this packet!\n",
                 __func__ );
#endif  /* DEBUG_CHECK */
        return -1;
    }

    n = buf->ns - t->nr - 1;

    if( t->rw_buf.head[n].packet[0] != 0 )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: dup of future packet\n",
                 __func__ );
#endif  /* DEBUG_CHECK */
        return -1;
    }

    if( memcpy( t->rw_buf.head + n,  buf, sizeof( struct buffer ) ) == NULL )
    {
        return -1;
    }

    t->rw_buf.count++;

#ifdef DEBUG_RWS
    msg_log ( LEVEL_INFO,
              "%s: add a packet to rw buf, current have %d\n",
              __func__,
              t->rw_buf.count);
#endif  /* DEBUG_RWS */

    return 0;
}



void clean_rw_buf( struct tunnel *t )
{
    if( t == NULL )
    {
#ifdef DEBUG_CHECK
        msg_log ( LEVEL_ERR,
                  "%s: null param!\n",
                  __func__ );
#endif  /* DEBUG_CHECK */
        return;
    }

    if( t->rw_buf.size > 0 )
    {
        if( t->rw_buf.head != NULL )
        {
            free( t->rw_buf.head );
            t->rw_buf.head = NULL;
        }
    }

    t->rw_buf.size = 0;
    t->rw_buf.count = 0;
}



void clear_rw_buf( struct tunnel *t )
{
    if( t == NULL )
    {
#ifdef DEBUG_CHECK
        msg_log ( LEVEL_ERR,
                  "%s: null param!\n",
                  __func__ );
#endif  /* DEBUG_CHECK */
        return;
    }

    if( t->rw_buf.size > 0 )
    {
        if( t->rw_buf.head != NULL )
        {
            memset ( t->rw_buf.head, 0, t->rw_buf.size * sizeof( struct buffer ) );
        }
    }

    t->rw_buf.count = 0;
}



/*
 *
 */
void handle_control_packet( struct buffer *buf )
{
    struct l2tp_ctl_hdr *hdr = (struct l2tp_ctl_hdr *) buf->current;

    /* check tunnel id */
    if( hdr->tid != globle_tunnel.ass_tid )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: recv a packet reseiver tid=%d, but self ass_tid=%d\n",
                 __func__,
                 hdr->tid,
                 globle_tunnel.ass_tid );
#endif  /* DEBUG_CHECK */
        return;
    }

    /* we will only have one session, simplify not to check sid */
//    /* check session id */
//    if( globle_tunnel.call.call_state != 0
//        && globle_tunnel.call.ass_sid != hdr->sid )
//    {
//        msg_log( LEVEL_ERR,
//                 "%s: recv a packet reseiver sid=%d, but self ass_sid=%d\n",
//                 __func__,
//                 hdr->sid,
//                 globle_tunnel.call.ass_sid );
//        return;
//    }

    buf->t = &globle_tunnel;

    /* check length */
    if( hdr->length != buf->end - buf->current )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: length is not equal to the hdr special length!\n",
                 __func__ );
#endif  /* DEBUG_CHECK */

        /* just ignore this packet other than close call or tunnel */
        //globle_tunnel.close_state = 1;
        return;
    }

    /* check ns and nr */
    if( hdr->ns != globle_tunnel.nr )
    {
        /* not expected received squence number packet  */

        if( hdr->ns < globle_tunnel.nr )
        {
            /* receive a retransmit packet, however, acknoledge it */
            globle_tunnel.need_send_ack = 1;
            return;
        }
        else
        {
            /*
             * receive a 'furture' packet
             * try to save it tempory
             */

            if( save_rw_packet( &globle_tunnel, buf ) == -1 )
            {
                /* may be the receive window buf is full now, discard */
#ifdef  DEBUG_RWS
                msg_log( LEVEL_WARN,
                         "%s: discard this packet\n",
                         __func__ );
#endif  /* DEBUG_RWS */
                return;
            }
        }
    }

    /*
     * receive a control reply packet,
     * cancle any retransmit schedule which ns is small than received reply's nr
     */
    remove_spec_schedule( send_packet, &hdr->nr );
    globle_tunnel.ns = hdr->nr;

    /* if is zlb packet */
    if( hdr->length == sizeof(struct l2tp_ctl_hdr) )
    {
        if( globle_tunnel.close_state == 2 )
        {
#ifdef  DEBUG_STATE
            msg_log( LEVEL_INFO,
                     "%s: tunnel disconnect!\n",
                     __func__ );
#endif  /* DEBUG_STATE */
            //clean_tunnel( &globle_tunnel );
            exit(0);
        }

        if( globle_tunnel.call.close_state == 2 )
        {
#ifdef  DEBUG_STATE
            msg_log( LEVEL_INFO,
                     "%s: call disconnect!\n",
                     __func__ );
#endif  /* DEBUG_STATE */

            clean_call(&globle_tunnel.call);
            tunnel_send_StopCCN( &globle_tunnel );

            //globle_tunnel.need_control = 1;

            return;
        }

        if( globle_tunnel.tunnel_state == SCCRQ /* && !globle_tunnel.call.call_state */ )
        {
#ifdef DEBUG_CONNECT_STATE
            msg_log( LEVEL_INFO,
                     "\ntunnel connected\n" );
#endif  /* DEBUG_STATE */

            globle_tunnel.connect_state = TUNNEL_CONNECTED;

            clear_schedule();
            globle_tunnel.tunnel_state = SCCCN;

            /* to start call */
            globle_tunnel.need_control = 1;
            return;
        }

        if( globle_tunnel.tunnel_state == SCCCN && globle_tunnel.call.call_state == ICRQ )
        {
#ifdef DEBUG_CONNECT_STATE
            msg_log( LEVEL_INFO,
                     "call connected\n" );
#endif  /* DEBUG_STATE */

            globle_tunnel.connect_state = CALL_CONNECTED;

            clear_schedule();
            globle_tunnel.call.call_state = ICCN;

            return;
        }

        return;
    }

    /* deal with receive window  */
    if( globle_tunnel.rw_buf.count > 0 )
    {
        int i;

        if( globle_tunnel.rw_buf.head[0].packet[0] != 0
            && globle_tunnel.rw_buf.head[0].ns == hdr->ns + 1 )
        {
            /* deal mulity packet */
            struct buffer *save_buf;

            /* deal current packet */
            buf->current += sizeof(struct l2tp_ctl_hdr);
            if( handle_avp( &globle_tunnel, buf ) != 0 )
            {
                /* avp error, clean packet left, need server retransmit */
                clear_rw_buf( &globle_tunnel );
                return;
            }

            for( i = 0, save_buf = globle_tunnel.rw_buf.head + i;
                 i < globle_tunnel.rw_buf.size && save_buf->packet[0] != 0;
                 i++, globle_tunnel.rw_buf.count-- )
            {
                save_buf->current += sizeof(struct l2tp_ctl_hdr);

                if( handle_avp( save_buf->t, buf ) != 0 )
                {
                    /* some avp error, clean packet left, need server retransmit */
                    clear_rw_buf( &globle_tunnel );
                    break;
                }

                /* empty memory */
                bzero( globle_tunnel.rw_buf.head + i, sizeof( struct buffer ) );
            }

            /* left shift un-reach packet */
            if( globle_tunnel.rw_buf.count > 0 )
            {
                int n = i;

                while( ++i < globle_tunnel.rw_buf.size )
                {
                    if( globle_tunnel.rw_buf.head[i].packet[0] != 0 )
                    {
                        bcopy( globle_tunnel.rw_buf.head + i,
                               globle_tunnel.rw_buf.head + i - n,
                               sizeof( struct buffer ) );
                        bzero( globle_tunnel.rw_buf.head + i, sizeof( struct buffer ) );
                    }
                }
            }
        }
        else
        {
            /* left shift the packets one position in rw_buf */
            for( i = 1; i < globle_tunnel.rw_buf.size; i++ )
            {
                if( globle_tunnel.rw_buf.head[i].packet[0] != 0 )
                {
                    bcopy( globle_tunnel.rw_buf.head + i,
                           globle_tunnel.rw_buf.head + i - 1,
                           sizeof( struct buffer ) );
                    bzero( globle_tunnel.rw_buf.head + i, sizeof( struct buffer ) );
                }
            }
        }
    }
    else
    {
        buf->current += sizeof(struct l2tp_ctl_hdr);
        handle_avp( &globle_tunnel, buf );
    }
}



/*
 *
 */
void handle_data_packet( struct buffer *buf )
{
    _u16 *head = ( _u16 * ) buf->current;
    register _u16 *ptr = head;

    if( HAS_LENGTH_FIELD( *head ) )
    {
        ptr++;

        if( *ptr != buf->end - buf->current )
        {
#ifdef DEBUG_CHECK
            msg_log( LEVEL_ERR,
                     "%s: length is not equal to the hdr special length!\n",
                     __func__ );
#endif  /* DEBUG_CHECK */
            return;
        }
    }

    ptr++;

    /* check tunnel id */
    if( globle_tunnel.ass_tid != *ptr )
    {
#ifdef DEBUG_CHECK
        msg_log( LEVEL_ERR,
                 "%s: recv a packet reseiver tid=%d, but self ass_tid=%d\n",
                 __func__,
                 *ptr,
                 globle_tunnel.ass_tid );
#endif  /* DEBUG_CHECK */
        return;
    }

    /* check session id */
//    if( globle_tunnel.call.ass_sid != ptr->b2 )
//    {
//        msg_log( LEVEL_ERR,
//                 "%s: recv a packet reseiver sid=%d, but self ass_sid=%d\n",
//                 __func__,
//                 ptr->b2,
//                 globle_tunnel.call.ass_sid );
//        return;
//    }

    ptr += 2;

    if( HAS_SQUENCE_FIELD( *head ) )
    {
        /* our ns is little than server nr, flush schedule */
        if( globle_tunnel.ns < *( ptr + 1 ) )
        {
            remove_spec_schedule( send_packet, ptr + 1 );
            globle_tunnel.ns = *( ptr + 1 );
        }

        /* ns not equal our expected nr */
        /* Todo, save future packet */
        if( *ptr != globle_tunnel.nr )
        {
#ifdef DEBUG_CHECK
            msg_log( LEVEL_ERR,
                     "%s: not nr required data packet, ignore!\n",
                     __func__ );
#endif  /* DEBUG_CHECK */
            return;
        }

        ptr += 2;
    }

    if( HAS_OFFSET_FIELD( *head ) )
    {
        /* get pad data if need here */
        ptr = head + *ptr;
    }

    buf->t = &globle_tunnel;

//    if( globle_tunnel.call.call_state == ICRQ && globle_tunnel.tunnel_state == SCCCN )
//    {
//        msg_log( LEVEL_INFO,
//                 "%s: call connected\n",
//                 __func__);
//        globle_tunnel.call.call_state = ICCN;
//        clear_schedule();
//    }

    if( globle_tunnel.connect_state != CONNECTED )
    {
        analyse_ppp( (_u8 *)ptr, buf->end, 0 );
    }

    /* !! */
    //msg_log ( LEVEL_ERR, "l2tp_recv_ppp:\n" );
    //print_packet ( (char *)&ptr->b3, buf->end - (_u8 *)&ptr->b3 );
    write_pppd( (_u8 *)ptr, buf->end - (_u8 *)ptr );
}



/*
 *
 */
void handle_packet( struct buffer *buf )
{
    l2tp_ntoh_hdr( buf );

    if( IS_CTL(*(_u16 *) buf->current) )
    {
        handle_control_packet( buf );

        if( globle_tunnel.need_control == 1
            || globle_tunnel.need_send_ack == 1 )
        {
            do_control();
        }
    }
    else
    {
        handle_data_packet( buf );
    }
}



void siml2tp_handler_connectted()
{
    pid_t pid;
    char exec_file[MAX_PATH_LEN];

    set_home_path( exec_file, MAX_PATH_LEN );
    strncat( exec_file, DEFAULT_CONF_PREFIX, MAX_PATH_LEN - strlen( exec_file ) );
    strncat( exec_file, CONNECTTED_EXEC, MAX_PATH_LEN - strlen( exec_file ) );

    if( access( exec_file, X_OK ) != 0 )
    {
#ifdef DEBUG_CHECK
            msg_log( LEVEL_ERR,
                     "after-connectted file \"%s\": %s\n",
                     exec_file,
                     strerror(errno) );
#endif  /* DEBUG_CHECK */
        return;
    }


    pid = fork();

    if( pid == 0 )
    {
        close( globle_tunnel.call.ppp_fd);
        close( globle_tunnel.sockfd );

        execlp( exec_file, exec_file, globle_conf.username, NULL );

#ifdef DEBUG_CHECK
            msg_log( LEVEL_ERR,
                     "exec \"%s\" fail: %s\n",
                     exec_file,
                     strerror(errno) );
#endif  /* DEBUG_CHECK */

        exit(1);
    }
    else if( pid < 0 )
    {
#ifdef DEBUG_CHECK
            msg_log( LEVEL_ERR,
                     "fork fail: %s\n",
                     strerror(errno) );
#endif  /* DEBUG_CHECK */

        return;
    }

    return;
}



void siml2tp_handler_exit()
{
    pid_t pid;
    char exec_file[MAX_PATH_LEN];

    set_home_path( exec_file, MAX_PATH_LEN );
    strncat( exec_file, DEFAULT_CONF_PREFIX, MAX_PATH_LEN - strlen( exec_file ) );
    strncat( exec_file, EXIT_EXEC, MAX_PATH_LEN - strlen( exec_file ) );

    if( access( exec_file, X_OK ) != 0 )
    {
#ifdef DEBUG_CHECK
            msg_log( LEVEL_ERR,
                     "after-connectted file \"%s\": %s\n",
                     exec_file,
                     strerror(errno) );
#endif  /* DEBUG_CHECK */
        return;
    }


    pid = fork();

    if( pid == 0 )
    {
        close( globle_tunnel.call.ppp_fd );
        close( globle_tunnel.sockfd > 0 );


        execlp( exec_file, exec_file, globle_conf.username, NULL );

#ifdef DEBUG_CHECK
            msg_log( LEVEL_ERR,
                     "exec \"%s\" fail: %s\n",
                     exec_file,
                     strerror(errno) );
#endif  /* DEBUG_CHECK */

        exit(1);
    }
    else if( pid < 0 )
    {
#ifdef DEBUG_CHECK
            msg_log( LEVEL_ERR,
                     "fork fail: %s\n",
                     strerror(errno) );
#endif  /* DEBUG_CHECK */

        return;
    }

    return;
}



void do_control()
{
    if( globle_tunnel.need_control == 0 && globle_tunnel.need_send_ack )
    {
        tunnel_send_ZLB( &globle_tunnel );

        globle_tunnel.need_control = 0;
        //globle_tunnel.need_send_ack = 0;

        /* if only send a zlb, otherwise pigback ack by below packet */
        return;
    }

    if( globle_tunnel.tunnel_state == StopCCN && !globle_tunnel.close_state )
    {
#ifdef DEBUG_CONTROL
        msg_log( LEVEL_INFO,
                 "%s: receive server close tunnel notify, send ZLB\n",
                 __func__ );
#endif  /* DEBUG_CONTROL */

        tunnel_send_ZLB( &globle_tunnel );
        /* exit handler clean the resources */
        exit(1);
    }
    else if( globle_tunnel.close_state == 1 )
    {
#ifdef DEBUG_CONTROL
        msg_log( LEVEL_INFO,
                 "%s: send StopCCN\n",
                 __func__);
#endif  /* DEBUG_CONTROL */

        tunnel_send_StopCCN( &globle_tunnel );
        clean_call( &globle_tunnel.call );
    }
    else if( globle_tunnel.call.call_state == CDN && !globle_tunnel.call.close_state )
    {
#ifdef DEBUG_CONTROL
        msg_log( LEVEL_INFO,
                 "%s: receive server close call notify, send reply\n",
                 __func__ );
#endif  /* DEBUG_CONTROL */


        //tunnel_send_ZLB( &globle_tunnel );
        //clean_call( &globle_tunnel.call );

        /* to re-control */
        //do_control();
        tunnel_send_StopCCN( &globle_tunnel );
        clean_call( &globle_tunnel.call );
    }
    else if( globle_tunnel.call.close_state == 1 )
    {
#ifdef DEBUG_CONTROL
        msg_log( LEVEL_INFO,
                 "%s: send CDN\n",
                 __func__);
#endif  /* DEBUG_CONTROL */

        call_send_CDN( &globle_tunnel.call );
    }
    else if( globle_tunnel.tunnel_state == SCCRQ && !globle_tunnel.call.call_state )
    {
#ifdef DEBUG_CONTROL
        msg_log( LEVEL_INFO,
                 "%s: send SCCCN\n",
                 __func__);
#endif  /* DEBUG_CONTROL */

        tunnel_send_SCCCN( &globle_tunnel );
    }
    else if( globle_tunnel.tunnel_state == SCCCN && !globle_tunnel.call.call_state )
    {
#ifdef DEBUG_CONTROL
        msg_log( LEVEL_INFO,
                 "%s: send ICRQ!\n",
                 __func__);
#endif  /* DEBUG_CONTROL */

        //if( globle_conf.is_reconnect && globle_conf.max_reconnect-- > 0 )
        //{
            //globle_tunnel.call.ass_sid = globle_conf.max_reconnect + 2;
            //globle_tunnel.call.serial_num = globle_conf.max_reconnect + 1;

        if( start_pppd(&globle_tunnel) == -1 )
        {
            msg_log( LEVEL_ERR,
                     "%s: start pppd fail\n",
                     __func__);

            //call_send_CDN( &globle_tunnel.call );
            globle_tunnel.close_state = 1;
            globle_tunnel.need_control = 1;
            clean_call( &globle_tunnel.call );

            do_control();
        }
        else
        {
#ifdef DEBUG_CONNECT_STATE
        msg_log( LEVEL_INFO,
                 "pppd started\n" );
#endif  /* DEBUG_STATE */

            globle_tunnel.connect_state = PPP_START;

            call_send_ICRQ( &globle_tunnel.call );
        }

        //}
//        else
//        {
//            tunnel_send_StopCCN( &globle_tunnel );
//            clean_call( &globle_tunnel.call );
//        }
    }
    else if( globle_tunnel.tunnel_state == SCCCN && globle_tunnel.call.call_state == ICRQ )
    {
#ifdef DEBUG_CONTROL
        msg_log( LEVEL_INFO,
                 "%s: send ICCN\n",
                 __func__);
#endif  /* DEBUG_CONTROL */

        call_send_ICCN( &globle_tunnel.call );
    }
    else
    {
#ifdef DEBUG_CONTROL
        msg_log( LEVEL_INFO,
                 "%s: unknown what to do, tunnel state %x, call state %x,"
                 "need_control=%d, need_send_ack=%d\n",
                 __func__,
                 globle_tunnel.tunnel_state,
                 globle_tunnel.call.call_state,
                 globle_tunnel.need_control,
                 globle_tunnel.need_send_ack );
#endif  /* DEBUG_CONTROL */
    }

    globle_tunnel.need_control = 0;

    /* may be already restore when sent ctl_packet */
    globle_tunnel.need_send_ack = 0;
}



/*
 * async  -->  sync
 */
int read_pppd(struct buffer *buf, int fd)
{
    /* use static to reuse next call if needed */
    static unsigned char ppp_buf[MAX_PPP_LEN];
    static int cur = 0, max = 0;
    int n, len = 0, escape = 0;
    unsigned char ch;

    for(;;)
    {
        if( cur >= max )
        {
            n = xread( fd, (char *)ppp_buf, sizeof(ppp_buf) );

            if( n == -1 )
            {
                if( errno == EINTR )
                {
                    continue;
                }

                return 0;
            }

            if( n == 0 )
            {
                /* packet not finished ? */
                return 0;
            }

            //msg_log ( LEVEL_ERR, "ppp_request:\n");
            //print_packet ( (const char *)ppp_buf, n );

            max = n;
            cur = 0;
        }

        ch = ppp_buf[cur++];

        switch( ch )
        {

        case PPP_FLAG:
        {
            if( escape == 1 )
            {
                /* escaped PPP_FLAG ? */
                max = 0;
                cur = 0;
                return -1;
            }

            /* finish  a packet */
            if( len >= 2 )
            {
                /* discard 2 bit FSC */
                buf->end = buf->current - 2;
                len -= 2;

                //msg_log ( LEVEL_ERR, "ppp_send:\n");
                //print_packet ( (const char *)(buf->end - len), len );
                return len;
            }
            else if( len == 1 )
            {
                /* only a single char ? */
                buf->end = buf->current;
                return len;
            }
            else
            {
                /* len == 0, a packet start */
            }
        }
        break;

        case PPP_ESCAPE:
        {
            escape = 1;
        }
        break;

        default:
        {
            if( escape == 1 )
            {
                ch ^= PPP_TRANS;
                escape = 0;
            }

            *buf->current++ = ch;
            len++;
        }

        }
    }

    return len;
}



_u16 get_fcs( register const _u8 *buf, int len )
{
    register int i = 0;
    register _u16 fcs = 0xffff;

    for (; i < len; i++, buf++)
    {
        fcs = PPP_FCS (fcs, *buf);
    }

    return fcs ^ 0xffff;
}



void write_pppd( _u8 *buf, int len )
{
    register int i = 0;
    register int n = 0;
    _u8 wr_buf[MAX_PPP_LEN];
    _u16 fcs = get_fcs( buf, len );

    wr_buf[n++] = PPP_FLAG;

    for( ; i < len; i++ )
    {
        if( buf[i] < PPP_TRANS || buf[i] == PPP_FLAG || buf[i] == PPP_ESCAPE )
        {
            wr_buf[n++] = PPP_ESCAPE;
            wr_buf[n++] = buf[i] ^ PPP_TRANS;
        }
        else
        {
            wr_buf[n++] = buf[i];
        }
    }

    wr_buf[n++] = fcs & 0xff;
    wr_buf[n++] = (fcs >> 8) & 0xff;

    wr_buf[n++] = PPP_FLAG;   

    //nwrite( globle_tunnel.call.ppp_fd, (char *)wr_buf, n );

    if( nwrite( globle_tunnel.call.ppp_fd, (char *)wr_buf, n ) == 0 )
    {
        //msg_log ( LEVEL_ERR, "l2tp_write_ppp success:\n" );
    }
    else
    {
        msg_log ( LEVEL_ERR, "l2tp_write_ppp error: %s\n", strerror(errno) );
        print_packet ( (char *)buf, len );
        print_packet ( (char *)wr_buf, n );
    }

    //print_packet ( (char *)buf, len );
    //print_packet ( (char *)wr_buf, n );
}



inline void analyse_ppp( const _u8 *start, const _u8 *end, int IO )
{
    _u16 *ptr = (_u16 *)(start + 2);

    /*  */
    if( end - start < 4 )
    {
        return;
    }

    //msg_log( LEVEL_ERR, "#%d:\n", IO );
    //print_packet( (char *)start, end - start );

    if( ntohs(*ptr) == PPP_CTL_PAP )
    {
        start += 4;

        /* client  -->  server */
        if( IO == 1 )
        {
            if( *start == 0x01 )
            {
                globle_tunnel.connect_state = SENT_AUTH;

#ifdef DEBUG_CONNECT_STATE
                msg_log( LEVEL_INFO,
                         "send username and password...\n" );
#endif  /* DEBUG_CONNECT_STATE */
                return;
            }

            /* should never run here as a client */
            return;
        }
        /* server  -->  client */
        else if( IO == 0 )
        {
            if( *start == 0x02 )
            {
                globle_tunnel.connect_state = AUTH_SUCCESS;

#ifdef DEBUG_CONNECT_STATE
                msg_log( LEVEL_INFO,
                         "auth success!\n" );
#endif  /* DEBUG_CONNECT_STATE */
                return;
            }
            else if( *start  == 0x03 )
            {
#ifdef DEBUG_CONNECT_STATE
                char buf[MAX_STRLEN_LEN];
                int len = *( start + 4 );

                bcopy( start + 5, buf, len );
                buf[len] = '\0';

                msg_log( LEVEL_INFO,
                         "auth fail: %s\n",
                         buf);
#endif  /* DEBUG_CONNECT_STATE */

                globle_tunnel.connect_state = AUTH_FAIL;

                return;
            }

            /* should never run here as a client */
            return;
        }
    }
    /*
     * get local and remote ppp addr
     * normally, self send a local addr request,
     * if the server ack, then it is the local ppp addr,
     * if server nak, then server will give the recommend local addr
     * Server will also send a addr request as our remote addr to us.
     * in short, each peer ack the other peer's ppp addr request
     */
    else if( ntohs(*ptr) == PPP_CTL_IPCP )
    {
        start += 4;

        /* ppp addr ack */
        if( *start == 0x02 )
        {
            start += 4;

            /* IP-Address and right length */
            if( *start == 0x03 && *++start == 0x06 )
            {
                //char addr[16];

                start++;

                /* client  -->  server */
                if( IO == 1 )
                {
                    bcopy( start, &globle_tunnel.call.ppp_remote, 4 );

//#ifdef DEBUG_CONNECT_STATE
//                    if( inet_ntop( AF_INET, &globle_tunnel.call.ppp_remote, addr, 15 ) != NULL )
//                    {
//                        addr[15] = '\0';
//                        msg_log( LEVEL_INFO,
//                                 "remote ppp address: %s\n",
//                                 addr );
//                    }
//#endif

                    /* it's too early do this step, since ppp have not get this packet */
                    static int done = 0;

                    if( done == 0 )
                    {
                        int *how = malloc( sizeof(int) );

                        *how = 0;
                        add_schedule( 1, set_defaultroute, how  );
                        done = 1;
                        //set_defaultroute( how );
#ifdef DEBUG_CONNECT_STATE
                        msg_log( LEVEL_INFO, "fix route...\n" );
#endif  /* DEBUG_CONNECT_STATE */

                        globle_tunnel.connect_state = FIX_ROUTE;
                    }
                }
                /* server -->  client */
                else if( IO == 0 )
                {
                    bcopy( start, &globle_tunnel.call.ppp_local, 4 );

//#ifdef DEBUG_CONNECT_STATE
//                    if( inet_ntop( AF_INET, &globle_tunnel.call.ppp_local, addr, 15 ) != NULL )
//                    {
//                        addr[15] = '\0';
//                        msg_log( LEVEL_INFO,
//                                 "local ppp address: %s\n",
//                                 addr );
//                    }
//#endif
                }
            }

            return;
        }

        /* should never run here as a client */
        return;
    }

}
