/***************************************************************************
 *            asiml2tp.h
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



#ifndef SIML2TP_H
#define SIML2TP_H

#include "defines.h"

#include <netinet/in.h>
#include <termios.h>

#include "misc.h"
#include "network.h"


/* default configure file path */
#define DEFAULT_CONF_PREFIX ".siml2tp/"

#define DEFAULT_CONF    "siml2tp.conf"

#define TIMESTAMP_FILE  "/var/run/timestamp.siml2tp"

#define CONNECTTED_EXEC "after-connect"

#define EXIT_EXEC  "before-exit"

/* comment char for config file */
#define COMMENT_CHAR    '#'

/* some siml2tp default value */
#define	DFL_PORT	1701

/* default Tx connect speed */
#define DFL_TX_CONNECT_SPEED    10000000

/* default Rx connect speed */
#define DFL_RX_CONNECT_SPEED    10000000

/* default bearer type */
#define DFL_BEARER_TYPE 0x0

/* default receive window size */
#define DFL_RECV_WIN_SIZE   0x8

/* vendor name */
#define AVP_VENDOR_NAME "guofeng @ AnHui University of Technology"

/* firmware revision */
#define AVP_FIRMWARE_REVISION   0x0690

/* maxium retry dial time */
//#define MAX_RETRY_TIMES	15

/* minium size of l2tp packet, headnode + tid + sid */
#define MIN_L2TP_PACKET_SIZE    6

/* default to redial */
//#define DFL_IS_REDIAL   1

/* default max redail times */
//#define DFL_MAX_REDIALS 5

/* default if is reconnect */
//#define DFL_IS_RECONNECT    1

/* default max reconnect times */
//#define DFL_MAX_RECONNECT   3

/* default max re-send times */
#define DLF_MAX_RESEND  5

/* default not to keepalive */
//#define DFL_IS_KEEPALIVE    0

/* default keepalive interval, in second */
//#define DFL_KEEPALIVE_INTERVAL  30*60   /* 30 minutes = 1800 seconds */

/* default not start in deamon mode */
#define DFL_IS_DEAMON   0


/* PPP */
#define DEFAULT_PPP_CONF    "ppp.conf"
#define DEFAULE_PWDFD       "passwordfd.so"
#define MAX_PPP_LEN 4096

#define MAX_ERR_MSG_LEN 256

#define	PPP_FLAG	0x7e	/* Flag Sequence */
#define	PPP_ESCAPE	0x7d	/* Asynchronous Control Escape */
#define	PPP_TRANS	0x20	/* Asynchronous transparency modifier */

#define PPP_CTL_PAP     0xc023  /* ppp pap-auth ctl packet */
#define PPP_CTL_IPCP    0x8021  /* ppp ipcp packet */

#define fcstab  ppp_crc16_table
#define PPP_FCS(fcs,c) (((fcs) >> 8) ^ fcstab[((fcs) ^ (c)) & 0xff])



/* connect state */
#define DISCONNECTED        0x01
#define TUNNEL_CONNECTED    0x02
#define CALL_CONNECTED      0x03
#define PPP_START           0x04
#define SENT_AUTH           0x05
#define AUTH_FAIL           0x06
#define AUTH_SUCCESS        0x07
#define FIX_ROUTE           0x08
#define CONNECTED           0x09


/* some micros */

/*
 * is T bit set
 * if it is, then it is a control packet,
 * else it is a data packet
 */
#define IS_CTL(x)   (x & 0x8000)

/*
 * is L bit set
 * only for data packet
 * if L set 1, then length field present
 */
#define HAS_LENGTH_FIELD(x)     (x & 0x4000)

/*
 * is S bit set
 * only for data packet
 * if S set 1, then the two squence number field present
 */
#define HAS_SQUENCE_FIELD(x)    (x & 0x0800)

/*
 * is O bit set
 * only for data packet
 * if O set 1, then the Offset field present
 */
#define HAS_OFFSET_FIELD(x)     (x & 0x0200 )



/*
 * l2tp control message head
 * in head_node:
 *	T:	1
 *	L:	1	Length field present
 *	S:	1	Ns and Nr present
 *	O	0	Offset Size field absent
 *	P:	0	Normal treatment
 *	VER:	2
 */
struct l2tp_ctl_hdr
{
    _u16 head_node;	/* contain ver */
    _u16 length;
    _u16 tid;
    _u16 sid;
    _u16 ns;
    _u16 nr;

} ATTR(packed);	/*  */


/*
 * l2tp data message head full formate
 */
struct l2tp_data_hdr_f
{
    _u16 head_node;	/* contain ver */
    _u16 length;
    _u16 tid;
    _u16 sid;
    _u16 ns;
    _u16 nr;
    _u16 offset;

} ATTR(packed); /*  */



/*
 * l2tp data message head short formate
 */
struct l2tp_data_hdr_s
{
    _u16 head_node;	/* contain ver */
    _u16 tid;
    _u16 sid;

} ATTR(packed); /*  */



/* forwarding declare */
struct tunnel;
struct  config;

/* call struct */
struct call
{
    int     ppp_fd;
    pid_t   ppp_pid;

    struct in_addr ppp_local;
    struct in_addr ppp_remote;

    _u16    ass_sid;        /* our session ID */
    _u16    peer_sid;       /* peer session ID */
    _u32    serial_num;

    //_u32    cid;
    //_u32    frame_cap;
    //_u32    tx_con_speed;
    //_u32    rx_con_speed;
    //_u16    proxy_auth_type;
    struct tunnel *tunnel;

    int     close_state;                /* 0 -- do not need close
                                           1 -- need close (to force self to send CDN or StopCCN)
                                           2 -- closing ( self had send send CDN or StopCCN, wait ack )
                                         */

    _u16    call_state;     /* Call Management */

    //_u16    result_code;    /* for the CDN message */
    //_u16    error_code;
    //char    err_msg[MAX_ERR_MSG_LEN];
    //_u32    peer_frame_cap;


    struct termios *o_termconf;      /* to restore the pty attr before exit */

} ATTR(packed);


/* tunnel struct */
struct tunnel
{
    int		sockfd;
    struct	sockaddr_in server_addr;

    struct  rw_buffer  rw_buf;

    int     need_send_ack;
    int     need_control;

    _u16    tunnel_state;               /* Control Connection Management */
    _u8     connect_state;              /* include the ppp state */

    //int		retry_times;
    //int		max_retry_times;
    //int     max_resend;

    int     close_state;                /* 0 -- do not need close
                                           1 -- need close (to force self to send CDN or StopCCN)
                                           2 -- closing ( self had send send CDN or StopCCN, wait ack )
                                         */
    struct	call call;
    const struct  config *config;

    _u16	ns;                         /* Next send, sequence number for this packet */
    _u16	nr;                         /* Next receive, the sequence number expected in the next control message */

    //_u32	frame_cap;                  /* Framing Capabilities */
    //_u32    bearer_type;                /* Bearer Type */
    _u16    receive_win_size;           /* Receive Window Size */
    _u16    ass_tid;                    /* Assigned Tunnel ID */
    _u16    peer_tid;                   /* peer tunnel ID */

    //_u16    result_code;                /* for the StopCCN message */
    //_u16    error_code;                 /* error_code for both CDN and StopCCN message */
    //char    err_msg[MAX_ERR_MSG_LEN];

} ATTR(packed);



/* siml2tp configure struct */
struct config
{
    char interface[MAX_ADDRESS_LEN];

    char hostname[MAX_HOSTNAME_LEN];

    char host[MAX_ADDRESS_LEN];
    int  port;

    struct lan_rt *rt_head;
    char    gateway[16];
    char    rt_dev[32];

    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];

    char config_path[MAX_PATH_LEN];

    char ppp_path[MAX_PATH_LEN];
    char ppp_conf_path[MAX_PATH_LEN];
    char ppp_pwdfd_path[MAX_PATH_LEN];

    //int is_reconnect;
    //int max_reconnect;

    int max_resend;

    int rws;

    //int is_keepalive;
    //int keepalive_interval;

    int deamon;
};


extern void init_tunnel( struct tunnel * );
extern void restore_config( struct config * );

extern void clean_tunnel( struct tunnel * );
extern void clean_call( struct call * );
extern void clean_rw_buf( struct tunnel * );



extern void tunnel_send_SCCRQ( void * );
extern void tunnel_send_SCCCN( void * );
extern void tunnel_send_StopCCN( void * );
extern void tunnel_send_ZLB( void * );
//extern void tunnel_send_HELLO( void * );

extern void call_send_ICRQ( void * );
extern void call_send_ICCN( void * );
extern void call_send_CDN( void * );

extern void handle_packet( struct buffer * );
extern void siml2tp_handler_connectted();
extern void siml2tp_handler_exit();
extern void do_control();

extern int read_pppd(struct buffer *, int );
extern void write_pppd( _u8 *buf, int len );

extern void analyse_ppp( const _u8 *, const _u8 *, int );


extern void l2tp_add_data_hdr_s( struct tunnel *, struct buffer * );


#endif
