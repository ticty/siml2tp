/***************************************************************************
 *            main.c
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <fcntl.h>
#include <syslog.h>
#include <wait.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <setjmp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "siml2tp.h"
#include "avp.h"
#include "schedule.h"
#include "network.h"


/* globle_conf siml2tp configure */
struct config globle_conf;
struct tunnel globle_tunnel;
struct schedule *globle_schedule;
int async_notify;


struct termios termconf;

sigjmp_buf jmp_env;
pid_t ppid;


static int  main_loop();
static void init( int , char ** );
static void check_env();
static void parse_cmd( int , char ** );
static void init_config();
static void init_sys();
static void daemonize();
static void check_userinfo();
static void interupt_handler( int );
static void exit_handler();
static void restore_term( int );
static void handler_child_term( int );
static void version();
static void usage();

void force_exit( void * );

static void build_fd_set( fd_set *, int * );


static void set_username( const void * );
static void set_password( const void * );
static void set_address( const void * );
static void set_daemon( const void * );
static void set_interface( const void * );
static void set_hostname( const void * );
static void set_ppp_path( const void * );
static void set_ppp_conf_path( const void * );
static void set_ppp_passwordfd( const void * );
//static void set_reconnect( const void * );
//static void set_max_reconnect( const void * );
static void set_max_resend( const void * );
static void set_rws( const void * );
static void add_route_list( const void * );
//static void set_keepalive( const void * );
//static void set_keepalive_interval( const void * );

static int get_bool_value( const void * );
static int get_num_value( const void * );



static const struct option long_options[] = {
    { "address",	1, 0, 'a' },
    { "username",	1, 0, 'u' },
    { "password",	1, 0, 'p' },
    { "config",		1, 0, 'c' },
    { "daemon",		0, 0, 'D' },
    { "interface",  1, 0, 'I' },
    { "version",    0, 0, 'v' },
    { "help",       0, 0, 'h' },
    { 0, 0, 0, 0 }
};


#define MIN_LETTER  'A'

static const char *cmd_option_desc[] = {
    ['a' - MIN_LETTER] = "Server IP assress",
    ['u' - MIN_LETTER] = "Username",
    ['p' - MIN_LETTER] = "Password",
    ['c' - MIN_LETTER] = "Configure file path",
    ['D' - MIN_LETTER] = "Run in deamon mode",
    ['I' - MIN_LETTER] = "Special the outgoing interface",
    ['v' - MIN_LETTER] = "Version infomation",
    ['h' - MIN_LETTER] = "Help infomation"
};



static const struct cmd
{
    const char *name;
    void (*handler)( const void * );

} cmds[] = {
    { "username",	&set_username },
    { "password",	&set_password },
    { "host",		&set_address },
    { "daemon",		&set_daemon },
    { "add route",  &add_route_list },
    { "interface",  &set_interface },
    { "hostname",   &set_hostname },
    { "ppp path",   &set_ppp_path },
    { "ppp config", &set_ppp_conf_path },
    { "passwordfd", &set_ppp_passwordfd },
    //{ "reconnect",  &set_reconnect },
    //{ "max_reconnect",  &set_max_reconnect },
    { "rws",            &set_rws },
    { "max_re_send",    &set_max_resend },
    { NULL, NULL }
};



int main(int argc, char *argv[])
{
    init(argc, argv);

    /* start a tunnel to server */
    tunnel_send_SCCRQ( &globle_tunnel );

#ifdef DEBUG_CONNECT_STATE
    msg_log( LEVEL_INFO, "Waitting for Server's response...\n" );
#endif  /* DEBUG_CONNECT_STATE */

    return main_loop();
}



int main_loop()
{
    int n;
    int ret;
    int maxfd;
    fd_set rfds;
    struct buffer buf;

    /* ! save the signal mask */
    if( (n = sigsetjmp( jmp_env, 1 )) != 0 )
    {
        /* abnormal back jump
         * n == 1   --  ppd unexpected terminal
         * n == 2   --  user or system sent a interupt signal
         */
    }

    for(;;)
    {
        if( async_notify == 1 )
        {
            do_schedule();
        }

        build_fd_set( &rfds, &maxfd );
        init_buf( &buf );

        /* nothing to do, exit */
        if( maxfd == 0 )
        {
//            if( globle_schedule != NULL )
//            {
//                pause();
//            }
//            else
//            {
//                break;
//            }
            exit(0);
        }

        ret = select( maxfd + 1, &rfds, NULL, NULL, NULL );

        if( ret <= 0 )
        {
            if( errno == EINTR )
            {
                /* interupt by signal, continue */
                continue;
            }
            else
            {
                /* continue ? */
                continue;
            }
        }

        if( FD_ISSET( globle_tunnel.sockfd, &rfds ) )
        {
            /*  */
            if( (n = xread( globle_tunnel.sockfd,
                            (char *)buf.packet,
                            sizeof( buf.packet ) )) >= MIN_L2TP_PACKET_SIZE )
            {
                /* handler message */
                buf.end = buf.packet + n;
                //print_packet( (const char *)buf.current, n );

                handle_packet( &buf );
            }
            else if( n > 0 )
            {
                msg_log( LEVEL_ERR,
                         "%s: receive a bad packet, its length %d is small than min_l2tp_packet_size %d\n",
                         __func__,
                         n,
                         MIN_L2TP_PACKET_SIZE );
            }
            else
            {
                msg_log( LEVEL_ERR,
                         "%s: receive error, %s\n",
                         __func__,
                         strerror(errno) );
            }

            ret--;
        }

        /* call ppp */
        if( ret > 0 && FD_ISSET( globle_tunnel.call.ppp_fd, &rfds ) )
        {
            /*  */
            buf.t = &globle_tunnel;
            buf.current += sizeof( struct l2tp_data_hdr_s );

            for(; read_pppd( &buf, globle_tunnel.call.ppp_fd) > 0 ;)
            {
                /* analyse ppp packet to get some connect info */
                if( globle_tunnel.connect_state != CONNECTED )
                {
                    analyse_ppp( buf.packet + sizeof( struct l2tp_data_hdr_s ),
                    			 buf.end, 1 );
                }

                l2tp_add_data_hdr_s( &globle_tunnel, &buf );
                send_packet( &buf );
                buf.current += sizeof( struct l2tp_data_hdr_s );
            }

            ret--;
        }

        if( ret > 0 )
        {
            /* here ret should be zero */

        }
    }

    return 0;
}



void build_fd_set( fd_set *set, int *maxfd )
{
    *maxfd = 0;
    FD_ZERO(set);

    FD_SET( globle_tunnel.sockfd, set );

    //if( *maxfd < globle_tunnel.sockfd )
    //{
        *maxfd = globle_tunnel.sockfd;
    //}

    if( ( globle_tunnel.call.call_state == ICCN
          /* || globle_tunnel.call.call_state == ICRQ */ )
        && globle_tunnel.call.ppp_fd > 0 )
    {
        FD_SET( globle_tunnel.call.ppp_fd, set );

        if( *maxfd < globle_tunnel.call.ppp_fd )
        {
            *maxfd = globle_tunnel.call.ppp_fd;
        }
    }
}



void init( int argc, char *argv[] )
{
    restore_config( &globle_conf );
    parse_cmd( argc, argv );
    check_env();
    init_config();
    check_userinfo();
    init_sys();
    init_tunnel( &globle_tunnel );
    init_schedule(&globle_schedule);
}



void check_env()
{
    uid_t euid;

    euid = geteuid();

    if( euid != 0 )
    {
        msg_log( LEVEL_WARN,
                 "please run with root privilege!\n");
        exit(1);
    }

    /*
     * still now, it is a terminal based soft
     * althrough we can run it in deamon mode.
     * but at start of run, we should have a control terminal,
     * in case that someone double click this proc and then may lose control
     */
    if( isatty( STDIN_FILENO ) != 1 )
    {
        exit(1);
    }

    ppid = getppid();
    //msg_log( LEVEL_INFO, "ppid = %d\n", getppid());
    //kill( getppid(), SIGKILL );
}



void parse_cmd( int argc, char *argv[] )
{
    int opt;

    const char short_options[] = ":a:c:Du:p:hI:v";

    for(;;)
    {
        opt = getopt_long( argc, argv, short_options, long_options, NULL );

        if( opt == -1 )
        {
            break;
        }

        switch(opt)
        {
        case 'a':
            {
                set_address( optarg );
            }
            break;

        case 'c':
            {
                /* if the path start with a '/', then just copy it */
                fix_path_prefix( optarg,
                                 globle_conf.config_path,
                                 sizeof( globle_conf.config_path ) );
            }
            break;

        case 'D':
            {
                globle_conf.deamon = 1;
            }
            break;

        case 'u':
            {
                set_username( optarg );
            }
            break;

        case 'p':
            {
                set_password( optarg );
            }
            break;

        case 'h':
            {
                if( optind == 2 )
                {
                    usage();
                    exit(0);
                }
                else
                {
                    msg_log( LEVEL_ERR,
                             "\"%s\": help request should only be the first argument!\n",
                             argv[optind-1] );
                    exit(1);
                }
            }
            break;

        case 'v':
            {
                if( optind == 2 )
                {
                    version();
                    exit(0);
                }
                else
                {
                    msg_log( LEVEL_ERR,
                             "\"%s\": help request should only be the first argument!\n",
                             argv[optind-1] );
                    exit(1);
                }
            }
            break;

        case 'I':
            {
                set_interface( optarg );
            }
            break;

        case ':':
            {
                msg_log( LEVEL_ERR,
                         "\"%s\": need a argument!\n",
                         argv[optind-1] );
                exit(1);
            }
            break;

        case '?':
            {
                msg_log( LEVEL_ERR,
                         "\"%s\": unknown argument!\n",
                         argv[optind-1] );
                exit(1);
            }
            break;

        default:
            {
                msg_log( LEVEL_ERR,
                         "\"%s\"(%s): unknown error!\n",
                         argv[optind-1],
                         __func__ );
                exit(1);
            }

        }
    }

    /*
     * here if optind little than argc,
     * than some other argument may need to consider
     */
}



/**
 *
 */
void init_config()
{
    FILE *fp;
    char *begin, *end;
    char *ptr1, *ptr2;
    char buf[MAX_STRLEN_LEN];
    int linenumber = 0;
    const struct cmd *c;

    if( globle_conf.config_path == NULL
        || globle_conf.config_path[0] == 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: error config file path!\n",
                 __func__ );
        exit(1);
    }

    fp = fopen( globle_conf.config_path, "r" );

    if( fp == NULL )
    {
        msg_log( LEVEL_ERR,
                 "%s: fail to open config file \"%s\", %s!\n",
                 __func__,
                 globle_conf.config_path,
                 strerror(errno) );
        exit(1);
    }

    /*
     * Micro COMMENT_CHAR defines comment char
     * a comment char is effective only if the char before is a blank ' ',
     * or it is the first readable char of a line
     * string after a comment char in same line is consider as comments
     * to use the char itself after a blank ' ', please use '\' before it
     */
    while( feof(fp) == 0 )
    {
        if( fgets( buf, sizeof(buf), fp ) == NULL )
        {
            break;
        }

        linenumber++;
        begin = buf;

        /*
         * char little than 32 in ASCII is non-readable
         * char 32 of ACCII is ' '
         * below is to trim begin non-readable char
         */
        while( *begin && *begin <= 32 )
        {
            begin++;
        }

        /* to find comment */
        for(end = begin;;)
        {
            end = strchr( end, COMMENT_CHAR );

            /* no comment char */
            if( end == NULL )
            {
                break;
            }
            /* first readable char is comment char, ignore this line */
            else if( end == begin )
            {
                /* to continue next line */
                *begin = '\0';
                break;
            }
            /* find a effecial comment char */
            else if( *(end - 1) == ' ' )
            {
                *--end = '\0';
                break;
            }
        }

        if( *begin == '\0' )
        {
            continue;
        }

        if( end == NULL )
        {
            end = begin + strlen(begin);
        }

        /* below is to trim end non-readable char */
        while( end > begin && *end <= 32 )
        {
            end--;
        }

        if( *end != '\0' )
        {
            *++end = '\0';
        }

        /* if exist "\COMMENT_CHAR" string, replace it with a single COMMENT_CHAR */
        /* should this step put behind ? */
        for( ptr1 = end - 1; ptr1 > begin; ptr1-- )
        {
            if( *ptr1 == COMMENT_CHAR )
            {
                if( *(ptr1 - 1) == '\\' )
                {
                    ptr2 = ptr1;

                    for( ; ptr1 <= end; ptr1++ )
                    {
                        *(ptr1 - 1) = *ptr1;
                    }

                    end--;
                    ptr1 = ptr2;
                }
            }
        }

        /* every preparation done, parse argument and value now */
        ptr1 = strchr( begin, '=' );

        /* no argument and value ! */
        if( ptr1 == NULL || ptr1 == begin )
        {
#ifdef STRICT_CHECK
            msg_log( LEVEL_ERR,
                     "%s: find unknown line %d: \"%s\"\n",
                     __func__,
                     linenumber,
                     begin );
            exit(1);
#endif  /* strict check */
            continue;
        }

        ptr2 = ptr1 + 1;
        ptr1--;

        /* trim argument end */
        while( ptr1 > begin && *ptr1 <= 32 )
        {
            ptr1--;
        }

        if( *ptr1 == '=' )
        {
            *ptr1 = '\0';
        }
        else
        {
            *++ptr1 = '\0';
        }

        /* trim value begin */
        while( ptr2 < end && *ptr2 <= 32 )
        {
            ptr2++;
        }

        if( ptr2 == end )
        {
            /*
            msg_log( LEVEL_ERR,
                     "%s: no value found in line %d: \"%s\"\n",
                     __func__,
                     linenumber,
                     begin );
            exit(1);
            */

            /* just no value, continue */
            continue;
        }

        /* trim mulity blanks to one between words of argument */
        while( --ptr1 > begin )
        {
            if( *ptr1 <= 32 )
            {
                char *temp = ptr1;

                while( *--temp <= 32 )
                {
                    ;
                }

                /* rewrite some non-readable to blank */
                *++temp = ' ';

                if( ptr1 > temp )
                {
                    int n = ptr1 - temp;
                    temp  = temp + 1;

                    while( *temp != '\0' )
                    {
                        *(temp - n) = *temp;
                        temp++;
                    }
                    *(temp - n) = *temp;

                    ptr1 = ptr1 - n - 1;
                }
            }
        }

        /* deal value is in quota */
        if( (*ptr2 == '\"' && *(end-1) == '\"')
            || (*ptr2 == '\'' && *(end-1) == '\'') )
        {
            ptr2++;
            *--end = '\0';
        }

        if( ptr2 >= end )
        {
            /*
            msg_log( LEVEL_ERR,
                     "%s: no value found in line %d: \"%s\"\n",
                     __func__,
                     linenumber,
                     begin );
            exit(1);
            */

            /* just no value, continue */
            continue;
        }

        /*
         * argument string's ptr is begin
         * value string's ptr is ptr2
         */
        for( c = cmds; c->name && strncmp(c->name, begin, MAX_STRLEN_LEN); c++ )
        {
            ;
        }

        if( c->name == NULL )
        {
            msg_log( LEVEL_ERR, 
            	     "unknown arg %s line %d: \"%s\"\n", begin, linenumber, begin );
            exit(1);
        }
        else
        {
            c->handler(ptr2);
        }
    }

    fclose(fp);
}



void set_username( const void *ptr )
{
    char *value = (char *) ptr;

    if( value == NULL )
    {
        msg_log( LEVEL_WARN,
                 "%s: value is null\n",
                 __func__);
        return;
    }

    /* only accept once */
    if( globle_conf.username[0] != '\0' )
    {
        return;
    }

    strncpy( globle_conf.username, value, sizeof(globle_conf.username) );
}



void set_password( const void *ptr )
{
    char *value = (char *) ptr;

    if( value == NULL )
    {
        msg_log( LEVEL_WARN,
                 "%s: value is null\n",
                 __func__);
        return;
    }

    /* only accept once */
    if( globle_conf.password[0] != '\0' )
    {
        return;
    }

    strncpy( globle_conf.password, value, sizeof(globle_conf.password) );
}



void set_address( const void *ptr )
{
    char *value = (char *) ptr;
    char *temp = NULL;
    char *port = NULL;

    int n;

    if( value == NULL )
    {
        msg_log( LEVEL_WARN,
                 "%s: value is null\n",
                 __func__);
        return;
    }

    /* only accept once */
    if( globle_conf.host[0] != '\0' )
    {
        return;
    }

    temp = strchr( value, ':');

    if( temp != NULL )
    {
        *temp = '\0';
        port = ++temp;

        n = atoi( port );

        if( n <= 0 )
        {
            msg_log( LEVEL_ERR,
                     "%s: error port number, ignore host string \"%s\"\n",
                     __func__,
                     value );
            temp = NULL;
        }
    }

    strncpy( globle_conf.host, value, sizeof(globle_conf.host) );

    if( temp != NULL )
    {
        globle_conf.port = n;
    }
}



void set_daemon( const void *ptr )
{
    /* user had special this value in command line */
    if( globle_conf.deamon != DFL_IS_DEAMON )
    {
        return;
    }

    globle_conf.deamon = get_bool_value(ptr);

    if( globle_conf.deamon == -1 )
    {
        exit(1);
    }
}



void set_interface( const void *str )
{
    int sockfd;
    //char gateway[16];
    struct sockaddr_in addr;

    /* only accept once */
    if( globle_conf.interface[0] != '\0' )
    {
        return;
    }

    sockfd = socket( AF_INET, SOCK_DGRAM, 0 );

    if( sockfd < 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: socket error, %s\n",
                 __func__,
                 strerror(errno) );
        exit(1);
    }

    if( inet_pton( AF_INET, (char *)str, &addr.sin_addr ) != 1 )
    {
        /* interface is a device name */
        struct ifreq ifr;

        bzero( &ifr, sizeof(struct ifreq) );

        strncpy( ifr.ifr_name, (char *)str, IFNAMSIZ );

        /* fetch the interface info, no this interface if faild */
        if( ioctl( sockfd, SIOCGIFADDR, &ifr ) == -1 )
        {
            msg_log( LEVEL_ERR,
                     "%s (%s): ioctl fail, %s\n",
                     __func__,
                     (char *)str,
                     strerror(errno) );
                     close(sockfd);
                     exit(1);
        }

        strncpy( globle_conf.interface, ifr.ifr_name, sizeof( globle_conf.interface ) );

        /* gateway */
//        if( inet_ntop( AF_INET,
//                       &((struct sockaddr_in *)&(ifr.ifr_dstaddr))->sin_addr,
//                       gateway,
//                       16 ) != NULL )
//        {
//            gateway[15] = '\0';
//            strncpy( globle_conf.gateway, gateway, 16 );
//        }
    }
    else
    {
        /* user special a outgoing address, now fetch the interface info */
        int i;
        char *buf;
        int size;
        int count = 10;
        struct ifconf ifc;
        struct ifreq *ifr;
        struct sockaddr_in *sin;

        for(;;)
        {
            if( (buf = (char *)calloc( count, sizeof( struct ifreq ) )) == NULL )
            {
                msg_log( LEVEL_ERR,
                         "%s: out of memory\n",
                         __func__ );

                close(sockfd);
                exit(1);
            }

            size = count * sizeof( struct ifreq );
            ifc.ifc_len = size;
            ifc.ifc_buf = buf;

            /* get interface list */
            if( ioctl( sockfd, SIOCGIFCONF, &ifc ) != 0 )
            {
                if( errno != EINVAL )
                {
                    msg_log( LEVEL_ERR,
                             "%s (%s): ioctl fail, %s\n",
                             __func__,
                             (char *)str,
                             strerror(errno) );

                    free(buf);
                    buf = NULL;
                    close(sockfd);
                    exit(1);
                }
                else
                {
                    free(buf);
                    buf = NULL;
                    count += 10;
                    continue;
                }
            }

            /*
            * if giving memory is enough, then ifc.ifc_len should <= giving size.
            * but in order to ensure all interfaces fetched, if ifc.ifc_len should == giving size,
            * try again with a larger memory
            */
            if( ifc.ifc_len < size )
            {
                break;
            }

            free(buf);
            buf = NULL;
            count += 10;
        }

        for( i = 0, ifr = ifc.ifc_req;
             i < ifc.ifc_len;
             i += sizeof( struct ifreq ), ifr++ )
        {
            sin = (struct sockaddr_in *) &ifr->ifr_addr;

            if( sin->sin_family == AF_INET )
            {
                /* compare the interface's addr to user specialled addr */
                if( bcmp( &sin->sin_addr,
                          &addr.sin_addr,
                          sizeof( struct in_addr ) ) == 0 )
                {
                    break;
                }
            }
        }

        /* no interface whose address is user specialled addr  */
        if( i >= ifc.ifc_len )
        {
            msg_log( LEVEL_ERR,
                     "%s: no interface whose address is %s\n",
                     __func__,
                     (char *)str );

            free(buf);
            buf = NULL;
            close(sockfd);
            exit(1);
        }

        strncpy( globle_conf.interface, ifr->ifr_name, sizeof( globle_conf.interface ) );
        free(buf);
        buf = NULL;

        /* gateway */
//        if( inet_ntop( AF_INET,
//                       &((struct sockaddr_in *)&(ifr->ifr_dstaddr))->sin_addr,
//                       gateway,
//                       16 ) != NULL )
//        {
//            gateway[15] = '\0';
//            strncpy( globle_conf.gateway, gateway, 16 );
//        }
    }

    close(sockfd);
}



void set_hostname( const void *str )
{
    if(  str == NULL )
    {
        return;
    }

    if( globle_conf.hostname[0] != 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: could not special hostname twice, ignore \"%s\"\n",
                 __func__,
                 (char *)str );
    }

    strncpy( globle_conf.hostname, (char *)str, sizeof( globle_conf.hostname ) );
}



void set_ppp_path( const void *str )
{
    char path[1024];

    fix_path_prefix( str, path, 1024 );

    if( access( path, F_OK | R_OK ) != 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: wrong specialled ppp path, %s\n",
                 __func__,
                 strerror(errno) );
        exit(1);
    }

    strncpy( globle_conf.ppp_path, path, sizeof( globle_conf.ppp_path ) );
}



void set_ppp_conf_path( const void *str )
{
    char path[1024];

    fix_path_prefix( str, path, 1024 );

    if( access( str, F_OK ) != 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: wrong specialled ppp config file path, %s\n",
                 __func__,
                 strerror(errno) );
        exit(1);
    }

    strncpy( globle_conf.ppp_conf_path, path, sizeof( globle_conf.ppp_conf_path ) );
}



static void set_ppp_passwordfd( const void *str )
{
    char path[1024];

    fix_path_prefix( str, path, 1024 );

    if( access( str, F_OK ) != 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: wrong specialled ppp passwordfd plugin path, %s\n",
                 __func__,
                 strerror(errno) );
        exit(1);
    }

    strncpy( globle_conf.ppp_pwdfd_path, path, sizeof( globle_conf.ppp_pwdfd_path ) );
}



void add_route_list( const void *buf )
{
    int n;
    char *ptr;
    char net[16] = { '\0' };
    char mask[16] = { '\0' };

    if( globle_conf.gateway[0] == 0 )
    {
        if( get_dst_route( globle_conf.host ) < 0 )
        {
            /* net unreachable */
            exit(1);
        }
    }

    ptr = strchr( (char *)buf, ' ' );

    if( ptr == NULL )
    {
        ptr = strchr( (char *)buf, '\t' );

        if( ptr == NULL )
        {
            return;
        }
    }

    n = ptr - (char *)buf;

    /* 111.111.111.111  --  max len is 15 */
    if( n > 15 )
    {
        return;
    }

    strncpy( net, (char *)buf, n );
    net[n] = '\0';

    if( is_vaild_ip( net ) == 0 )
    {
        return;
    }

    while( *ptr != '\0' && *ptr <= 32  )
    {
        ptr++;
    }

    if( ptr == '\0' )
    {
        return;
    }

    strncpy( mask, ptr, 15 );
    mask[15 - 1] = '\0';

    if( is_vaild_ip( mask ) == 0 )
    {
        return;
    }

    add_rt_list( &globle_conf.rt_head, net, mask );
}



/*
void set_reconnect( const void *ptr )
{
    globle_conf.is_reconnect = get_bool_value(ptr);

    if( globle_conf.is_reconnect == -1 )
    {
        exit(1);
    }
}
*/



/*
void set_max_reconnect( const void *ptr )
{
    globle_conf.max_reconnect = get_num_value(ptr);

    if( globle_conf.max_reconnect <= 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: invaild max_reconnect value!\n",
                 __func__ );
        exit(1);
    }
}
*/



void set_max_resend( const void *ptr )
{
    globle_conf.max_resend = get_num_value(ptr);

    if( globle_conf.max_resend < 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: invaild max_re_send value!\n",
                 __func__ );
        exit(1);
    }
}



void set_rws( const void *ptr )
{
    globle_conf.rws = get_num_value(ptr);

    if( globle_conf.rws <= 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: invaild recvive window size value!\n",
                 __func__ );
        exit(1);
    }
}



//void set_keepalive( const void *ptr )
//{
//    globle_conf.is_keepalive = get_bool_value(ptr);

//    if( globle_conf.is_keepalive == -1 )
//    {
//        exit(1);
//    }
//}



//void set_keepalive_interval( const void *ptr )
//{
//    globle_conf.keepalive_interval = get_num_value(ptr);

//    if( globle_conf.keepalive_interval <= 0 )
//    {
//        msg_log( LEVEL_ERR,
//                 "%s: invaild keepalive_interval value!\n",
//                 __func__ );
//        exit(1);
//    }
//}



int get_bool_value( const void *ptr )
{
    char *value = (char *) ptr;

    if( value == NULL )
    {
        msg_log( LEVEL_WARN,
                 "%s: value is null\n",
                 __func__);
        return -1;
    }

    /* value is 0 or 1 */
    if( strlen(value) == 1 )
    {
        if( *value == '0' )
        {
            return 0;
        }
        else if( *value == '1' )
        {
            return 1;
        }
        else
        {
            msg_log( LEVEL_ERR,
                     "%s: unknown value \"%s\"\n",
                     __func__,
                     value );
            exit(1);
        }
    }
    else if( strncasecmp( value, "true", MAX_STRLEN_LEN ) == 0
             || strncasecmp( value, "yes", MAX_STRLEN_LEN ) == 0)
    {
        return 1;
    }
    else if( strncasecmp( value, "false", MAX_STRLEN_LEN ) == 0
             || strncasecmp( value, "no", MAX_STRLEN_LEN ) == 0)
    {
        return 0;
    }
    else
    {
        msg_log( LEVEL_ERR,
                 "%s: unknown value \"%s\"\n",
                 __func__,
                 value );
        exit(1);
    }
}



int get_num_value( const void *ptr )
{
    char *value = (char *) ptr;

    if( value == NULL )
    {
        msg_log( LEVEL_WARN,
                 "%s: value is null\n",
                 __func__);
        return -1;
    }

    return atoi(value);
}



void check_userinfo()
{
    int n;

    /* hostname */
    if( globle_conf.hostname[0] == 0 )
    {
        /* get hostname */
        if( gethostname( globle_conf.hostname, sizeof(globle_conf.hostname) ) == -1 )
        {
            /* does it matter if provider a wrong hostname ? */
            msg_log( LEVEL_ERR,
                     "%s: gethostname fail, %s\n",
                     __func__,
                     strerror(errno) );
            exit(1);
        }
    }

    if( globle_conf.username[0] != 0 )
    {
        if( globle_conf.password[0] != 0 )
        {
            /* all info given */
            return;
        }

        /* password not given */
        msg_log( LEVEL_INFO,
                 "\nInput password for %s: ",
                 globle_conf.username );

        signal( SIGINT, restore_term );
        signal( SIGHUP, restore_term );
        signal( SIGQUIT, restore_term );
        signal( SIGCONT, restore_term );
        //signal( SIGTSTP, restore_term );

        close_echo( &termconf );

        n = xfgets( globle_conf.password,
                    sizeof( globle_conf.password ),
                    stdin );

        restore_termconf( &termconf );
        signal( SIGINT, SIG_DFL );
        signal( SIGHUP, SIG_DFL );
        signal( SIGQUIT, SIG_DFL );
        signal( SIGCONT, SIG_DFL );
        //signal( SIGTSTP, SIG_DFL );
        msg_log( LEVEL_INFO, "\n" );

        if( n <= 0 )
        {
            /* not giving the password here, may be in pap-secret file */
            bzero( globle_conf.password, sizeof( globle_conf.password ) );
        }

        return;
    }

    /* try to get username */
    msg_log( LEVEL_INFO, "\nInput username: " );

    n = xfgets( globle_conf.username,
                sizeof( globle_conf.username ),
                stdin );

    if( n <= 0 )
    {
        bzero( globle_conf.username, sizeof( globle_conf.username ) );
        bzero( globle_conf.password, sizeof( globle_conf.password ) );
        return;
    }

    /* try to get password */
    msg_log( LEVEL_INFO,
             "Input password for %s: ",
             globle_conf.username );

    signal( SIGINT, restore_term );
    signal( SIGHUP, restore_term );
    signal( SIGQUIT, restore_term );
    signal( SIGCONT, restore_term );
    signal( SIGTSTP, restore_term );

    close_echo( &termconf );

    n = xfgets( globle_conf.password,
                sizeof( globle_conf.password ),
                stdin );

    restore_termconf( &termconf );
    signal( SIGINT, SIG_DFL );
    signal( SIGHUP, SIG_DFL );
    signal( SIGQUIT, SIG_DFL );
    signal( SIGCONT, SIG_DFL );
    signal( SIGTSTP, SIG_DFL );
    msg_log( LEVEL_INFO, "\n" );

    if( n <= 0 )
    {
        /* not giving the password here, may be in pap-secret file */
        bzero( globle_conf.password, sizeof( globle_conf.password ) );
        return;
    }
}



void daemonize()
{
    int i, n;
    pid_t pid;
    struct sigaction sig_hup, sig_chld;

    /*
     * set to ignore the sigchld signal,
     * because we do not fetch the child process's terminal state,
     * as do this makes no zombie process
     */
    sig_chld.sa_handler = SIG_IGN;
    sig_chld.sa_flags = 0;

    if( sigaction( SIGCHLD, &sig_chld, NULL ) == -1 )
    {
        msg_log( LEVEL_ERR,
                 "%s--sigaction()--chld: %s\n",
                 __func__,
                 strerror(errno) );
        exit(1);
    }


    /*
     * fork one child,
     * so the child process is not a processes group leader
     */
    pid = fork();

    if( pid < 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s--fork(): %s\n",
                 __func__,
                 strerror(errno) );
        exit(1);
    }
    else if( pid > 0 )
    {
        _exit(0);
    }

    /*
     * become a session leader to disconnect from the control terminal
     */
    if( setsid() < 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s--setsid(): %s\n",
                 __func__,
                 strerror(errno) );
        exit(1);
    }

    /*
     * to ignore sighup signal,
     * bcause next step will terminal session leader,
     * it may make every member in session receive a sighup,
     * and the default action of sighup is terminal,
     * so, here I ignore it
     */
    sig_hup.sa_handler = SIG_IGN;
    sig_hup.sa_flags = 0;

    if( sigaction( SIGHUP, &sig_hup, NULL ) == -1 )
    {
        msg_log( LEVEL_ERR,
                 "%s--sigaction()--hup: %s\n",
                 __func__,
                 strerror(errno) );
        exit(1);
    }

    /*
     * fork a child again,
     * so the child process is not a session leader
     * and it could not own a control terminal by openning a tty device
     */
    pid = fork();

    if( pid < 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s--fork()--2: %s\n",
                 __func__,
                 strerror(errno) );
        exit(1);
    }
    else if( pid > 0 )
    {
        _exit(0);
    }

    /* change current dir to root */
    if( chdir("/") == -1 )
    {
        msg_log( LEVEL_WARN,
                 "%s: change current dir fail, %s\n",
                 __func__,
                 strerror(errno) );
    }

    /* get maxium number that a process can open */
    n = sysconf( _SC_OPEN_MAX );

    if( n < 0 )
    {
        /* if fail, set it to user define value */
        n = MAX_FD;
    }

    /* try to close all openned file */
    for( i = 0; i < n; i++ )
    {
        if( i == 1 || i == 2 )
        {
            continue;
        }

        close(i);
    }

    /* redirect file descripetor 0 1 2 to /dev/null */
    open( "/dev/null", O_RDWR );    /* fd == 0 */
    //open( "/dev/null", O_RDWR );
    //open( "/dev/null", O_RDWR );  /*  */

    /* set syslog(...) options */
    openlog( "SimL2tp", LOG_PID, 0 );

    return;
}



void init_sys()
{
    sigset_t sigset;
    struct sigaction sig_alrm;
    struct sigaction sig_chld;
    struct sigaction sig_int, sig_quit, sig_hup, sig_term;

    time_t now;
    struct stat timestamp;


    /* get pppd path if not special */
    if( globle_conf.ppp_path[0] == 0 )
    {
        if( get_bin_path( "pppd",
                          globle_conf.ppp_path,
                          sizeof( globle_conf.ppp_path ) ) == NULL )
        {
            msg_log( LEVEL_ERR, "cannot find pppd!\n" );
            exit(1);
        }
    }

    set_route( ADD_RT );

    /* do daemonize if required */
    if( globle_conf.deamon == 1 )
    {
        daemonize();
    }

    /*
     * fix the signal mask
     */
    if( sigprocmask( 0, NULL, &sigset ) == -1 )
    {
        msg_log( LEVEL_ERR,
                 "%s: get signal mask fail\n",
                 __func__ );
        exit(1);
    }

    sigdelset( &sigset, SIGALRM );
    sigdelset( &sigset, SIGCHLD );
    sigdelset( &sigset, SIGINT );
    sigdelset( &sigset, SIGQUIT );
    sigdelset( &sigset, SIGHUP );
    sigdelset( &sigset, SIGTERM );
    sigdelset( &sigset, SIGCONT );

    if( sigprocmask( SIG_SETMASK, &sigset, NULL ) == -1 )
    {
        msg_log( LEVEL_ERR,
                 "%s: set signal mask fail\n",
                 __func__ );
        exit(1);
    }


    /*
     * below signals are usually sent by user to terminal process
     */
    sig_int.sa_handler = interupt_handler;
    sig_quit.sa_handler = interupt_handler;
    sig_int.sa_flags = 0;
    sig_quit.sa_flags = 0;

    /*
     * below signal are usually sent by system to termianl or hung process
     * it is reasonable to terminal siml2tp other than just stop or hung it
     * so, if catch signal that may make siml2tp stop, just terminal siml2tp
     */
    sig_hup.sa_handler = interupt_handler;
    sig_hup.sa_flags = 0;
    sig_term.sa_handler = interupt_handler;
    sig_term.sa_flags = 0;

    /*
     * set update_schedule func to handler timer expire
     * try to restart the func interupted by SIGALRM
     * addition: when update_schedule called, it will auto block the SIGALRM tempory
     */
    sig_alrm.sa_handler = update_schedule;
    sig_alrm.sa_flags = SA_RESTART;

    /*
     * handler the terminal of child process self
     * mainly for pppd child process
     * set flags 'SA_RESTART' to auto-restart system-call interupted by SIGCHLD
     */
    sig_chld.sa_handler = handler_child_term;
    sig_chld.sa_flags = SA_RESTART;

    if( sigaction( SIGALRM, &sig_alrm, NULL ) == -1
        || sigaction( SIGCHLD, &sig_chld, NULL ) == -1
        || sigaction( SIGTERM, &sig_term, NULL ) == -1
        || sigaction( SIGHUP, &sig_hup, NULL ) == -1
        || sigaction( SIGINT, &sig_int, NULL ) == -1
        || sigaction( SIGQUIT, &sig_quit, NULL ) == -1 )
    {
        msg_log( LEVEL_ERR,
                 "%s--sigaction(): %s\n",
                 __func__,
                 strerror(errno) );
        exit(1);
    }


    /* regedit atexit func */
    if( atexit(exit_handler) != 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: regedit atexit func fail\n",
                 __func__ );
        exit(1);
    }

    /* clear file masks */
    umask(0);


    /* check timestamp file */
    if( stat( TIMESTAMP_FILE, &timestamp ) == 0 )
    {
        now = time(NULL);

        if( now > 0 && now < timestamp.st_mtim.tv_sec + 30 )
        {
            msg_log( LEVEL_WARN,
                     "\n\nIt's only %ld second since last disconnect, \n"
                     "if server not responses please try serveal seconds later\n",
                     now - timestamp.st_mtim.tv_sec );
        }
    }
}



/*
 *
 */
void handler_child_term( int signo )
{
    int result;
    pid_t pid;

    if( signo != SIGCHLD )
    {
        return;
    }

    pid = waitpid( -1, &result, WNOHANG );

    if( pid < 0 )
    {
        return;
    }

    if( pid == globle_tunnel.call.ppp_pid )
    {
        if( globle_tunnel.tunnel_state == StopCCN
            || globle_tunnel.close_state > 0
            || globle_tunnel.call.call_state == CDN
            || globle_tunnel.call.close_state > 0 )
        {
            msg_log( LEVEL_INFO,
                     "%s: pppd terminalled!\n",
                     __func__ );
            globle_tunnel.call.ppp_pid = -1;
            return;
        }
        else
        {
            msg_log( LEVEL_ERR,
                     "%s: pppd unexpected terminalled!\n",
                     __func__ );

            clean_call( &globle_tunnel.call );
            tunnel_send_StopCCN ( &globle_tunnel );

            /* just send CDN */
            //call_send_CDN( &globle_tunnel.call );

            /* stop whatever doing now, jump back */
            //return;
            siglongjmp( jmp_env, 1 );
        }
    }
}



/*
 * handler after exit() func called
 *		1. stop timing timer
 *		2. clean unexpired schedule
 *		3. close all open file description
 *		4. everything else need to handler
 */
void exit_handler()
{
    int fd;

    siml2tp_handler_exit();

    clear_schedule();
    clean_call( &globle_tunnel.call );
    clean_tunnel( &globle_tunnel );

    /* del what we had added in route table */
    set_route( DEL_RT );

    /* clean lan_rt struct memory */
    destroy_rt_list( &globle_conf.rt_head );

    /* restore defaultroute */
    int *how = malloc( sizeof(int) );
    *how = 1;
    set_defaultroute( how );

    /* everything else need to handler */
    if( globle_conf.deamon == 1 )
    {
        closelog();
    }


    /* create a timestamp file */
    fd = open( TIMESTAMP_FILE, O_RDONLY | O_CREAT | O_TRUNC, 0664 );
    if( fd >= 0 )
    {
        close(fd);
    }
}



void restore_term( int signo )
{
    if( signo == SIGINT
        || signo == SIGQUIT
        || signo == SIGHUP)
    {
        msg_log( LEVEL_INFO, "\n" );
        restore_termconf( &termconf );
        exit(0);
    }

//    if( signo == SIGTSTP )
//    {
//        restore_termconf( &termconf );
//    }
//
    if( signo == SIGCONT )
    {
        msg_log( LEVEL_INFO,
                 "\nInput password for %s: ",
                 globle_conf.username );
        close_echo( &termconf );
    }
}



void force_exit( void *data )
{
    int n;

    if( data == NULL )
    {
        exit(1);
    }

    n = *(int *)data;

    free(data);
    data = NULL;

    exit(n);
}



/*
 *  set flag to disconnect connectted connection
 */
void interupt_handler( int signo )
{
    if( signo != SIGTERM
        && signo != SIGHUP
        && signo != SIGINT
        && signo != SIGQUIT )
    {
        return;
    }

//    msg_log ( LEVEL_ERR,
//              "\b\breceive a interupt signal %d\n",
//              signo);

    /* new line */
    msg_log( LEVEL_INFO, "\b\b  \b\b\n" );

    if( globle_tunnel.tunnel_state != 0 )
    {
        if( globle_tunnel.close_state == 0 )
        {
            clean_call( &globle_tunnel.call );

#ifdef DEBUG_STATE
            msg_log( LEVEL_ERR,
                     "interupted, send StopCCN\n" );
#endif  /* DEBUG_STATE */

            tunnel_send_StopCCN ( &globle_tunnel );
            /* stop whatever doing now, jump back */
            siglongjmp( jmp_env, 2 );
        }
    }
    else
    {
        exit(1);
    }

}



void version()
{
    msg_log( LEVEL_INFO,
             "Version 1.1.2, Build at %s %s.\n",
             __TIME__,
             __DATE__
             );
}



void usage()
{
    int i;

    msg_log( LEVEL_INFO, "Usage:\n" );

    for( i = 0; long_options[i].name != NULL; i++ )
    {
        msg_log( LEVEL_INFO,
                 "%-15s-%c\t\t%s\n",
                 long_options[i].name,
                 long_options[i].val >= MIN_LETTER ? long_options[i].val : '\b',
                 long_options[i].val >= MIN_LETTER && \
                 cmd_option_desc[long_options[i].val - MIN_LETTER] != NULL ? \
                 cmd_option_desc[long_options[i].val - MIN_LETTER] : "" );
    }
}
