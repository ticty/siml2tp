/***************************************************************************
 *            network.c
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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <signal.h>

#include "misc.h"
#include "schedule.h"
#include "siml2tp.h"


extern struct config globle_conf;
extern struct tunnel globle_tunnel;
extern const pid_t ppid;


void send_packet( void *data )
{
    struct buffer *buf = (struct buffer *) data;

    //print_packet( buf );

    if( buf->retry_times > 0
        && buf->retry_times > globle_conf.max_resend )
    {
        msg_log( LEVEL_ERR,
                 "\n%s: beyond max retry times!\n",
                 __func__ );

        buf->t->close_state = 1;

        //free(data);
        //data = NULL;

        //return;
        exit(1);
    }

    if( buf->retry_times > 0 )
    {
        add_schedule( 2*buf->retry_times, send_packet, data );
        buf->retry_times++;
    }

    if( nwrite( buf->t->sockfd,
                (char *)buf->current,
                buf->end - buf->packet ) == -1 )
    {
#ifdef DEBUG_IO
        msg_log( LEVEL_ERR,
                 "%s: send fail, %s\n",
                 __func__,
                 strerror(errno) );
#endif  /* DEBUG_IO */

        /* if a interface disconnect, try another one */
        if( errno == EBADF )
        {
            /* Todo */
        }
    }
}



void add_rt_list( struct lan_rt **ptr, const char *net, const char *netmask )
{
    if( net == NULL || netmask == NULL )
    {
        return;
    }

    if( *ptr == NULL )
    {
        *ptr = ( struct lan_rt * ) malloc( sizeof( struct lan_rt ) );

        if( *ptr == NULL )
        {
            return;
        }

        strncpy( (*ptr)->net, net, 16 );
        strncpy( (*ptr)->netmask, netmask, 16 );
        (*ptr)->act_state = -1;
        (*ptr)->next = NULL;
    }
    else
    {
        struct lan_rt *node = ( struct lan_rt * ) malloc( sizeof( struct lan_rt ) );

        if( node == NULL )
        {
            return;
        }

        strncpy( node->net, net, 16 );
        strncpy( node->netmask, netmask, 16 );
        node->act_state = -1;

        node->next = (*ptr)->next;
        (*ptr)->next = node;
    }
}



void destroy_rt_list( struct lan_rt **ptr )
{
    if( *ptr == NULL )
    {
        return;
    }

    destroy_rt_list( &(*ptr)->next );

    free( *ptr );
    *ptr = NULL;
}



int modify_route( const char *net, const char *netmask, const char *gw, int how )
{
    int n;
    int sockfd;
    struct rtentry rt;
    struct sockaddr_in *addr;

    if( net == NULL || netmask == NULL || gw == NULL )
    {
        return -1;
    }

    if( how != ADD_RT && how != DEL_RT )
    {
        return -1;
    }

    bzero( &rt, sizeof( rt ) );

    /* destination address */
    rt.rt_dst.sa_family = AF_INET;
    addr = (struct sockaddr_in *) &rt.rt_dst;
    //addr->sin_family = AF_INET;
    if( inet_pton( AF_INET, net, &addr->sin_addr ) != 1 )
    {
        msg_log( LEVEL_ERR,
                 "%s: inet_pton error, %s\n",
                 __func__,
                 errno == EAFNOSUPPORT ? \
                 "invalid address family" : \
                 "invalid network address");
        return -1;
    }

    /* netmask */
    rt.rt_genmask.sa_family = AF_INET;
    addr = (struct sockaddr_in *) &rt.rt_genmask;
    //addr->sin_family = AF_INET;
    if( inet_pton( AF_INET, netmask, &addr->sin_addr ) != 1 )
    {
        msg_log( LEVEL_ERR,
                 "%s: inet_pton error, %s\n",
                 __func__,
                 errno == EAFNOSUPPORT ? \
                 "invalid address family" : \
                 "invalid network address");
        return -1;
    }

    /* gateway */
    if( *gw == 0 || strncmp( gw, "0.0.0.0", 8 ) == 0 )
    {
        /* rt_dev val other than interface val of struct globle_conf */
        rt.rt_dev = globle_conf.rt_dev;
    }
    else
    {
        rt.rt_gateway.sa_family = AF_INET;
        addr = (struct sockaddr_in *) &rt.rt_gateway;
        //addr->sin_family = AF_INET;
        if( inet_pton( AF_INET, gw, &addr->sin_addr ) != 1 )
        {
            msg_log( LEVEL_ERR,
                     "%s: inet_pton error, %s\n",
                     __func__,
                     errno == EAFNOSUPPORT ? \
                     "invalid address family" : \
                     "invalid network address");
            return -1;
        }
    }

    /* flags */
    rt.rt_flags = RTF_UP | RTF_GATEWAY;

    sockfd = socket( AF_INET, SOCK_DGRAM, 0 );
    if( sockfd < 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: socket error, %s\n",
                 __func__,
                 strerror( errno ));

        return -1;
    }

    if( ioctl( sockfd,
               how == ADD_RT ? SIOCADDRT : SIOCDELRT,
               &rt ) == -1 )
    {
        n = errno;

#ifdef DEBUG_ROUTE
        msg_log( LEVEL_ERR,
                 "%s: ioctl error, %s\n",
                 __func__,
                 strerror( errno ));
#endif  /* DEBUG_ROUTE */

        close(sockfd);
        return n;
    }

    close(sockfd);
    return 0;
}


/*
 * set defalut route
 * how:
 *   0   replace default route with remote ppp address
 *   1   restore the default route which replaced by remote ppp address
 *
 * I will only save the first default route that found.
 */
void set_defaultroute( void *how )
{
    static int replaced = 0;
    char addr[16];

    if( how == NULL )
    {
        return;
    }

    /* neither 1 nor 0 */
    if( *(int *)how != 0 && *(int *)how != 1 )
    {
        free( how );
        how = NULL;
        return;
    }


    /* convert addr */
    if( inet_ntop( AF_INET, &globle_tunnel.call.ppp_remote, addr, 16 ) == NULL )
    {
        msg_log( LEVEL_INFO, "%s: inet_ntop fail\n", __func__ );
        return;
    }
    addr[15] = '\0';

    if( is_vaild_ip( addr ) == 0 )
    {
        msg_log( LEVEL_INFO, "%s: invalid ip address format\n", __func__ );
        return;
    }


    /* restore default route */
    if( *(int *)how == 1 )
    {
        modify_route( "0.0.0.0", "0.0.0.0", addr, DEL_RT );

        if( replaced == 1 )
        {
            modify_route( "0.0.0.0", "0.0.0.0", globle_conf.gateway, ADD_RT );
        }

        free(how);
        how = NULL;
        return;
    }


    if( modify_route( "0.0.0.0", "0.0.0.0", addr, ADD_RT ) != 0 )
    {
        static int max_times = 0;

        if( max_times++ > 10 )
        {
            free( how );
            how = NULL;

            msg_log( LEVEL_ERR,
                     "%s: cannot set ppp default route!\n",
                     __func__ );
            globle_tunnel.need_control = 1;
            globle_tunnel.close_state = 1;
            return;
        }

        /* this route is already exist, maybe set by ppp */
        if( errno != EEXIST )
        {
            add_schedule( 1, set_defaultroute, how );
        }
        else
        {
            free( how );
            how = NULL;
        }

        return;
    }

    if( modify_route( "0.0.0.0", "0.0.0.0", globle_conf.gateway, DEL_RT ) == 0 )
    {
        replaced = 1;
    }

    /* there will only one set_defaultroute in shedule */
    free( how );
    how = NULL;

#ifdef DEBUG_CONNECT_STATE
    msg_log( LEVEL_INFO, "all finished, net connected!\n" );
#endif  /* DEBUG_CONNECT_STATE */

    globle_tunnel.connect_state = CONNECTED;

    siml2tp_handler_connectted();

    if( globle_conf.deamon == 1 )
    {
        dup2( 0, 1 );
        dup2( 0, 2 );
        kill( ppid, SIGINT );
    }
}



/* set route entry */
void set_route( int how )
{
    struct lan_rt *ptr;

    if( globle_conf.rt_head == NULL )
    {
        return;
    }

    /* gateway and outgoing interface must at least know one */
    if( globle_conf.gateway[0] == 0 && globle_conf.interface[0] == 0 )
    {
        return;
    }

    if( how != ADD_RT && how != DEL_RT )
    {
        return;
    }

    for( ptr = globle_conf.rt_head;
         ptr != NULL;
         ptr = ptr->next )
    {
        if( how == DEL_RT )
        {
            if( ptr->act_state == 0 )
            {
                modify_route( ptr->net, ptr->netmask, globle_conf.gateway ,how );
                ptr->act_state = -1;
            }
        }
        else
        {
            ptr->act_state = modify_route( ptr->net, ptr->netmask, globle_conf.gateway ,how );
        }
    }
}




int get_dst_route( /* int family, */ const char *dst )
{
    int n;
    char buf[1024];
    char *ptr;

    int sockfd;
    struct sockaddr_in dst_addr;

    FILE *fp;

    /*
     * the default column in /proc/net/route,
     * only fetch the column we interest
     */
    int rest = 4;   /* concern only #rest below */
    int rt_interface_col = 0;
    int rt_dest_col = 1;
    int rt_gateway_col = 2;
    int rt_netmask_col = 7;


    if( dst == NULL )
    {
        return -1;
    }

    if( inet_pton( AF_INET, dst, &dst_addr.sin_addr ) != 1 )
    {
        msg_log( LEVEL_ERR,
                 "%s: inet_pton error, %s\n",
                 __func__,
                 strerror(errno) );
        return -1;
    }


    sockfd = socket( AF_INET, SOCK_DGRAM, 0 );

    if( sockfd < 0 )
    {
        msg_log( LEVEL_ERR,
                 "%s: socket error, %s\n",
                 __func__,
                 strerror(errno) );
        return -1;
    }

    dst_addr.sin_family = AF_INET;
    /* just test if net is reachable via udp connect */
    dst_addr.sin_port = htons( 23 );

    for( ;; )
    {
        n = connect( sockfd, (struct sockaddr *)&dst_addr, sizeof(dst_addr) );

        if( n == -1 )
        {
            if( errno == EINTR )
            {
                continue;
            }

            msg_log( LEVEL_ERR, "%s\n", strerror(errno) );
            return -1;
        }

        break;
    }

    /*
     * success connect to remote host,
     * thus there is a proper route entry.
     * anyway, we should not return a value below zero
     */
    close( sockfd );

    /*
     * read /proc/net/route to obtain some info
     * maybe I should consider the path, if it has a different path
     * Todo
     */
    fp = fopen( "/proc/net/route", "r" );

    if( fp == NULL )
    {
        return 0;
    }

    /*
     * parase the header line,
     * determine the column
     */
    if( xfgets( buf, 1024, fp ) <= 0 )
    {
        fclose(fp);
        return 0;
    }

    for( n = 0, ptr = buf;
         ;
         n++, ptr = NULL )
    {
        ptr = strtok( ptr, "\n\t " );

        if( ptr == NULL )
        {
            break;
        }

        if( strncasecmp( ptr, "iface", 1024 ) == 0 )
        {
            rt_interface_col = n;
            rest--;
        }
        else if( strncasecmp( ptr, "destination", 1024 ) == 0 )
        {
            rt_dest_col = n;
            rest--;
        }
        else if( strncasecmp( ptr, "gateway", 1024 ) == 0 )
        {
            rt_gateway_col = n;
            rest--;
        }
        else if( strncasecmp( ptr, "mask", 1024 ) == 0 )
        {
            rt_netmask_col = n;
            rest--;
        }
    }

    /* some column we interst not recogonise */
    if( rest != 0 )
    {
        fclose(fp);
        return 0;
    }

    int find = 0;

    /* parse route entry */
    for(;;)
    {
        if( xfgets( buf, 1204, fp ) <= 0 )
        {
            break;
        }

        const char *interface_ptr = NULL;
        const char *dest_ptr = NULL;
        const char *gateway_ptr = NULL;
        const char *netmask_ptr = NULL;

        for( n = 0, ptr = buf; ; n++, ptr = NULL )
        {
            ptr = strtok( ptr, "\n\t " );

            if( ptr == NULL )
            {
                break;
            }

            if( rt_interface_col == n )
            {
                interface_ptr = ptr;
            }
            else if( rt_dest_col == n )
            {
                dest_ptr = ptr;
            }
            else if( rt_gateway_col == n )
            {
                gateway_ptr = ptr;
            }
            else if( rt_netmask_col == n )
            {
                netmask_ptr = ptr;
            }            
        }

        if( interface_ptr == NULL
            || dest_ptr == NULL
            || gateway_ptr == NULL
            || netmask_ptr == NULL )
        {
            continue;
        }

        /*
         * here we only accept IPv4 4 byte address
         */
        if( strlen( dest_ptr ) != 8 )
        {
            continue;
        }

        /* user special outgoing interface */
        if( globle_conf.interface[0] != 0 )
        {
            if( strncasecmp( globle_conf.interface,
                             interface_ptr,
                             sizeof( globle_conf.interface ) ) != 0 )
            {
                continue;
            }
        }

        /*
         * check the route entry
         * dst_addr & rt_netmask == rt_dest
         */
        if( ( dst_addr.sin_addr.s_addr
              & strtoul( netmask_ptr, NULL, 16 )
            ) == strtoul( dest_ptr, NULL, 16 ) )
        {
            /*
             * get one
             * should I distinc it with default route ?
             * should I distinc it with a gateway 0.0.0.0
             */
            _u32 val = strtoul( gateway_ptr, NULL, 16 );

            /* will overwrite globle gateway record otherwise the default route */
            if( inet_ntop( AF_INET, &val, globle_conf.gateway, 16 ) == NULL )
            {
                globle_conf.gateway[0] = 0;
                continue;
            }

            globle_conf.gateway[15] = '\0';
            find = 1;

            /* a 0.0.0.0 gateway, in fact it special a outgoing dev */
            if( val == 0 )
            {
                strncpy( globle_conf.rt_dev, interface_ptr, sizeof( globle_conf.rt_dev ) );
            }

            /* a default route, finish */
            if( strtoul( dest_ptr, NULL, 16 ) == 0 )
            {
                break;
            }
        }
    }

    /*
     * In fact, I am very curious at this situation:
     * net is reachable but can find a route entry about this
     * how to deal with this if it happen ??
     */
    fclose(fp);
    return find;
}




//#include <arpa/inet.h>
//#include <linux/rtnetlink.h>
//#include <net/if.h>
//#include <stdlib.h>
//#include <string.h>


/*
 * it seems that my ubuntu 10.04 system do not support struct rt_msghdr in net/route.h,
 * so I try to use NETLINK_ROUTE, but also faild,
 * I will refer more books to solve it
 */
//int get_dst_route( /* int family, */ const char *dst )
//{
//    int n;
//    int len = 2048;
//    char *buf;
//    int sockfd;
//    struct in_addr dst_addr, *ptr_addr;
//
//    struct nlmsghdr *nl_msghdr;
//    struct rtmsg *rt_msg;
//    struct rtattr *rt_attr;
//
//    if( dst == NULL )
//    {
//        return -1;
//    }
//
//    if( inet_pton( AF_INET, dst, &dst_addr) != 1 )
//    {
//        msg_log( LEVEL_ERR,
//                 "%s: inet_pton fail, %s\n",
//                 __func__,
//                 strerror(errno) );
//        return -1;
//    }
//
//    sockfd = socket( AF_NETLINK, SOCK_RAW, NETLINK_ROUTE );
//
//    if( sockfd < 0 )
//    {
//        msg_log( LEVEL_ERR,
//                 "%s: sockfd fail, %s\n",
//                 __func__,
//                 strerror(errno) );
//        return -1;
//    }
//
//    buf = (char *)calloc( 1, len );
//
//    if( buf == NULL )
//    {
//        msg_log( LEVEL_ERR,
//                 "%s: calloc fail, %s\n",
//                 __func__,
//                 strerror(errno) );
//        return -1;
//    }
//
//    nl_msghdr = (struct nlmsghdr *) buf;
//    rt_msg = (struct rtmsg *) (nlMsg + 1);
//    rt_attr = ( struct rtattr * ) ( rt_msg + 1 );
//    ptr_addr = ( struct in_addr * ) ( rt_attr + 1 );
//
//    /* nl_msghdr */
//    nl_msghdr->nlmsg_type = RTM_GETROUTE;
//    nl_msghdr->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
//    nl_msghdr->nlmsg_len = NLMSG_LENGTH( sizeof( struct rtmsg )
//                                         + sizeof( struct rtattr )
//                                         + sizeof( struct in_addr ) );
//    nl_msghdr->nlmsg_pid = getpid();
//    nl_msghdr->nlmsg_seq = 0;
//
//    /* rtmsg */
//    rt_msg->rtm_family = AF_INET;
//
//    /* rt_attr */
//    rt_attr->rta_type = RTA_DST;
//    rt_attr->rta_len = sizeof( sizeof( struct rtattr ) + sizeof( struct in_addr ) );
//
//    bcopy( &dst_addr, ptr_addr, sizeof( struct in_addr ) );
//
//    if( send( sockfd, nl_msghdr, nl_msghdr->nlmsg_len, 0 ) < 0 )
//    {
//        msg_log( LEVEL_ERR,
//                 "%s: send fail, %s\n",
//                 __func__,
//                 strerror(errno) );
//
//        free(buf);
//        buf = NULL;
//        close( sockfd );
//        return -1;
//    }
//
//    int cur;
//
//    for( cur = 0; ; )
//    {
//        n = read( sockfd, buf + cur, len - cur );
//
//        if( n < 0 )
//        {
//            break;
//        }
//
//        nl_msghdr = (struct nlmsghdr *) buf + cur;
//
//        if( (NLMSG_OK(nl_msghdr, n) == 0) || nl_msghdr->nlmsg_type == NLMSG_ERROR )
//        {
//            break;
//        }
//
//        if( nl_msghdr->nlmsg_type == NLMSG_DONE )
//        {
//            break;
//        }
//
//        cur += n;
//    }
//
//    if( cur == 0 )
//    {
//        free(buf);
//        buf = NULL;
//        close( sockfd );
//        return -1;
//    }
//
//    nl_msghdr = (struct nlmsghdr *) buf;
//    rt_msg = (struct rtmsg *) NLMSG_DATA( nl_msghdr );
//
//    if( ( rt_msg->rtm_family != AF_INET )
//          || ( rt_msg->rtm_table != RT_TABLE_MAIN ) )
//    {
//        free(buf);
//        buf = NULL;
//        close( sockfd );
//        return -1;
//    }
//
//    rt_attr = ( struct rtattr * ) RTM_RTA( rt_msg );
//    n = RTM_PAYLOAD( nl_msghdr );
//
//    for( ; RTA_OK( rt_attr, n ); rt_attr = RTA_NEXT( rt_attr, n) )
//    {
//        if( rt_attr->rta_type == RTA_GATEWAY )
//        {
//            char addr_str[16];
//
//            if( inet_ntop( AF_INET, RTA_DATA( rt_attr ), addr_str, 16 ) == NULL )
//            {
//                continue;
//            }
//
//
//        }
//    }
//
//    free(buf);
//    buf = NULL;
//    close( sockfd );
//
//    return 0;
//}

