/***************************************************************************
 *            network.h
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



#ifndef NETWORK_H
#define NETWORK_H

#include "defines.h"


#define ROUTE_MAX_COLS 12

#define ADD_RT  1
#define DEL_RT  2


struct lan_rt
{
    char net[16];
    char netmask[16];

    int  act_state;

    struct lan_rt *next;
};



extern void send_packet( void * );

extern void add_rt_list( struct lan_rt **, const char *, const char * );
extern void destroy_rt_list( struct lan_rt ** );

extern int  get_dst_route( const char * );

extern void set_route( int how );
extern void set_defaultroute( void * );

extern int modify_route( const char *, const char *, const char *, int );



#endif // NETWORK_H
