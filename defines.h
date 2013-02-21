/***************************************************************************
 *            types.h
 *            2012-3-8
 *
 *  Thu Apr 12 08:57:22 2012
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



#ifndef TYPES_H
#define TYPES_H



//#define __func__ ""


//#define DEBUG_ALL

#ifdef DEBUG_ALL
    #define DEBUG_SCHEDULE
    #define DEBUG_TIMER
    #define DEBUG_IO
    #define DEBUG_CHECK
    #define DEBUG_RWS
    #define DEBUG_STATE
    #define DEBUG_CONNECT_STATE
    #define DEBUG_CONTROL
    #define DEBUG_AVP
    #define DEBUG_ROUTE
#endif

//#define DEBUG_STATE
#define DEBUG_CONNECT_STATE


/*
 * some useful micro
 */

#define ATTR(x)	__attribute__((x))
//#define ATTR(x)

#define UNUSED_ARGUMENT(x) (void)x;


/* MAX args */
#define MAX_ARG 256



/* value types */
typedef unsigned char	_u8;
typedef unsigned short	_u16;
typedef unsigned int    _u32;


/*  */
struct bit32_ptr
{
    _u32 b0;
    _u32 b1;
    _u32 b2;
    _u32 b3;
};


/*  */
struct bit16_ptr
{
    _u16 b0;
    _u16 b1;
    _u16 b2;
    _u16 b3;
};


/*  */
struct bit8_ptr
{
    _u8 b0;
    _u8 b1;
    _u8 b2;
    _u8 b3;
};



#endif
