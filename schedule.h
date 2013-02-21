/***************************************************************************
 *            schedule.h
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



#ifndef SCHEDULE_H
#define SCHEDULE_H

#include "defines.h"


/* schedule struct */
struct schedule
{
    int time_to_live;
    void (*handler)( void * );
    void *data;

    struct schedule *next;
};


extern void init_schedule( struct schedule ** );
extern void update_schedule( int );
extern void add_schedule( int , void (*)( void * ), void * );
extern void remove_spec_schedule( void (*)( void * ), void * );
extern void do_schedule();
extern void clear_schedule();


#endif // SCHEDULE_H
