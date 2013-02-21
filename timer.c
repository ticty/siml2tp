/***************************************************************************
 *            timer.c
 *            2012-3-10
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include "misc.h"


static int active = 0;



void start_timer( int sec_interval )
{
    struct itimerval itv;

    if( active == 1 )
    {
#ifdef DEBUG_TIMER
        msg_log ( LEVEL_ERR,
                  "%s: start a already started timer, ignore!\n",
                  __func__ );
#endif  /* DEBUG_TIMER */
        return;
    }

    itv.it_interval.tv_sec = sec_interval;
    itv.it_interval.tv_usec = 0;
    itv.it_value.tv_sec = sec_interval;
    itv.it_value.tv_usec = 0;

    if( setitimer( ITIMER_REAL, &itv, NULL ) == -1 )
    {
        msg_log( LEVEL_ERR,
                 "%s: %s\n",
                 __func__,
                 strerror(errno) );
        exit(1);
    }

#ifdef DEBUG_TIMER
    msg_log ( LEVEL_INFO,
              "%s: start timer\n",
              __func__ );
#endif  /* DEBUG_TIMER */

    active = 1;
}



void stop_timer()
{
    struct itimerval itv;

    if( active == 0 )
    {
#ifdef DEBUG_TIMER
        msg_log ( LEVEL_ERR,
                  "%s: stop a already stoped timer, ignore!\n",
                  __func__ );
#endif  /* DEBUG_TIMER */
        return;
    }

    itv.it_interval.tv_sec = 0;
    itv.it_interval.tv_usec = 0;
    itv.it_value.tv_sec = 0;
    itv.it_value.tv_usec = 0;

    if( setitimer( ITIMER_REAL, &itv, NULL ) == -1 )
    {
        msg_log( LEVEL_ERR,
                 "%s: %s\n",
                 __func__,
                 strerror(errno) );
        return;
    }

#ifdef DEBUG_TIMER
    msg_log ( LEVEL_INFO,
              "%s: stop timer\n",
              __func__ );
#endif  /* DEBUG_TIMER */

    active = 0;
}
