/***************************************************************************
 *            schedule.c
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


#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include "timer.h"
#include "schedule.h"
#include "misc.h"
#include "network.h"
#include "siml2tp.h"


extern struct schedule *globle_schedule;
extern int async_notify;
extern void force_exit( void * );



void init_schedule( struct schedule **s )
{
    async_notify = 0;
    *s = NULL;
}



void update_schedule( int signo )
{
    struct schedule *s;

    if( signo != SIGALRM )
    {
        return;
    }

    if( globle_schedule == NULL )
    {
        /* should not happen that the timer is on waiting nothing */

#ifdef DEBUG_SCHEDULE
        msg_log( LEVEL_ERR,
                 "%s: timer expire while no schedule waiting!\n",
                 __func__ );
#endif	/* DEBUG_SCHEDULE */

        stop_timer();
        return;
    }

    s = globle_schedule;

    while( s != NULL )
    {
        s->time_to_live--;

        if( s->time_to_live == 0 )
        {
            async_notify = 1;
        }
        else if( s->time_to_live < 0 )
        {
            /* schedule's time_to_live below zero ??? */

#ifdef DEBUG_SCHEDULE
            msg_log( LEVEL_ERR,
                     "%s: found schedule's time_to_live below zero\n",
                     __func__ );
#endif	/* DEBUG_SCHEDULE */

            /* should start its handler or not ? */
            async_notify = 1;
        }

        s = s->next;
    }

#ifdef DEBUG_SCHEDULE
    msg_log ( LEVEL_INFO,
              "%s: update\n",
              __func__ );
#endif  /* DEBUG_SCHEDULE */
}



void add_schedule( int delay, void (*handler)( void * ), void *data )
{
    sigset_t o_set, set;
    struct schedule *s;

    if( handler == NULL )
    {
#ifdef DEBUG_SCHEDULE
        msg_log( LEVEL_ERR,
                 "%s : schedule handler cannot be null!\n",
                 __func__ );
#endif	/* DEBUG_SCHEDULE */
        return;
    }

    if( delay < 0 )
    {
#ifdef DEBUG_SCHEDULE
        msg_log( LEVEL_ERR,
                 "%s : schedule delay \'%d\'' cannot be below zero!\n",
                 __func__,
                 delay );
#endif	/* DEBUG_SCHEDULE */
        return;
    }
    /* do it now */
    else if( delay == 0 )
    {
        handler( data );
        return;
    }

    /* block signal sigalrm tempory to stop schedule update */
    sigemptyset(&set);
    sigaddset( &set, SIGALRM );

    if( sigprocmask( SIG_BLOCK, &set, &o_set ) == -1 )
    {
#ifdef DEBUG_SCHEDULE
        msg_log( LEVEL_ERR,
                 "%s: set signal mask fail!\n",
                 __func__ );
#endif  /* DEBUG_SCHEDULE */
        return;
    }

    s = (struct schedule *) calloc( 1, sizeof(struct schedule) );

    if( s == NULL )
    {
        msg_log( LEVEL_ERR,
                 "%s : cannot alloc for new schedule!\n",
                 __func__ );
        exit(1);
    }

    s->data = data;
    s->time_to_live = delay;
    s->handler = handler;
    s->next = NULL;

    if( globle_schedule == NULL )
    {
        globle_schedule = s;
        start_timer(1);
    }
    else
    {
        struct schedule *front, *behind;

        front = NULL;
        behind = globle_schedule;

        while( behind && behind->time_to_live < s->time_to_live )
        {
            front = behind;
            behind = behind->next;
        }

        if( front )
        {
            s->next = behind;
            front->next = s;
        }
        else
        {
            s->next = globle_schedule;
            globle_schedule = s;
        }
    }

#ifdef DEBUG_SCHEDULE
    msg_log ( LEVEL_ERR,
              "%s: add a %d schedule\n",
              __func__,
              delay );
#endif  /* DEBUG_SCHEDULE */

    /* restore signal maks */
    if( sigprocmask( SIG_SETMASK, &o_set, NULL ) == -1 )
    {
        msg_log( LEVEL_ERR,
                 "%s: restore signal mask fail!\n",
                 __func__ );

        /* should exit ? */
        //return;
        exit(1);
    }
}



void remove_spec_schedule( void (*handler)( void * ), void *data )
{
    sigset_t o_set, set;
    struct schedule *temp;
    struct schedule *s;

    if( globle_schedule == NULL )
    {
#ifdef DDEBUG_SCHEDULE
        msg_log( LEVEL_ERR,
                 "%s: null schedule!\n",
                 __func__ );
#endif	/* DEBUG_SCHEDULE */
        return;
    }

    /* block signal sigalrm tempory */
    sigemptyset(&set);
    sigaddset( &set, SIGALRM );

    if( sigprocmask( SIG_BLOCK, &set, &o_set ) == -1 )
    {
#ifdef DEBUG_SCHEDULE
        msg_log( LEVEL_ERR,
                 "%s: set signal mask fail!\n",
                 __func__ );
#endif  /* DEBUG_SCHEDULE */
        return;
    }

    temp = NULL;
    s = globle_schedule;

    while( s != NULL )
    {
        if(  s->handler == handler )
        {
            if( (handler == send_packet && ((struct buffer *)s->data)->ns < *(int *)data)
                || handler == set_defaultroute )
            {
                if( s == globle_schedule )
                {
                    s = s->next;
                    free( globle_schedule->data );
                    globle_schedule->data = NULL;
                    free(globle_schedule);
                    globle_schedule = s;
                }
                else
                {
                    temp->next = s->next;
                    free( s->data );
                    s->data = NULL;
                    free(s);
                    s = temp->next;
                }

#ifdef DEBUG_SCHEDULE
                msg_log ( LEVEL_ERR,
                          "%s: remove a schedule\n",
                          __func__ );
#endif  /* DEBUG_SCHEDULE */
            }
            else if( data == s->data )
            {
                if( s == globle_schedule )
                {
                    s = s->next;
                    free(globle_schedule);
                    globle_schedule = s;
                }
                else
                {
                    temp->next = s->next;
                    free(s);
                    s = temp->next;
                }

#ifdef DEBUG_SCHEDULE
                msg_log ( LEVEL_ERR,
                          "%s: remove a schedule\n",
                          __func__ );
#endif  /* DEBUG_SCHEDULE */
            }
            else
            {
                temp = s;
                s = s->next;
            }
        }
        else
        {
            temp = s;
            s = s->next;
        }
    }

    if( globle_schedule == NULL )
    {
        stop_timer();
    }

    /* restore signal maks */
    if( sigprocmask( SIG_SETMASK, &o_set, NULL ) == -1 )
    {
        msg_log( LEVEL_ERR,
                 "%s: restore signal mask fail!\n",
                 __func__ );

        /* should exit ? */
        //return;
        exit(1);
    }
}



void do_schedule()
{
    struct schedule *s;
    struct schedule *temp;
    sigset_t o_set, set;

    if( globle_schedule == NULL )
    {
        /* should not happen that get async_notify but nothing pending */
#ifdef DEBUG_SCHEDULE
        msg_log( LEVEL_ERR,
                 "%s: timer expire while no schedule pending!\n",
                 __func__ );
#endif	/* DEBUG_SCHEDULE */
        return;
    }

    if( async_notify != 1 )
    {
        return;
    }

    /* block signal sigalrm tempory to prevent update */
    sigemptyset(&set);
    sigaddset( &set, SIGALRM );

    if( sigprocmask( SIG_BLOCK, &set, &o_set ) == -1 )
    {
#ifdef DEBUG_SCHEDULE
        msg_log( LEVEL_ERR,
                 "%s: set signal mask fail!\n",
                 __func__ );
#endif  /* DEBUG_SCHEDULE */
        return;
    }

    s = globle_schedule;

    while( s != NULL )
    {
        if( s->time_to_live <= 0 )
        {
            s->handler(s->data);
            //temp = s->next;

//            if( s->handler == send_packet )
//            {
//                free(s->data);
//                s->data = NULL;
//            }

            /* in order to deal the memory problem,
             * move this step out of this cycle 'while' block
             */
            //free(s);
            //s = temp;
        }
        else
        {
            break;
        }

        s = s->next;
    }

    /* move done schedule */
    while( globle_schedule != s )
    {
        temp = globle_schedule->next;
        free(globle_schedule);
        globle_schedule = temp;
    }

    async_notify = 0;

    /* restore signal maks */
    if( sigprocmask( SIG_SETMASK, &o_set, NULL ) == -1 )
    {
        msg_log( LEVEL_ERR,
                 "%s: restore signal mask fail!\n",
                 __func__ );

        /* should exit ? */
        //return;
        exit(1);
    }
}



void clear_schedule()
{
    struct schedule *s;

    if( globle_schedule == NULL )
    {
        return;
    }

    stop_timer();
    async_notify = 0;

    while( globle_schedule != NULL )
    {
        s = globle_schedule->next;

        if( globle_schedule->handler == send_packet
            || globle_schedule->handler == force_exit
            || globle_schedule->handler == set_defaultroute )
        {
            if( globle_schedule->data != NULL )
            {
                free(globle_schedule->data);
                globle_schedule->data = NULL;
            }
        }

        free(globle_schedule);
        globle_schedule = s;

#ifdef DEBUG_SCHEDULE
            msg_log ( LEVEL_ERR,
                      "%s: remove a schedule\n",
                      __func__ );
#endif  /* DEBUG_SCHEDULE */
    }

}
