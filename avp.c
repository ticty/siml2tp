/***************************************************************************
 *            avp_builder.c
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
#include <string.h>

#include "avp.h"
#include "siml2tp.h"
#include "misc.h"


/*
 * Result_Code String of Result_Code type AVP for StopCCN message
 */
const char *StopCCN_Result_msg[MAX_STOPCCN_RESULT_CODE] = {
    NULL,
    "General request to clear control connection",
    "General error",
    "Control channel already exists",
    "Requester is not authorized to establish a control channel",
    "The protocol version of the requester is not supported",
    "Requester is being shut down",
    "Finite State Machine error"
};



/*
 * Result_Code String of Result_Code type AVP for CDN message
 */
const char *CDN_Result_msg[MAX_CDN_RESULT_CODE] = {
    NULL,
    "Call disconnected due to loss of carrier",
    "General error",
    "Call disconnected for administrative reasons",
    "Call failed due to lack of appropriate facilities being available(temp)",
    "Call failed due to lack of appropriate facilities being available(term)",
    "Invalid destination",
    "Call failed due to no carrier detected",
    "Call failed due to detection of a busy signal",
    "Call failed due to lack of a dial tone",
    "Call was not established within time allotted by LAC",
    "Call was connected but no appropriate framing was detected"
};



/*
 * Error_Code String of Result_Code type AVP for Result Code General Error
 */
const char *Error_msg[MAX_ERROR_CODE] = {
    "No general error",
    "No control connection exists yet for this LAC-LNS pair",
    "Length is wrong",
    "One of the field values was out of range or reserved field was non-zero",
    "Insufficient resources to handle this operation now",
    "The Session ID is invalid in this context",
    "A generic vendor-specific error occurred in the LAC",
    "Try another(see detail in RFC2661)",
    "Session or tunnel was shutdown due to receipt of an unknown AVP with the M-bit set"
};



/* avp message handler */




/*
 *
 */
inline int avp_handle_msg_type( struct tunnel *t, struct buffer *buf )
{
    struct bit16_ptr *ptr;
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    if( buf->current - buf->packet != sizeof( struct l2tp_ctl_hdr ) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: avp message type is not the first avp!\n",
                 __func__ );
#endif  /* DEBUG_AVP */
        return -1;
    }

    if( !IS_M_SET(hdr->head_node) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: M bit not set for msg-type-avp which is required!\n",
                 __func__ );
#endif  /* DEBUG_AVP */
        return -1;
    }

    if( GET_AVP_LEN(hdr->head_node) != 0x0008 )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: msg-type-avp length is %x\n",
                 __func__,
                GET_AVP_LEN(hdr->head_node));
#endif  /* DEBUG_AVP */
        return -1;
    }

    /* translate to host order */
    ptr = (struct bit16_ptr *) buf->current;
    ptr->b3 = ntohs( ptr->b3 );

    /* parase received control message type  */
    switch( ptr->b3 )
    {
    case SCCRP:
        {
            if( t->tunnel_state != 0 )
            {
#ifdef  DEBUG_STATE
                msg_log( LEVEL_ERR,
                         "%s: wrong state %x response to current %x\n",
                         __func__,
                         ptr->b3,
                         t->tunnel_state );
#endif  /* DEBUG_STATE */
                return -1;
            }

            t->tunnel_state = SCCRQ;
            t->need_control = 1;
        }
        break;

    case ICRP:
        {
            if( t->tunnel_state != SCCCN && !t->call.call_state )
            {
#ifdef  DEBUG_STATE
                msg_log( LEVEL_ERR,
                         "%s: wrong state %x response to current %x\n",
                         __func__,
                         ptr->b3,
                         t->tunnel_state );
#endif  /* DEBUG_STATE */
                return -1;
            }

            t->call.call_state = ICRQ;
            t->need_control = 1;
        }
        break;

    case HELLO:
        {
            t->need_send_ack = 1;
        }
        break;

    case StopCCN:
    {
        t->need_send_ack = 1;
        t->tunnel_state = StopCCN;
    }
    break;

    case CDN:
    {
        //t->need_send_ack = 1;
        t->need_control = 1;
        t->call.call_state = CDN;
    }
    break;

    default:
        /* to simplify test, so far just deal above state */
        break;
    }

    buf->current += 8;

    return 0;
}



/*
 *
 */
inline int avp_handle_result_code( struct tunnel *t, struct buffer *buf )
{
    //_u16 *ptr;
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    if( !IS_M_SET(hdr->head_node) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: M bit not set for msg-type-avp which is required!\n",
                 __func__ );
#endif  /* DEBUG_AVP */
        return -1;
    }

    if( IS_H_SET(hdr->head_node) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: H bit cannot be set for %x type avp!\n",
                 __func__,
                 hdr->attribute_type );
#endif  /* DEBUG_AVP */
        return -1;
    }

    if( GET_AVP_LEN(hdr->head_node) < 0x0008 )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: result_code-type-avp's length is less 8\n",
                 __func__ );
#endif  /* DEBUG_AVP */
        return -1;
    }

//    ptr = (_u16 *)&hdr->attribute_type + 1;

//    if( t->tunnel_state == StopCCN )
//    {
//        t->result_code = *ptr;

//        if( GET_AVP_LEN(hdr->head_node) >= 10
//            && (*ptr == 2 || *ptr == 5) )
//        {
//            t->error_code = *++ptr;
//        }

//        if( GET_AVP_LEN(hdr->head_node) > 10 )
//        {
    /*
            bcopy( ptr + 1,
                   t->err_msg,
                   GET_AVP_LEN(hdr->head_node) - 10 >= MAX_ERR_MSG_LEN ? \
                   MAX_ERR_MSG_LEN :
                   GET_AVP_LEN(hdr->head_node) - 10 );
                   */

//            t->err_msg[MAX_ERR_MSG_LEN - 1] = '\0';
//        }
//    }
//    else if( t->call.call_state == CDN )
//    {
//        t->call.result_code = *ptr;

//        if( GET_AVP_LEN(hdr->head_node) >= 10
//            && *ptr == 2 )
//        {
//            t->call.error_code = *++ptr;
//        }

//        if( GET_AVP_LEN(hdr->head_node) > 10 )
//        {
    /*
            bcopy( ptr + 1,
                   t->call.err_msg,
                   GET_AVP_LEN(hdr->head_node) - 10 >= MAX_ERR_MSG_LEN ? \
                   MAX_ERR_MSG_LEN :
                   GET_AVP_LEN(hdr->head_node) - 10 );
                   */

//            t->call.err_msg[MAX_ERR_MSG_LEN - 1] = '\0';
//        }
//    }

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_protocol_ver( struct tunnel *t, struct buffer *buf )
{
    //struct bit16_ptr *ptr;
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    if( !IS_M_SET(hdr->head_node) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: M bit not set for msg-type-avp which is required!\n",
                 __func__ );
#endif  /* DEBUG_AVP */
        return -1;
    }

    if( IS_H_SET(hdr->head_node) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: H bit cannot be set for %x type avp!\n",
                 __func__,
                 hdr->attribute_type );
#endif  /* DEBUG_AVP */
        return -1;
    }

    if( GET_AVP_LEN(hdr->head_node) != 0x0008 )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: msg-type-avp is not 8\n",
                 __func__ );
#endif  /* DEBUG_AVP */
        return -1;
    }

    /* simplify */
    buf->current += 8;
    return 0;
}



/*
 *
 */
inline int avp_handle_frame_caps( struct tunnel *t, struct buffer *buf )
{
    //_u32 *ptr;
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    if( !IS_M_SET(hdr->head_node) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: M bit not set for msg-type-avp which is required!\n",
                 __func__ );
#endif  /* DEBUG_AVP */
        return -1;
    }

    if( GET_AVP_LEN(hdr->head_node) != 10 )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: frame_caps-type-avp is not 10\n",
                 __func__ );
#endif  /* DEBUG_AVP */
        return -1;
    }

//    ptr = ( _u8 * )&hdr->attribute_type + 1;
//    t->call.peer_frame_cap = *ptr;

    buf->current += 10;

    return 0;
}



/*
 *
 */
inline int avp_handle_bearer_cap( struct tunnel *t, struct buffer *buf )
{
    buf->current += 10;

    UNUSED_ARGUMENT(t);

    return 0;
}



/*
 *
 */
inline int avp_handle_tie_breaker( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);
    return 0;
}



/*
 *
 */
inline int avp_handle_firmware_ver( struct tunnel *t, struct buffer *buf )
{
    //struct bit16_ptr *ptr;
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    if( IS_M_SET(hdr->head_node) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: M bit cannot set for msg-type-avp!\n",
                 __func__ );
#endif  /* DEBUG_AVP */
        return -1;
    }

    if( GET_AVP_LEN(hdr->head_node) != 8 )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: %x caps-type-avp is not 10\n",
                 __func__,
                 hdr->attribute_type);
#endif  /* DEBUG_AVP */
        return -1;
    }

    buf->current += 8;

    return 0;
}



/*
 *
 */
inline int avp_handle_hostname( struct tunnel *t, struct buffer *buf )
{
    //struct bit16_ptr *ptr;
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    if( !IS_M_SET(hdr->head_node) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: M bit not set for msg-type-avp which is required!\n",
                 __func__ );
#endif  /* DEBUG_AVP */
        return -1;
    }

    if( IS_H_SET(hdr->head_node) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: H bit cannot be set for %x type avp!\n",
                 __func__,
                 hdr->attribute_type );
#endif  /* DEBUG_AVP */
        return -1;
    }

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_vendor_name( struct tunnel *t, struct buffer *buf )
{
    //struct bit16_ptr *ptr;
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    if( IS_M_SET(hdr->head_node) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: M bit cannot set for msg-type-avp!\n",
                 __func__ );
#endif  /* DEBUG_AVP */
        return -1;
    }

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_ass_tid( struct tunnel *t, struct buffer *buf )
{
    struct bit16_ptr *ptr;
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    if( !IS_M_SET(hdr->head_node) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: M bit not set for msg-type-avp which is required!\n",
                 __func__ );
#endif  /* DEBUG_AVP */
        return -1;
    }

    if( IS_H_SET(hdr->head_node) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: H bit cannot be set for %x type avp!\n",
                 __func__,
                 hdr->attribute_type );
#endif  /* DEBUG_AVP */
        return -1;
    }

    if( GET_AVP_LEN(hdr->head_node) != 8 )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: %x caps-type-avp is not 10\n",
                 __func__,
                 hdr->attribute_type);
#endif  /* DEBUG_AVP */
        return -1;
    }

    ptr = (struct bit16_ptr *) buf->current;
    ptr->b3 = ntohs( ptr->b3 );

    t->peer_tid = ptr->b3;

    buf->current += 8;

    return 0;
}



/*
 *
 */
inline int avp_handle_recv_win_size( struct tunnel *t, struct buffer *buf )
{
    //struct bit16_ptr *ptr;
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    if( !IS_M_SET(hdr->head_node) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: M bit not set for msg-type-avp which is required!\n",
                 __func__ );
#endif  /* DEBUG_AVP */
        return -1;
    }

    if( GET_AVP_LEN(hdr->head_node) != 8 )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: %x caps-type-avp is not 10\n",
                 __func__,
                 hdr->attribute_type);
#endif  /* DEBUG_AVP */
        return -1;
    }

    buf->current += 8;

    return 0;
}



/*
 *
 */
inline int avp_handle_challenge( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_cause_code( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_challenge_rep( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_ass_sid( struct tunnel *t, struct buffer *buf )
{
    struct bit16_ptr *ptr;
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    if( !IS_M_SET(hdr->head_node) )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: M bit not set for msg-type-avp which is required!\n",
                 __func__ );
#endif  /* DEBUG_AVP */
        return -1;
    }

    if( GET_AVP_LEN(hdr->head_node) != 8 )
    {
#ifdef DEBUG_AVP
        msg_log( LEVEL_ERR,
                 "%s: %x ass_sid-type-avp is not 10\n",
                 __func__,
                 hdr->attribute_type);
#endif  /* DEBUG_AVP */
        return -1;
    }

    ptr = (struct bit16_ptr *) buf->current;
    ptr->b3 = ntohs( ptr->b3 );

    t->call.peer_sid = ptr->b3;

    buf->current += 8;

    return 0;
}



/*
 *
 */
inline int avp_handle_call_S_num( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_min_BPS( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_max_BPS( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_bearer_type( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_frame_type( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_not_define( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_called_num( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_calling_num( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_sun_address( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_Tx_con_speed( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_phy_channel_id( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_init_recvd_LCP_confq( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_last_sent_LCP_confq( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_last_recvd_LCP_confq( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_proxy_auth_type( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_proxy_auth_name( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_proxy_auth_challenge( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_proxy_auth_id( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_proxy_auth_rep( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_call_error( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_accm( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_random_vector( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_private_gid( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_Rx_con_speed( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*
 *
 */
inline int avp_handle_squencing_req( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    UNUSED_ARGUMENT(t);

    buf->current += GET_AVP_LEN(hdr->head_node);

    return 0;
}



/*  */
const struct avp_handler avp_handler[] = {
    { 0x0000, 1, 0, &avp_handle_msg_type },              /* MSG_TYPE */
    { 0x0001, 1, 0, &avp_handle_result_code },           /* RESULT_CODE */
    { 0x0002, 1, 0, &avp_handle_protocol_ver },          /* PROTOCOL_VERSION */
    { 0x0003, 1, 0, &avp_handle_frame_caps },            /* FRAMING_CAPABILITIES */
    { 0x0004, 1, 0, &avp_handle_bearer_cap },            /* BEARER_CAPABILITIES */
    { 0x0005, 1, 0, &avp_handle_tie_breaker },           /* TIE_BREAKER */
    { 0x0006, 1, 0, &avp_handle_firmware_ver },          /* FIRMWARE_REVISION */
    { 0x0007, 1, 0, &avp_handle_hostname },              /* HOST_NAME */
    { 0x0008, 1, 0, &avp_handle_vendor_name },           /* VENDOR_NAME */
    { 0x0009, 1, 0, &avp_handle_ass_tid },               /* ASSIGNED_TUNNEL_ID */
    { 0x000a, 1, 0, &avp_handle_recv_win_size },         /* RESEIVE_WINDOWS_SIZE */
    { 0x000b, 1, 0, &avp_handle_challenge },             /* CHALLENGE */
    { 0x000c, 1, 0, &avp_handle_cause_code },            /* CAUSE_CODE */
    { 0x000d, 1, 0, &avp_handle_challenge_rep },         /* CHALLENGE_RESPONSE */
    { 0x000e, 1, 0, &avp_handle_ass_sid },               /* ASSIGNED_SESSION_ID */
    { 0x000f, 1, 0, &avp_handle_call_S_num },            /* CALL_SERIAL_NUMBER */
    { 0x0010, 1, 0, &avp_handle_min_BPS },               /* MINIMUM_BPS */
    { 0x0011, 1, 0, &avp_handle_max_BPS },               /* MAXIMUM_BPS */
    { 0x0012, 1, 0, &avp_handle_bearer_type },           /* BEARER_TYPE */
    { 0x0013, 1, 0, &avp_handle_frame_type },            /* FRAMING_TYPE */
    { 0x0014, 0, 0, &avp_handle_not_define },            /* not define */
    { 0x0015, 1, 0, &avp_handle_called_num },            /* CALLED_NUMBER */
    { 0x0016, 1, 0, &avp_handle_calling_num },           /* CALLING_NUMBER */
    { 0x0017, 1, 0, &avp_handle_sun_address },           /* SUB_ADDRESS */
    { 0x0018, 1, 0, &avp_handle_Tx_con_speed },          /* TX_CONNECT_SPEED */
    { 0x0019, 1, 0, &avp_handle_phy_channel_id },        /* PHYSICAL_CHANNEL_ID */
    { 0x001a, 1, 0, &avp_handle_init_recvd_LCP_confq },  /* INIT_RECVD_LCP_CONFREQ */
    { 0x001b, 1, 0, &avp_handle_last_sent_LCP_confq },   /* LAST_SENT_LCP_CONFREQ */
    { 0x001c, 1, 0, &avp_handle_last_recvd_LCP_confq },  /* LAST_RECVD_LCP_CONFREQ */
    { 0x001d, 1, 0, &avp_handle_proxy_auth_type },       /* PROXY_AUTHEN_TYPE */
    { 0x001e, 1, 0, &avp_handle_proxy_auth_name },       /* PROXY_AUTHEN_NAME */
    { 0x001f, 1, 0, &avp_handle_proxy_auth_challenge },  /* PROXY_AUTHEN_CHALLENGE */
    { 0x0020, 1, 0, &avp_handle_proxy_auth_id },         /* PROXY_AUTHEN_ID */
    { 0x0021, 1, 0, &avp_handle_proxy_auth_rep },        /* PROXY_AUTHEN_REPONSE */
    { 0x0022, 1, 0, &avp_handle_call_error },            /* CALL_ERROR */
    { 0x0023, 1, 0, &avp_handle_accm },                  /* ACCM */
    { 0x0024, 1, 0, &avp_handle_random_vector },         /* RANDOM_VECTOR */
    { 0x0025, 1, 0, &avp_handle_private_gid },           /* PRIVATE_GROU_ID */
    { 0x0026, 1, 0, &avp_handle_Rx_con_speed },          /* RX_CONNECT_SPEED */
    { 0x0027, 1, 0, &avp_handle_squencing_req }          /* SQUENCING_REQUIRED */
};



/*
 * set the header value of the AVP
 */
inline void avp_set_hdr( struct buffer *buf, int set_M, int set_H, _u16 len, _u16 type )
{
    struct avp_hdr *avp = (struct avp_hdr *) buf->current;
    avp->head_node = htons( (set_M ? 0x8000 : 0 ) | (set_H ? 0x4000 : 0) | len );
    avp->vendor_id = htons( AVP_VENDOR_ID );
    avp->attribute_type = htons( type );

    buf->current += sizeof( struct avp_hdr );
}



inline void avp_ntoh_hdr( struct buffer *buf )
{
    struct avp_hdr *hdr = (struct avp_hdr *) buf->current;

    hdr->head_node = ntohs( hdr->head_node );
    hdr->vendor_id = ntohs( hdr->vendor_id );
    hdr->attribute_type = ntohs( hdr->attribute_type );
}




/*
 * handle avp mesage
 */
int handle_avp( struct tunnel *t, struct buffer *buf )
{
    struct avp_hdr *hdr;

    if( t->tunnel_state == StopCCN && t->close_state == 2 )
    {
        if( t->nr < buf->ns + 1 )
        {
            t->nr = buf->ns + 1;
        }

        return -1;
    }

    for(;;)
    {
        if( buf->current >= buf->end )
        {
            break;
        }

        avp_ntoh_hdr( buf );
        hdr = (struct avp_hdr *) buf->current;

        if( hdr->attribute_type > 0x0027 )
        {
#ifdef  DEBUG_AVP
            msg_log ( LEVEL_ERR,
                      "%s: unknown avp type %x\n",
                      __func__,
                      hdr->attribute_type );
#endif  /* DEBUG_AVP */
            return -1;
        }

        if( avp_handler[hdr->attribute_type].handler( t, buf ) == -1 )
        {
            t->close_state = 1;
            return -1;
        }
    }

    if( t->nr < buf->ns + 1 )
    {
        t->nr = buf->ns + 1;
    }

    return 0;
}



/*
 * MUST be the first AVP in a message
 * Attribute Type is 0
 * M-bit MUST be set to 1
 * Length of this AVP is 8
 */
inline void avp_add_msg_type( _u16 state, struct buffer *buf )
{
    struct bit16_ptr *ptr;
    //set AVP header
    avp_set_hdr( buf, 1, 0, 0x8, MSG_TYPE );

    //set AVP value
    ptr = (struct bit16_ptr *) buf->current;

    ptr->b0 = htons(state);

    buf->current += 0x2;
}



/*
 * This AVP MUST NOT be hidden (the H-bit MUST be 0).
 * The M-bit for this AVP MUST be set to 1.
 * The Length of this AVP is 8.
 */
inline void avp_add_protocol_ver( struct buffer *buf )
{
    struct bit8_ptr *ptr;
    //set AVP header
    avp_set_hdr( buf, 1, 0, 0x8, PROTOCOL_VERSION );

    //set AVP value
    ptr = (struct bit8_ptr *) buf->current;
    ptr->b0 = 0x1;
    ptr->b1 = 0;

    buf->current += 0x2;
}



/*
 * This AVP MUST NOT be hidden (the H-bit MUST be 0).
 * The M-bit for this AVP MUST be set to 1.
 * The Length of this AVP is 6 plus the length of the Host Name.
 */
inline void avp_add_hostname( const struct tunnel *t, struct buffer *buf )
{
    size_t namelen = strlen( t->config->hostname );

    /* fix: do some length check */

    /* set avp header */
    avp_set_hdr( buf, 1, 0, 0x6 + namelen , HOST_NAME );

    /* set value */
    strncpy( (char *)buf->current, t->config->hostname, namelen );

    buf->current += namelen;
}



/*
 * The M-bit for this AVP MUST be set to 1.
 * The Length (before hiding) is 10.
 */
inline void avp_add_frame_caps( const struct tunnel *t, struct buffer *buf )
{
    struct bit32_ptr *ptr;

    UNUSED_ARGUMENT(t);

    //set AVP header
    avp_set_hdr( buf, 1, 0, 0xa, FRAMING_CAPABILITIES );

    /* set value */
    ptr = (struct bit32_ptr *) buf->current;
    //ptr->b0 = htonl( t->frame_cap );
    ptr->b0 = htonl( SYNC_FRAME );
    buf->current += 4;
}



/*
 * This AVP may be hidden (the H-bit may be 0 or 1).
 * The M-bit for this AVP MUST be set to 1.
 * The Length (before hiding) of this AVP is 8.
 */
inline void avp_add_ass_tid( const struct tunnel *t, struct buffer *buf )
{
    struct bit16_ptr *ptr;
    //set AVP header
    avp_set_hdr( buf, 1, 0, 0x8, ASSIGNED_TUNNEL_ID );

    //set value
    ptr = (struct bit16_ptr *) buf->current;
    ptr->b0 = htons( t->ass_tid );
    buf->current += 2;
}


/*
 * This AVP MUST NOT be hidden (the H-bit MUST be 0).
 * The M-bit for this AVP MUST be set to 1.
 * The Length is 8 if there is no Error Code or Message
 * The Length is 10 if there is an Error Code and no Error Message
 * The Length is 10 + length of the Error Message if there is an Error Code and Message
 */
inline void avp_add_result_code( const struct tunnel *t, struct buffer *buf )
{
    //_u16 len;
    struct bit16_ptr *ptr;

    if( t->call.call_state == CDN )
    {
//        if( t->error_code == 2 )
//        {
//            len = strlen( Error_msg[t->error_code] );
//            avp_set_hdr( buf, 1, 0, 10 + len, RESULT_CODE );
//            ptr = (struct bit16_ptr *) buf->current;
//            ptr->b0 = htons( t->call.result_code );
//            ptr->b1 = htons( t->error_code );
//            strncpy( (char *)&ptr->b2, Error_msg[t->error_code], len );
//            buf->current += len;
//        }
//        else
//        {
            avp_set_hdr( buf, 1, 0, 0x8, RESULT_CODE );
            ptr = (struct bit16_ptr *) buf->current;
            //ptr->b0 = htons( t->call.result_code );
            ptr->b0 = htons( 3 );
            buf->current += 2;
        //}

        return;
    }


    if( t->tunnel_state == StopCCN )
    {
//        if( t->error_code == 2 || t->error_code == 5 )
//        {
//            len = strlen( Error_msg[t->error_code] );
//            avp_set_hdr( buf, 1, 0, 10 + len, RESULT_CODE );
//            ptr = (struct bit16_ptr *) buf->current;
//            ptr->b0 = htons( t->result_code );
//            ptr->b1 = htons( t->error_code );
//            strncpy( (char *)&ptr->b2, Error_msg[t->error_code], len );
//            buf->current += len;
//        }
//        else
//        {
            avp_set_hdr( buf, 1, 0, 0x8, RESULT_CODE );
            ptr = (struct bit16_ptr *) buf->current;
//            ptr->b0 = htons( t->result_code );
            ptr->b0 = htons( 1 );
            buf->current += 2;
        //}

        return;
    }

    /*  */

}



/*
 * This AVP may be hidden (the H-bit may be 0 or 1).
 * The M-bit for this AVP MUST be set to 1.
 * The Length (before hiding) of this AVP is 8.
 */
inline void avp_add_ass_sid( const struct tunnel *t, struct buffer *buf )
{
    struct bit16_ptr *ptr;
    //set AVP header
    avp_set_hdr( buf, 1, 0, 0x8, ASSIGNED_SESSION_ID );

    //set value
    ptr = (struct bit16_ptr *) buf->current;
    ptr->b0 = htons( t->call.ass_sid );
    buf->current += 2;
}



/*
 * This AVP may be hidden (the H-bit may be 0 or 1).
 * The M-bit for this AVP MUST be set to 1.
 * The Length (before hiding) of this AVP is 10
 */
inline void avp_add_call_S_num( const struct tunnel *t, struct buffer *buf )
{
    struct bit32_ptr *ptr;
    //set AVP header
    avp_set_hdr( buf, 1, 0, 0xa, CALL_SERIAL_NUMBER );

    //set value
    ptr = (struct bit32_ptr *) buf->current;
    //ptr->b0 = htonl( t->call.cid );
    ptr->b0 = htonl( t->call.serial_num );
    buf->current += 4;
}



/*
 * This AVP may be hidden (the H-bit may be 0 or 1).
 * The M-bit for this AVP MUST be set to 1.
 * The Length (before hiding) of this AVP is 10.
 */
inline void avp_add_frame_type( const struct tunnel *t, struct buffer *buf )
{
    struct bit32_ptr *ptr;

    UNUSED_ARGUMENT(t);

    //set AVP header
    avp_set_hdr( buf, 1, 0, 0xa, FRAMING_TYPE );

    /* set value */
    ptr = (struct bit32_ptr *) buf->current;
    //ptr->b0 = htonl( t->call.frame_cap );SYNC_FRAME
    ptr->b0 = htonl( SYNC_FRAME );
    buf->current += 0x4;
}



/*
 * This AVP may be hidden (the H-bit may be 0 or 1).
 * The M-bit for this AVP MUST be set to 1.
 * The Length (before hiding) of this AVP is 10.
 */
inline void avp_add_Tx_con_speed( const struct tunnel *t, struct buffer *buf )
{
    struct bit32_ptr *ptr;

    UNUSED_ARGUMENT(t);

    //set AVP header
    avp_set_hdr( buf, 1, 0, 0xa, TX_CONNECT_SPEED );

    /* set value */
    ptr = (struct bit32_ptr *) buf->current;
    //ptr->b0 = htonl( t->call.tx_con_speed );
    ptr->b0 = htonl( DFL_TX_CONNECT_SPEED );
    buf->current += 0x4;
}



/*
 * This AVP may be hidden (the H-bit may be 0 or 1).
 * The M-bit for this AVP MUST be set to 1.
 * The Length (before hiding) of this AVP is 10.
 */
inline void avp_add_Rx_con_speed( const struct tunnel *t, struct buffer *buf )
{
    struct bit32_ptr *ptr;

    UNUSED_ARGUMENT(t);

    //set AVP header
    avp_set_hdr( buf, 1, 0, 0xa, RX_CONNECT_SPEED );

    /* set value */
    ptr = (struct bit32_ptr *) buf->current;
    //ptr->b0 = htonl( t->call.rx_con_speed );
    ptr->b0 = htonl( DFL_RX_CONNECT_SPEED );
    buf->current += 0x4;
}



/*
 * This AVP may be hidden (the H-bit may be 0 or 1).
 * The M-bit for this AVP MUST be set to 1.
 * The Length (before hiding) is 10.
 */
inline void avp_add_bearer_caps( const struct tunnel *t, struct buffer *buf )
{
    struct bit32_ptr *ptr;

    UNUSED_ARGUMENT(t);

    //set AVP header
    avp_set_hdr( buf, 1, 0, 0xa, BEARER_CAPABILITIES );

    /* set value */
    ptr = (struct bit32_ptr *) buf->current;
    //ptr->b0 = htonl( t->bearer_type );
    ptr->b0 = htonl( DFL_BEARER_TYPE );
    buf->current += 0x4;
}



/*
 * This AVP MUST NOT be hidden (the H-bit MUST be 0).
 * The M-bit for this AVP MUST be set to 1.
 * The Length of this AVP is 8.
 */
inline void avp_add_recv_win_size( const struct tunnel *t, struct buffer *buf )
{
    struct bit16_ptr *ptr;
    //set AVP header
    avp_set_hdr( buf, 1, 0, 0x8, RESEIVE_WINDOWS_SIZE );

    /* set value */
    ptr = (struct bit16_ptr *) buf->current;
    ptr->b0 = htons( t->receive_win_size );
    buf->current += 0x2;
}



/*
 * This AVP may be hidden (the H-bit may be 0 or 1).
 * The M-bit for this AVP MUST be set to 0.
 * The Length (before hiding) of this AVP is 6 plus the length of the Vendor Name.
 */
inline void avp_add_vendor_name( struct buffer *buf )
{
    _u16 len;

    len = strlen( AVP_VENDOR_NAME );
    avp_set_hdr( buf, 0, 0, 6 + len, VENDOR_NAME );

    strncpy( (char *)buf->current, AVP_VENDOR_NAME, len );
    buf->current += len;
}



/*
 * This AVP may be hidden (the H-bit may be 0 or 1).
 * The M-bit for this AVP MUST be set to 0.
 * The Length (before hiding) is 8.
 */
inline void avp_add_firmware_rev( struct buffer *buf )
{
    struct bit16_ptr *ptr;
    //set AVP header
    avp_set_hdr( buf, 0, 0, 0x8, FIRMWARE_REVISION );

    /* set value */
    ptr = (struct bit16_ptr *) buf->current;
    ptr->b0 = htons( AVP_FIRMWARE_REVISION );
    buf->current += 0x2;
}



/*
 * This AVP may be hidden (the H-bit may be 0 or 1).
 * The M-bit for this AVP MUST be set to 0.
 * The Length (before hiding) of this AVP is 8.
 */
inline void avp_add_proxy_auth_type( const struct tunnel *t, struct buffer *buf )
{
    struct bit16_ptr *ptr;

    UNUSED_ARGUMENT(t);

    //set AVP header
    avp_set_hdr( buf, 0, 0, 0x8, PROXY_AUTHEN_TYPE );

    /* set value */
    ptr = (struct bit16_ptr *) buf->current;
    //ptr->b0 = htons( t->call.proxy_auth_type );
    ptr->b0 = htons( NO_AUTHEN );
    buf->current += 0x2;
}

