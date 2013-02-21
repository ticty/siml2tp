/***************************************************************************
 *            avp_builder.h
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



#ifndef AVP_BUILDER_H
#define AVP_BUILDER_H


#include "defines.h"
#include "misc.h"
#include "siml2tp.h"


#define	AVP_VENDOR_ID	0
#define L2TP_VER		2

#define	MAX_STOPCCN_RESULT_CODE	8
#define	MAX_CDN_RESULT_CODE	12
#define	MAX_ERROR_CODE	9


/*
 * is M bit set
 */
#define IS_M_SET(x)   (x & 0x8000)

/*
 * is H bit set
 */
#define IS_H_SET(x)   (x & 0x4000)

/*
 * get avp length
 */
#define GET_AVP_LEN(x)   (x & 0x0fff)


/*
 * Control Mseeage Types
 * the "Attribute Type" field value of AVP
 */

/* AVPs Applicable To All Control Messages */
#define	MSG_TYPE				0x0000
#define	RANDOM_VECTOR			0x0024
#define	RESULT_CODE				0x0001
#define	PROTOCOL_VERSION		0x0002
#define	FRAMING_CAPABILITIES	0x0003
#define	BEARER_CAPABILITIES		0x0004
#define	TIE_BREAKER				0x0005
#define	FIRMWARE_REVISION		0x0006
#define	HOST_NAME				0x0007
#define	VENDOR_NAME				0x0008
#define	ASSIGNED_TUNNEL_ID		0x0009
#define	RESEIVE_WINDOWS_SIZE	0x000a
#define	CHALLENGE				0x000b
#define	CHALLENGE_RESPONSE		0x000d

/* Call Management AVPs */
#define	CAUSE_CODE				0x000c
#define	ASSIGNED_SESSION_ID		0x000e
#define	CALL_SERIAL_NUMBER		0x000f
#define	MINIMUM_BPS				0x0010
#define	MAXIMUM_BPS				0x0011
#define	BEARER_TYPE				0x0012
#define	FRAMING_TYPE			0x0013
#define	CALLED_NUMBER			0x0015
#define	CALLING_NUMBER			0x0016
#define	SUB_ADDRESS				0x0017
#define	TX_CONNECT_SPEED		0x0018
#define	RX_CONNECT_SPEED		0x0026
#define	PHYSICAL_CHANNEL_ID		0x0019
#define	PRIVATE_GROU_ID			0x0025
#define	SQUENCING_REQUIRED		0x0027

/* Proxy LCP and Authentication AVPs */
#define	INIT_RECVD_LCP_CONFREQ	0x001a
#define	LAST_SENT_LCP_CONFREQ	0x001b
#define	LAST_RECVD_LCP_CONFREQ	0x001c
#define	PROXY_AUTHEN_TYPE		0x001d
#define	PROXY_AUTHEN_NAME		0x001e
#define	PROXY_AUTHEN_CHALLENGE	0x001f
#define	PROXY_AUTHEN_ID			0x0020
#define	PROXY_AUTHEN_REPONSE	0x0021

/* Call Status AVPs */
#define	CALL_ERROR				0x0022
#define	ACCM					0x0023


/*
 * Control Message Types,
 * the first AVP is Message Type,
 * and its Attribute Value field is shown below
 */

/* Control Connection Management */
#define	SCCRQ	0x0001	/* Start-Control-Connection-Request */
#define	SCCRP	0x0002	/* Start-Control-Connection-Reply */
#define	SCCCN	0x0003	/* Start-Control-Connection-Connected */
#define	StopCCN	0x0004	/* Stop-Control-Connection-Notification */
#define	HELLO	0x0006	/* Hello */

/* Call Management */
#define	OCRQ	0x0007	/* Outgoing-Call-Request */
#define	OCRP	0x0008	/* Outgoing-Call-Reply */
#define	OCCN	0x0009	/* Outgoing-Call-Connected */
#define	ICRQ	0x000a	/* Incoming-Call-Request */
#define	ICRP	0x000b	/* Incoming-Call-Reply */
#define	ICCN	0x000c	/* Incoming-Call-Connected */
#define	CDN	0x000e	/* Call-Disconnect-Notify */

/* Error Reporting */
#define	WEN		0x000f	/* WAN-Error-Notify */

/* PPP Session Control */
#define	SLI		0x0010	/* Set-Link-Info */


/*
 * FRAMING_CAPABILITIES AVP type
 */
#define SYNC_FRAME	1
#define ASYNC_FRAME	2


/*
 * Proxy Authen Type
 */
#define	TEXT_USER_PWD	0x0001
#define	PPP_CHAP		0x0002
#define	PPP_PAP			0x0003
#define	NO_AUTHEN		0x0004
#define	MSCHAPv1		0x0005



/* AVP head */
struct avp_hdr
{
    _u16 head_node;	/* contain length */
    _u16 vendor_id;
    _u16 attribute_type;

} ATTR(packed);



/*  */
struct avp_handler
{
    _u16    attr;
    int     need_M_bit;
    int     need_H_bit;
    int     ( *handler )( struct tunnel *, struct buffer * );

} ATTR(packed);



extern int handle_avp( struct tunnel *, struct buffer * );

extern void avp_add_msg_type( _u16 , struct buffer *);
extern void avp_add_protocol_ver( struct buffer * );
extern void avp_add_hostname( const struct tunnel *, struct buffer * );
extern void avp_add_frame_caps( const struct tunnel *, struct buffer * );
extern void avp_add_ass_tid( const struct tunnel *, struct buffer * );
extern void avp_add_Tx_con_speed( const struct tunnel *, struct buffer * );
extern void avp_add_frame_type( const struct tunnel *, struct buffer * );
extern void avp_add_call_S_num( const struct tunnel *, struct buffer * );
extern void avp_add_ass_sid( const struct tunnel *, struct buffer * );
extern void avp_add_result_code( const struct tunnel *, struct buffer * );

extern void avp_add_Rx_con_speed( const struct tunnel *, struct buffer * );
extern void avp_add_bearer_caps( const struct tunnel *, struct buffer * );
extern void avp_add_recv_win_size( const struct tunnel *, struct buffer * );
extern void avp_add_vendor_name( struct buffer * );
extern void avp_add_firmware_rev( struct buffer * );
extern void avp_add_proxy_auth_type( const struct tunnel *, struct buffer * );


#endif /* AVP_BUILDER_H */

