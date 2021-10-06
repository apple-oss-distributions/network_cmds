/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*-
 * Copyright (c) 2001 Charles Mott <cmott@scientech.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Based upon:
 * $FreeBSD: src/lib/libalias/alias_local.h,v 1.10.2.5 2001/08/01 09:52:26 obrien Exp $
 */

/*
 * Alias_local.h contains the function prototypes for alias.c,
 * alias_db.c, alias_util.c and alias_ftp.c, alias_irc.c (as well
 * as any future add-ons).  It also includes macros, globals and
 * struct definitions shared by more than one alias*.c file.
 *
 * This include file is intended to be used only within the aliasing
 * software.  Outside world interfaces are defined in alias.h
 *
 * This software is placed into the public domain with no restrictions
 * on its distribution.
 *
 * Initial version:  August, 1996  (cjm)    
 *
 * <updated several times by original author and Eivind Eklund>
 */

#ifndef _ALIAS_LOCAL_H_
#define	_ALIAS_LOCAL_H_

#ifndef NULL
#define NULL 0
#endif

/* Macros */

/*
 * The following macro is used to update an
 * internet checksum.  "delta" is a 32-bit
 * accumulation of all the changes to the
 * checksum (adding in new 16-bit words and
 * subtracting out old words), and "cksum"
 * is the checksum value to be updated.
 */
#define	ADJUST_CHECKSUM(acc, cksum) \
	do { \
		acc += cksum; \
		if (acc < 0) { \
			acc = -acc; \
			acc = (acc >> 16) + (acc & 0xffff); \
			acc += acc >> 16; \
			cksum = (u_short) ~acc; \
		} else { \
			acc = (acc >> 16) + (acc & 0xffff); \
			acc += acc >> 16; \
			cksum = (u_short) acc; \
		} \
	} while (0)

/* Globals */

extern int packetAliasMode;


/* Structs */

struct alias_link;    /* Incomplete structure */


/* Prototypes */

/* General utilities */
u_short IpChecksum(struct ip *);
u_short TcpChecksum(struct ip *);
void DifferentialChecksum(u_short *, u_short *, u_short *, int);

/* Internal data access */
struct alias_link *
FindIcmpIn(struct in_addr, struct in_addr, u_short, int);

struct alias_link *
FindIcmpOut(struct in_addr, struct in_addr, u_short, int);

struct alias_link *
FindFragmentIn1(struct in_addr, struct in_addr, u_short);

struct alias_link *
FindFragmentIn2(struct in_addr, struct in_addr, u_short);

struct alias_link *
AddFragmentPtrLink(struct in_addr, u_short);

struct alias_link *
FindFragmentPtr(struct in_addr, u_short);

struct alias_link *
FindProtoIn(struct in_addr, struct in_addr, u_char);

struct alias_link *
FindProtoOut(struct in_addr, struct in_addr, u_char);

struct alias_link *
FindUdpTcpIn (struct in_addr, struct in_addr, u_short, u_short, u_char, int);

struct alias_link *
FindUdpTcpOut(struct in_addr, struct in_addr, u_short, u_short, u_char, int);

struct alias_link *
AddPptp(struct in_addr, struct in_addr, struct in_addr, u_int16_t);

struct alias_link *
FindPptpOutByCallId(struct in_addr, struct in_addr, u_int16_t);

struct alias_link *
FindPptpInByCallId(struct in_addr, struct in_addr, u_int16_t);

struct alias_link *
FindPptpOutByPeerCallId(struct in_addr, struct in_addr, u_int16_t);

struct alias_link *
FindPptpInByPeerCallId(struct in_addr, struct in_addr, u_int16_t);

struct alias_link *
FindRtspOut(struct in_addr, struct in_addr, u_short, u_short, u_char);

struct in_addr
FindOriginalAddress(struct in_addr);

struct in_addr
FindAliasAddress(struct in_addr);

/* External data access/modification */
int FindNewPortGroup(struct in_addr, struct in_addr,
                     u_short, u_short, u_short, u_char, u_char);
void GetFragmentAddr(struct alias_link *, struct in_addr *);
void SetFragmentAddr(struct alias_link *, struct in_addr);
void GetFragmentPtr(struct alias_link *, char **);
void SetFragmentPtr(struct alias_link *, char *);
void SetStateIn(struct alias_link *, int);
void SetStateOut(struct alias_link *, int);
int GetStateIn(struct alias_link *);
int GetStateOut(struct alias_link *);
struct in_addr GetOriginalAddress(struct alias_link *);
struct in_addr GetDestAddress(struct alias_link *);
struct in_addr GetAliasAddress(struct alias_link *);
struct in_addr GetDefaultAliasAddress(void);
void SetDefaultAliasAddress(struct in_addr);
u_short GetOriginalPort(struct alias_link *);
u_short GetAliasPort(struct alias_link *);
struct in_addr GetProxyAddress(struct alias_link *);
void SetProxyAddress(struct alias_link *, struct in_addr);
u_short GetProxyPort(struct alias_link *);
void SetProxyPort(struct alias_link *, u_short);
void SetAckModified(struct alias_link *);
int GetAckModified(struct alias_link *);
int GetDeltaAckIn(struct ip *, struct alias_link *);
int GetDeltaSeqOut(struct ip *, struct alias_link *);
void AddSeq(struct ip *, struct alias_link *, int);
void SetExpire(struct alias_link *, int);
void ClearCheckNewLink(void);
void SetLastLineCrlfTermed(struct alias_link *, int);
int GetLastLineCrlfTermed(struct alias_link *);
void SetDestCallId(struct alias_link *, u_int16_t);
#ifndef NO_FW_PUNCH
void PunchFWHole(struct alias_link *);
#endif


/* Housekeeping function */
void HouseKeeping(void);

/* Tcp specfic routines */
/*lint -save -library Suppress flexelint warnings */

/* FTP routines */
void AliasHandleFtpOut(struct ip *, struct alias_link *, int);

/* IRC routines */
void AliasHandleIrcOut(struct ip *, struct alias_link *, int);

/* RTSP routines */
void AliasHandleRtspOut(struct ip *, struct alias_link *, int);

/* PPTP routines */
void AliasHandlePptpOut(struct ip *, struct alias_link *);
void AliasHandlePptpIn(struct ip *, struct alias_link *);
int AliasHandlePptpGreOut(struct ip *);
int AliasHandlePptpGreIn(struct ip *);

/* NetBIOS routines */
int AliasHandleUdpNbt(struct ip *, struct alias_link *, struct in_addr *, u_short);
int AliasHandleUdpNbtNS(struct ip *, struct alias_link *, struct in_addr *, u_short *, struct in_addr *, u_short *);

/* CUSeeMe routines */
void AliasHandleCUSeeMeOut(struct ip *, struct alias_link *);
void AliasHandleCUSeeMeIn(struct ip *, struct in_addr);

/* Transparent proxy routines */
int ProxyCheck(struct ip *, struct in_addr *, u_short *);
void ProxyModify(struct alias_link *, struct ip *, int, int);


enum alias_tcp_state {
	ALIAS_TCP_STATE_NOT_CONNECTED,
	ALIAS_TCP_STATE_CONNECTED,
	ALIAS_TCP_STATE_DISCONNECTED
};

/*lint -restore */

#endif /* !_ALIAS_LOCAL_H_ */
