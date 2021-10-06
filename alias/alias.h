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
 * $FreeBSD: src/lib/libalias/alias.h,v 1.12.2.4 2001/08/01 09:36:40 obrien Exp $
 */

/*-
 * Alias.h defines the outside world interfaces for the packet aliasing
 * software.
 * 
 * This software is placed into the public domain with no restrictions on its
 * distribution.
 */

#ifndef _ALIAS_H_
#define	_ALIAS_H_

/* Alias link representative (incomplete struct) */
struct alias_link;

/* External interfaces (API) to packet aliasing engine */

/* Initialization and Control */
    extern void
    PacketAliasInit(void);

    extern void
    PacketAliasUninit(void);

    extern void
    PacketAliasSetAddress(struct in_addr);

    extern unsigned int
    PacketAliasSetMode(unsigned int, unsigned int);

#ifndef NO_FW_PUNCH
    extern void
    PacketAliasSetFWBase(unsigned int, unsigned int);
#endif

    extern void
    PacketAliasClampMSS(u_short mss);

/* Packet Handling */
    extern int
    PacketAliasIn(char *, int maxpacketsize);

    extern int
    PacketAliasOut(char *, int maxpacketsize);

    extern int
    PacketUnaliasOut(char *, int maxpacketsize);

/* Port and Address Redirection */
    extern struct alias_link *
    PacketAliasRedirectPort(struct in_addr, u_short, 
                            struct in_addr, u_short,
                            struct in_addr, u_short,
                            u_char);

    extern int
    PacketAliasAddServer(struct alias_link *link,
                         struct in_addr addr,
                         u_short port);

    extern struct alias_link *
    PacketAliasRedirectProto(struct in_addr,
                             struct in_addr,
                             struct in_addr,
                             u_char);

    extern struct alias_link *
    PacketAliasRedirectAddr(struct in_addr,
                            struct in_addr);

    extern void
    PacketAliasRedirectDelete(struct alias_link *);

/* Fragment Handling */
    extern int
    PacketAliasSaveFragment(char *);

    extern char *
    PacketAliasGetFragment(char *);

    extern void 
    PacketAliasFragmentIn(char *, char *);

/* Miscellaneous Functions */
    extern void
    PacketAliasSetTarget(struct in_addr addr);

    extern int
    PacketAliasCheckNewLink(void);

    extern u_short
    PacketAliasInternetChecksum(u_short *, int);

/* Transparent Proxying */
    extern int
    PacketAliasProxyRule(const char *);


/********************** Mode flags ********************/
/* Set these flags using PacketAliasSetMode() */

/* If PKT_ALIAS_LOG is set, a message will be printed to
	/var/log/alias.log every time a link is created or deleted.  This
	is useful for debugging */
#define PKT_ALIAS_LOG 0x01

/* If PKT_ALIAS_DENY_INCOMING is set, then incoming connections (e.g.
	to ftp, telnet or web servers will be prevented by the aliasing
	mechanism.  */
#define PKT_ALIAS_DENY_INCOMING 0x02

/* If PKT_ALIAS_SAME_PORTS is set, packets will be attempted sent from
	the same port as they originated on.  This allows e.g. rsh to work
	*99% of the time*, but _not_ 100%.  (It will be slightly flakey
	instead of not working at all.)  This mode bit is set by
        PacketAliasInit(), so it is a default mode of operation. */
#define PKT_ALIAS_SAME_PORTS 0x04

/* If PKT_ALIAS_USE_SOCKETS is set, then when partially specified
	links (e.g. destination port and/or address is zero), the packet
	aliasing engine will attempt to allocate a socket for the aliasing
	port it chooses.  This will avoid interference with the host
	machine.  Fully specified links do not require this.  This bit
        is set after a call to PacketAliasInit(), so it is a default
        mode of operation. */
#define PKT_ALIAS_USE_SOCKETS 0x08

/* If PKT_ALIAS_UNREGISTERED_ONLY is set, then only packets with
	unregistered source addresses will be aliased.  Private
	addresses are those in the following ranges:
		10.0.0.0     ->   10.255.255.255
		172.16.0.0   ->   172.31.255.255
		192.168.0.0  ->   192.168.255.255  */
#define PKT_ALIAS_UNREGISTERED_ONLY 0x10

/* If PKT_ALIAS_RESET_ON_ADDR_CHANGE is set, then the table of dynamic
	aliasing links will be reset whenever PacketAliasSetAddress()
        changes the default aliasing address.  If the default aliasing
        address is left unchanged by this function call, then the
        table of dynamic aliasing links will be left intact.  This
        bit is set after a call to PacketAliasInit(). */
#define PKT_ALIAS_RESET_ON_ADDR_CHANGE 0x20

#ifndef NO_FW_PUNCH
/* If PKT_ALIAS_PUNCH_FW is set, active FTP and IRC DCC connections
   will create a 'hole' in the firewall to allow the transfers to
   work.  Where (IPFW "line-numbers") the hole is created is
   controlled by PacketAliasSetFWBase(base, size). The hole will be
   attached to that particular alias_link, so when the link goes away
   so do the hole.  */
#define PKT_ALIAS_PUNCH_FW 0x100
#endif

/* If PKT_ALIAS_PROXY_ONLY is set, then NAT will be disabled and only
      transparent proxying performed */
#define PKT_ALIAS_PROXY_ONLY 0x40

/* If PKT_ALIAS_REVERSE is set, the actions of PacketAliasIn()
      and PacketAliasOut() are reversed */
#define PKT_ALIAS_REVERSE 0x80

/* Return Codes */
#define PKT_ALIAS_ERROR -1
#define PKT_ALIAS_OK 1
#define PKT_ALIAS_IGNORED 2
#define PKT_ALIAS_UNRESOLVED_FRAGMENT 3
#define PKT_ALIAS_FOUND_HEADER_FRAGMENT 4

#endif
/* lint -restore */
