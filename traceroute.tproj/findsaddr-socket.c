/*
 * Copyright (c) 2008-2009 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*
 * Copyright (c) 2000
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/contrib/traceroute/findsaddr-socket.c,v 1.2 2002/07/30 04:49:13 fenner Exp $
 */

/* XXX Yes this is WAY too complicated */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#include <sys/time.h>				/* concession to AIX */

#if __STDC__
struct mbuf;
struct rtentry;
#endif

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gnuc.h"
#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "findsaddr.h"

#ifdef HAVE_SOCKADDR_SA_LEN
#define SALEN(sa) ((sa)->sa_len)
#else
#define SALEN(sa) salen(sa)
#endif

#ifndef roundup
#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))  /* to any y */
#endif

struct rtmsg {
        struct rt_msghdr rtmsg;
        u_char data[512];
};

static struct rtmsg rtmsg = {
	{ 0, RTM_VERSION, RTM_GET, 0,
	RTF_UP | RTF_GATEWAY | RTF_HOST | RTF_STATIC,
	RTA_DST | RTA_IFA, 0, 0, 0, 0, 0, { 0 } },
	{ 0 }
};

#ifndef HAVE_SOCKADDR_SA_LEN
static int salen(struct sockaddr *);
#endif

/*
 * Return the source address for the given destination address
 */
const char *
findsaddr(const struct sockaddr_in *to,
	struct sockaddr_in *from,
    u_short *ifindex)
{
	struct rt_msghdr *rp;
	u_char *cp;

	struct sockaddr_in *sp, *ifa;
	struct sockaddr *sa;
	int s, size, cc, seq, i;
	pid_t pid;
	static char errbuf[512];

	s = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
	if (s < 0) {
		snprintf(errbuf, sizeof(errbuf), "socket: %.128s", strerror(errno));
		return (errbuf);
	}

	seq = 0;
	pid = getpid();

	rp = &rtmsg.rtmsg;
	rp->rtm_seq = ++seq;
	cp = (u_char *)(rp + 1);

	sp = (struct sockaddr_in *)cp;
	*sp = *to;
	cp += roundup(SALEN((struct sockaddr *)sp), sizeof(u_int32_t));

	size = cp - (u_char *)rp;
	rp->rtm_msglen = size;

	cc = write(s, (char *)rp, size);
	if (cc < 0) {
		snprintf(errbuf, sizeof(errbuf), "write: %.128s", strerror(errno));
		close(s);
		return (errbuf);
	}
	if (cc != size) {
		snprintf(errbuf, sizeof(errbuf), "short write (%d != %d)", cc, size);
		close(s);
		return (errbuf);
	}

	size = sizeof(rtmsg);
	do {
		memset(rp, 0, size);
		cc = read(s, (char *)rp, size);
		if (cc < 0) {
			snprintf(errbuf, sizeof(errbuf), "read: %.128s", strerror(errno));
			close(s);
			return (errbuf);
		}

	} while (rp->rtm_seq != seq || rp->rtm_pid != pid);
	close(s);


	if (rp->rtm_version != RTM_VERSION) {
		snprintf(errbuf, sizeof(errbuf), "bad version %d", rp->rtm_version);
		return (errbuf);
	}
	if (rp->rtm_msglen > cc) {
		snprintf(errbuf, sizeof(errbuf), "bad msglen %d > %d", rp->rtm_msglen, cc);
		return (errbuf);
	}
	if (rp->rtm_errno != 0) {
		snprintf(errbuf, sizeof(errbuf), "rtm_errno: %.128s", strerror(rp->rtm_errno));
		return (errbuf);
	}

	/* Find the interface sockaddr */
	cp = (u_char *)(rp + 1);
	for (i = 1; i != 0; i <<= 1)
		if ((i & rp->rtm_addrs) != 0) {
			sa = (struct sockaddr *)cp;
			switch (i) {

			case RTA_IFA:
				if (sa->sa_family == AF_INET) {
					ifa = (struct sockaddr_in *)cp;
					if (ifa->sin_addr.s_addr != 0) {
						*from = *ifa;
						*ifindex  = rp->rtm_index;
						return (NULL);
					}
				}
				break;

			default:
				break;
				/* empty */
			}

			if (SALEN(sa) == 0)
				cp += sizeof (u_int32_t);
			else
				cp += roundup(SALEN(sa), sizeof (u_int32_t));
		}

	return ("failed!");
}

#ifndef HAVE_SOCKADDR_SA_LEN
static int
salen(struct sockaddr *sa)
{
	switch (sa->sa_family) {

	case AF_INET:
		return (sizeof(struct sockaddr_in));

	case AF_LINK:
		return (sizeof(struct sockaddr_dl));

	default:
		return (sizeof(struct sockaddr));
	}
}
#endif
