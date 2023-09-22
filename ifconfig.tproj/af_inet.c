/*
 * Copyright (c) 2009-2011, 2020 Apple Inc. All rights reserved.
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
 * Copyright (c) 1983, 1993
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
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>

#include <netinet/in.h>
#include <net/if_var.h>		/* for struct ifaddr */
#include <netinet/in_var.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "ifconfig.h"

static struct ifaliasreq in_addreq;
static struct ifreq in_ridreq;
static char addr_buf[NI_MAXHOST];	/*for getnameinfo()*/
extern char *f_inet, *f_addr;

static void
in_status(int s __unused, const struct ifaddrs *ifa)
{
	struct sockaddr_in *sin, null_sin;
	
	memset(&null_sin, 0, sizeof(null_sin));

	sin = (struct sockaddr_in *)ifa->ifa_addr;
	if (sin == NULL)
		return;

	if (f_addr == NULL || strcmp(f_addr, "default") == 0) {
		printf("\tinet %s", inet_ntoa(sin->sin_addr));
	} else {
		int error, n_flags;

		if (f_addr != NULL && strcmp(f_addr, "fqdn") == 0)
			n_flags = 0;
		else if (f_addr != NULL && strcmp(f_addr, "host") == 0)
			n_flags = NI_NOFQDN;
		else
			n_flags = NI_NUMERICHOST;

		error = getnameinfo((struct sockaddr *)sin, sin->sin_len, addr_buf,
					sizeof(addr_buf), NULL, 0, n_flags);
		if (error)
			inet_ntop(AF_INET, &sin->sin_addr, addr_buf, sizeof(addr_buf));

		printf("\tinet %s", addr_buf);
	}

	if (ifa->ifa_flags & IFF_POINTOPOINT) {
		sin = (struct sockaddr_in *)ifa->ifa_dstaddr;
		if (sin == NULL)
			sin = &null_sin;
		printf(" --> %s", inet_ntoa(sin->sin_addr));
	}

	sin = (struct sockaddr_in *)ifa->ifa_netmask;
	if (sin == NULL)
		sin = &null_sin;
	if (f_inet != NULL && strcmp(f_inet, "cidr") == 0) {
		int cidr = 32;
		unsigned long smask;

		smask = ntohl(sin->sin_addr.s_addr);
		while ((smask & 1) == 0) {
			smask = smask >> 1;
			cidr--;
			if (cidr == 0)
				break;
		}
		printf("/%d", cidr);
	} else if (f_inet != NULL && strcmp(f_inet, "dotted") == 0)
		printf(" netmask %s", inet_ntoa(sin->sin_addr));
	else {
		printf(" netmask 0x%lx", (unsigned long)ntohl(sin->sin_addr.s_addr));
	}

	if (ifa->ifa_flags & IFF_BROADCAST) {
		sin = (struct sockaddr_in *)ifa->ifa_broadaddr;
		if (sin != NULL && sin->sin_addr.s_addr != 0)
			printf(" broadcast %s", inet_ntoa(sin->sin_addr));
	}
	putchar('\n');
}

#define SIN(x) ((struct sockaddr_in *) &(x))
static struct sockaddr_in *sintab[] = {
	SIN(in_ridreq.ifr_addr), SIN(in_addreq.ifra_addr),
	SIN(in_addreq.ifra_mask), SIN(in_addreq.ifra_broadaddr)
};

static void
in_getaddr(const char *s, int which)
{
#ifndef MIN
#define	MIN(a,b)	((a)<(b)?(a):(b))
#endif /* MIN */
	struct sockaddr_in *sin = sintab[which];
	struct hostent *hp;
	struct netent *np;

	sin->sin_len = sizeof(*sin);
	if (which != MASK)
		sin->sin_family = AF_INET;

	if (which == ADDR) {
		char *p = NULL;

		if((p = strrchr(s, '/')) != NULL) {
			/* address is `name/masklen' */
			int masklen;
			int ret;
			struct sockaddr_in *min = sintab[MASK];
			*p = '\0';
			ret = sscanf(p+1, "%u", &masklen);
			if(ret != 1 || (masklen < 0 || masklen > 32)) {
				*p = '/';
				errx(1, "%s: bad value", s);
			}
			min->sin_len = sizeof(*min);
			min->sin_addr.s_addr = htonl(~((1LL << (32 - masklen)) - 1) & 
				              0xffffffff);
		}
	}

	if (inet_aton(s, &sin->sin_addr))
		return;
	if ((hp = gethostbyname(s)) != 0)
		bcopy(hp->h_addr, (char *)&sin->sin_addr, 
		    MIN(hp->h_length, sizeof(sin->sin_addr)));
	else if ((np = getnetbyname(s)) != 0)
		sin->sin_addr = inet_makeaddr(np->n_net, INADDR_ANY);
	else
		errx(1, "%s: bad value", s);
#undef MIN
}

static void
in_status_tunnel(int s)
{
	char src[NI_MAXHOST];
	char dst[NI_MAXHOST];
	struct ifreq ifr;
	const struct sockaddr *sa = (const struct sockaddr *) &ifr.ifr_addr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	if (ioctl(s, SIOCGIFPSRCADDR, (caddr_t)&ifr) < 0)
		return;
	if (sa->sa_family != AF_INET)
		return;
	if (getnameinfo(sa, sa->sa_len, src, sizeof(src), 0, 0, NI_NUMERICHOST) != 0)
		src[0] = '\0';

	if (ioctl(s, SIOCGIFPDSTADDR, (caddr_t)&ifr) < 0)
		return;
	if (sa->sa_family != AF_INET)
		return;
	if (getnameinfo(sa, sa->sa_len, dst, sizeof(dst), 0, 0, NI_NUMERICHOST) != 0)
		dst[0] = '\0';

	printf("\ttunnel inet %s --> %s\n", src, dst);
}

static void
in_set_tunnel(int s, struct addrinfo *srcres, struct addrinfo *dstres)
{
	struct ifaliasreq addreq;

	memset(&addreq, 0, sizeof(addreq));
	strlcpy(addreq.ifra_name, name, sizeof(addreq.ifra_name));
	memcpy(&addreq.ifra_addr, srcres->ai_addr, srcres->ai_addr->sa_len);
	memcpy(&addreq.ifra_dstaddr, dstres->ai_addr, dstres->ai_addr->sa_len);

	if (ioctl(s, SIOCSIFPHYADDR, &addreq) < 0)
		warn("SIOCSIFPHYADDR");
}

static void
in_set_router(int s, int enable)
{
	struct ifreq ifr;

	bzero(&ifr, sizeof (ifr));
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_intval = enable;

	if (ioctl(s, SIOCSETROUTERMODE, &ifr) < 0)
		warn("SIOCSETROUTERMODE");
}

static int
routermode_from_string(char * str, int *mode_p)
{
	int	success = 1;

	if (strcasecmp(str, "enabled") == 0) {
		*mode_p = 1;
	} else if (strcasecmp(str, "disabled") == 0) {
		*mode_p = 0;
	} else {
		success = 0;
	}
	return (success);
}

static const char *
routermode_string(int mode)
{
	const char *	str;

	switch (mode) {
	case 0:
		str = "disabled";
		break;
	case 1:
		str = "enabled";
		break;
	default:
		str = "<unknown>";
		break;
	}
	return str;
}

static int
in_routermode(int s, int argc, char *const*argv)
{
	struct ifreq 	ifr;
	int 		ret;

	bzero(&ifr, sizeof (ifr));
	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	if (argc == 0) {
		ret = 0;
#ifndef SIOCGETROUTERMODE
#define SIOCGETROUTERMODE _IOWR('i', 209, struct ifreq)   /* get IPv4 router mode state */
#endif /* SIOCGETROUTERMODE */
		if (ioctl(s, SIOCGETROUTERMODE, &ifr) < 0) {
			if (argv != NULL) {
				warn("SIOCGETROUTERMODE");
			}
		} else {
			/* argv is NULL if we're called from status() */
			printf("%s%s\n",
			       (argv == NULL) ? "\troutermode4: " : "",
			       routermode_string(ifr.ifr_intval));
		}
		ret = 0;
	} else {
		int mode;

		if (routermode_from_string(argv[0], &mode) == 0) {
			errx(EXIT_FAILURE,
			     "mode '%s' invalid, must be one of "
			     "disabled or enabled",
			     argv[0]);
		}
		ifr.ifr_intval = mode;
		if (ioctl(s, SIOCSETROUTERMODE, &ifr) < 0) {
			warn("SIOCSETROUTERMODE");
		}
		ret = 1;
	}
	return ret;
}

static struct afswtch af_inet = {
	.af_name	= "inet",
	.af_af		= AF_INET,
	.af_status	= in_status,
	.af_getaddr	= in_getaddr,
	.af_status_tunnel = in_status_tunnel,
	.af_settunnel	= in_set_tunnel,
	.af_setrouter	= in_set_router,
	.af_routermode	= in_routermode,
	.af_difaddr	= SIOCDIFADDR,
	.af_aifaddr	= SIOCAIFADDR,
	.af_ridreq	= &in_ridreq,
	.af_addreq	= &in_addreq,
};

static __constructor void
inet_ctor(void)
{
	af_register(&af_inet);
}
