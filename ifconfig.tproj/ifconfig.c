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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
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

#ifndef lint
static const char copyright[] =
"@(#) Copyright (c) 1983, 1993\n\
	The Regents of the University of California.  All rights reserved.\n";
#endif /* not lint */

#ifndef lint
#if 0
static char sccsid[] = "@(#)ifconfig.c	8.2 (Berkeley) 2/16/94";
#endif
static const char rcsid[] =
	"$Id: ifconfig.c,v 1.5.28.1 2004/04/14 00:27:17 lindak Exp $";
#endif /* not lint */

#include <sys/param.h>
#define KERNEL_PRIVATE
#include <sys/ioctl.h>
#undef KERNEL_PRIVATE
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>

/* IP */
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef INET6
#include <netinet6/nd6.h>	/* Define ND6_INFINITE_LIFETIME */
#endif


/* XNS */
#ifdef NS
#define	NSIP
#include <netns/ns.h>
#include <netns/ns_if.h>
#endif
/* OSI */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct	ether_addr *ether_aton __P((const char *));

#include "ifconfig.h"

/* wrapper for KAME-special getnameinfo() */
#ifndef NI_WITHSCOPEID
#define	NI_WITHSCOPEID	0
#endif

struct	ifreq		ifr, ridreq;
struct	ifaliasreq	addreq;
#ifdef INET6
struct	in6_ifreq	in6_ridreq;
struct	in6_aliasreq	in6_addreq = 
  { { 0 }, 
    { 0 }, 
    { 0 }, 
    { 0 }, 
    0, 
    { 0, 0, ND6_INFINITE_LIFETIME, ND6_INFINITE_LIFETIME } };
#endif
struct	sockaddr_in	netmask;


char	name[32];
int	flags;
int	metric;
int	mtu;
int	setaddr;
int	setipdst;
int	setmask;
int	doalias;
int	clearaddr;
int	newaddr = 1;
#ifdef INET6
static	int ip6lifetime;
#endif

struct	afswtch;

int supmedia = 0;
int listcloners = 0;

#ifdef INET6
char	addr_buf[MAXHOSTNAMELEN *2 + 1];	/*for getnameinfo()*/
#endif

void	Perror __P((const char *cmd));

int	ifconfig __P((int argc, char *const *argv, const struct afswtch *afp));
void	notealias __P((const char *, int, int, const struct afswtch *afp));
void	printb __P((const char *s, unsigned value, const char *bits));
void	rt_xaddrs __P((caddr_t, caddr_t, struct rt_addrinfo *));
void	status __P((const struct afswtch *afp, int addrcount,
		    struct sockaddr_dl *sdl, struct if_msghdr *ifm,
		    struct ifa_msghdr *ifam));
void	tunnel_status __P((int s));
void	usage __P((void));

#ifdef INET6
void	in6_fillscopeid __P((struct sockaddr_in6 *sin6));
int	prefix __P((void *, int));
static	char *sec2str __P((time_t));
int	explicit_prefix = 0;
#endif

typedef	void c_func __P((const char *cmd, int arg, int s, const struct afswtch *afp));
typedef	void c_func2 __P((const char *arg, const char *arg2, int s, const struct afswtch *afp));
c_func	setifaddr, setifbroadaddr, setifdstaddr, setifnetmask;
c_func2	settunnel;
c_func	deletetunnel;
#ifdef INET6
c_func	setifprefixlen;
c_func	setip6flags;
c_func  setip6pltime;
c_func  setip6vltime;
c_func2	setip6lifetime;
#endif
c_func	setifipdst;
c_func	setifflags, setifmetric, setifmtu, setiflladdr;
c_func	clone_destroy;


void clone_create(void);
#define	NEXTARG		0xffffff
#define	NEXTARG2	0xfffffe

const
struct	cmd {
	const	char *c_name;
	int	c_parameter;		/* NEXTARG means next argv */
	void	(*c_func) __P((const char *, int, int, const struct afswtch *afp));
	void	(*c_func2) __P((const char *, const char *, int, const struct afswtch *afp));
} cmds[] = {
	{ "up",		IFF_UP,		setifflags } ,
	{ "down",	-IFF_UP,	setifflags },
	{ "arp",	-IFF_NOARP,	setifflags },
	{ "-arp",	IFF_NOARP,	setifflags },
	{ "debug",	IFF_DEBUG,	setifflags },
	{ "-debug",	-IFF_DEBUG,	setifflags },
	{ "add",	IFF_UP,		notealias },
	{ "alias",	IFF_UP,		notealias },
	{ "-alias",	-IFF_UP,	notealias },
	{ "delete",	-IFF_UP,	notealias },
	{ "remove",	-IFF_UP,	notealias },
#ifdef notdef
#define	EN_SWABIPS	0x1000
	{ "swabips",	EN_SWABIPS,	setifflags },
	{ "-swabips",	-EN_SWABIPS,	setifflags },
#endif
	{ "netmask",	NEXTARG,	setifnetmask },
#ifdef INET6
	{ "prefixlen",	NEXTARG,	setifprefixlen },
	{ "anycast",	IN6_IFF_ANYCAST, setip6flags },
	{ "tentative",	IN6_IFF_TENTATIVE, setip6flags },
	{ "-tentative",	-IN6_IFF_TENTATIVE, setip6flags },
	{ "deprecated",	IN6_IFF_DEPRECATED, setip6flags },
	{ "-deprecated", -IN6_IFF_DEPRECATED, setip6flags },
	{ "autoconf",	IN6_IFF_AUTOCONF, setip6flags },
	{ "-autoconf",	-IN6_IFF_AUTOCONF, setip6flags },
	{ "pltime",     NEXTARG,        setip6pltime },
	{ "vltime",     NEXTARG,        setip6vltime },
#endif
	{ "metric",	NEXTARG,	setifmetric },
	{ "broadcast",	NEXTARG,	setifbroadaddr },
	{ "ipdst",	NEXTARG,	setifipdst },
	{ "tunnel",	NEXTARG2,	NULL,	settunnel },
	{ "deletetunnel", 0,		deletetunnel },
	{ "link0",	IFF_LINK0,	setifflags },
	{ "-link0",	-IFF_LINK0,	setifflags },
	{ "link1",	IFF_LINK1,	setifflags },
	{ "-link1",	-IFF_LINK1,	setifflags },
	{ "link2",	IFF_LINK2,	setifflags },
	{ "-link2",	-IFF_LINK2,	setifflags },
#if USE_IF_MEDIA
	{ "media",	NEXTARG,	setmedia },
	{ "mediaopt",	NEXTARG,	setmediaopt },
	{ "-mediaopt",	NEXTARG,	unsetmediaopt },
#endif
#ifdef USE_VLANS
	{ "vlan",	NEXTARG,	setvlantag },
	{ "vlandev",	NEXTARG,	setvlandev },
	{ "-vlandev",	NEXTARG,	unsetvlandev },
#endif
#if 0
	/* XXX `create' special-cased below */
	{"create",	0,		clone_create },
	{"plumb",	0,		clone_create },
#endif
	{"destroy",	0,		clone_destroy },
	{"unplumb",	0,		clone_destroy },
#ifdef USE_IEEE80211
	{ "ssid",	NEXTARG,	set80211ssid },
	{ "nwid",	NEXTARG,	set80211ssid },
	{ "stationname", NEXTARG,	set80211stationname },
	{ "station",	NEXTARG,	set80211stationname },	/* BSD/OS */
	{ "channel",	NEXTARG,	set80211channel },
	{ "authmode",	NEXTARG,	set80211authmode },
	{ "powersavemode", NEXTARG,	set80211powersavemode },
	{ "powersave",	1,		set80211powersave },
	{ "-powersave",	0,		set80211powersave },
	{ "powersavesleep", NEXTARG,	set80211powersavesleep },
	{ "wepmode",	NEXTARG,	set80211wepmode },
	{ "wep",	1,		set80211wep },
	{ "-wep",	0,		set80211wep },
	{ "weptxkey",	NEXTARG,	set80211weptxkey },
	{ "wepkey",	NEXTARG,	set80211wepkey },
	{ "nwkey",	NEXTARG,	set80211nwkey },	/* NetBSD */
	{ "-nwkey",	0,		set80211wep },		/* NetBSD */
#endif
	{ "normal",	-IFF_LINK0,	setifflags },
	{ "compress",	IFF_LINK0,	setifflags },
	{ "noicmp",	IFF_LINK1,	setifflags },
	{ "mtu",	NEXTARG,	setifmtu },
	{ "lladdr",	NEXTARG,	setiflladdr },
	{ 0,		0,		setifaddr },
	{ 0,		0,		setifdstaddr },
};

/*
 * XNS support liberally adapted from code written at the University of
 * Maryland principally by James O'Toole and Chris Torek.
 */
typedef	void af_status __P((int, struct rt_addrinfo *));
typedef	void af_getaddr __P((const char *, int));
typedef void af_getprefix __P((const char *, int));

af_status	in_status, at_status, ether_status;
af_getaddr	in_getaddr, at_getaddr, ether_getaddr;


#ifdef INET6
af_status	in6_status;
af_getaddr	in6_getaddr;
af_getprefix	in6_getprefix;
#endif /*INET6*/
#ifdef NS
af_status	xns_status;
af_getaddr	xns_getaddr;
#endif

/* Known address families */
const
struct	afswtch {
	const char *af_name;
	short af_af;
	af_status *af_status;
	af_getaddr *af_getaddr;
	af_getprefix *af_getprefix;
	u_long af_difaddr;
	u_long af_aifaddr;
	caddr_t af_ridreq;
	caddr_t af_addreq;
} afs[] = {
#define C(x) ((caddr_t) &x)
	{ "inet", AF_INET, in_status, in_getaddr, NULL,
	     SIOCDIFADDR, SIOCAIFADDR, C(ridreq), C(addreq) },
#ifdef INET6
	{ "inet6", AF_INET6, in6_status, in6_getaddr, in6_getprefix,
	     SIOCDIFADDR_IN6, SIOCAIFADDR_IN6,
	     C(in6_ridreq), C(in6_addreq) },
#endif /*INET6*/
#ifdef NS
	{ "ns", AF_NS, xns_status, xns_getaddr, NULL,
	     SIOCDIFADDR, SIOCAIFADDR, C(ridreq), C(addreq) },
#endif
	{ "ether", AF_LINK, ether_status, ether_getaddr, NULL,
	     0, SIOCSIFLLADDR, NULL, C(ridreq) },
#if 0	/* XXX conflicts with the media command */
#ifdef USE_IF_MEDIA
	{ "media", AF_UNSPEC, media_status, NULL, NULL, }, /* XXX not real!! */
#endif
#ifdef USE_VLANS
	{ "vlan", AF_UNSPEC, vlan_status, NULL, NULL, },  /* XXX not real!! */
#endif
#ifdef USE_IEEE80211
	{ "ieee80211", AF_UNSPEC, ieee80211_status, NULL, NULL, },  /* XXX not real!! */
#endif
#endif
	{ 0,	0,	    0,		0 }
};

/*
 * Expand the compacted form of addresses as returned via the
 * configuration read via sysctl().
 */

#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

void
rt_xaddrs(cp, cplim, rtinfo)
	caddr_t cp, cplim;
	struct rt_addrinfo *rtinfo;
{
	struct sockaddr *sa;
	int i;

	memset(rtinfo->rti_info, 0, sizeof(rtinfo->rti_info));
	for (i = 0; (i < RTAX_MAX) && (cp < cplim); i++) {
		if ((rtinfo->rti_addrs & (1 << i)) == 0)
			continue;
		rtinfo->rti_info[i] = sa = (struct sockaddr *)cp;
		ADVANCE(cp, sa);
	}
}


void
usage()
{
#ifndef INET6
    	fprintf(stderr, "%s",
	"usage: ifconfig interface address_family [address [dest_address]]\n"
	"                [parameters]\n"
	"       ifconfig interface create\n"
	"       ifconfig -a [-d] [-m] [-u] [address_family]\n"
	"       ifconfig -l [-d] [-u] [address_family]\n"
	"       ifconfig [-d] [-m] [-u]\n");
#else
	fprintf(stderr, "%s",
	"usage: ifconfig [-L] interface address_family [address [dest_address]]\n"
	"                [parameters]\n"
	"       ifconfig interface create\n"
	"       ifconfig -a [-L] [-d] [-m] [-u] [address_family]\n"
	"       ifconfig -l [-d] [-u] [address_family]\n"
	"       ifconfig [-L] [-d] [-m] [-u]\n");
#endif
	exit(1);
}

int
main(argc, argv)
	int argc;
	char *const *argv;
{
	int c;
	int all, namesonly, downonly, uponly;
	int foundit = 0, need_nl = 0;
	const struct afswtch *afp = 0;
	int addrcount;
	struct	if_msghdr *ifm, *nextifm;
	struct	ifa_msghdr *ifam;
	struct	sockaddr_dl *sdl;
	char	*buf, *lim, *next;


	size_t needed;
	int mib[6];

	/* Parse leading line options */
	all = downonly = uponly = namesonly = 0;
	while ((c = getopt(argc, argv, "adlmu"
#ifdef INET6
					"L"
#endif
			)) != -1) {
		switch (c) {
		case 'a':	/* scan all interfaces */
			all++;
			break;
		case 'd':	/* restrict scan to "down" interfaces */
			downonly++;
			break;
		case 'l':	/* scan interface names only */
			namesonly++;
			break;
		case 'm':	/* show media choices in status */
			supmedia = 1;
			break;
		case 'u':	/* restrict scan to "up" interfaces */
			uponly++;
			break;
#ifdef INET6
		case 'L':
			ip6lifetime++;	/* print IPv6 address lifetime */
			break;
#endif
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	/* -l cannot be used with -a or -m */
	if (namesonly && (all || supmedia))
		usage();

	/* nonsense.. */
	if (uponly && downonly)
		usage();

	/* no arguments is equivalent to '-a' */
	if (!namesonly && argc < 1)
		all = 1;

	/* -a and -l allow an address family arg to limit the output */
	if (all || namesonly) {
		if (argc > 1)
			usage();

		if (argc == 1) {
			for (afp = afs; afp->af_name; afp++)
				if (strcmp(afp->af_name, *argv) == 0) {
					argc--, argv++;
					break;
				}
			if (afp->af_name == NULL)
				usage();
			/* leave with afp non-zero */
		}
	} else {
		/* not listing, need an argument */
		if (argc < 1)
			usage();

		strncpy(name, *argv, sizeof(name));
		argc--, argv++;

		/*
		 * NOTE:  We must special-case the `create' command right
		 * here as we would otherwise fail when trying to find
		 * the interface.
		 */
		if (argc > 0 && (strcmp(argv[0], "create") == 0 ||
		    strcmp(argv[0], "plumb") == 0)) {
			clone_create();
			argc--, argv++;
			if (argc == 0)
				exit(0);
		}
	}

	/* Check for address family */
	if (argc > 0) {
		for (afp = afs; afp->af_name; afp++)
			if (strcmp(afp->af_name, *argv) == 0) {
				argc--, argv++;
				break;
			}
		if (afp->af_name == NULL)
			afp = NULL;	/* not a family, NULL */
	}

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = 0;	/* address family */
	mib[4] = NET_RT_IFLIST;
	mib[5] = 0;

	/* if particular family specified, only ask about it */
	if (afp)
		mib[3] = afp->af_af;

	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
		errx(1, "iflist-sysctl-estimate");
	if ((buf = malloc(needed)) == NULL)
		errx(1, "malloc");
	if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
		errx(1, "actual retrieval of interface table");
	lim = buf + needed;

	next = buf;
	while (next < lim) {

		ifm = (struct if_msghdr *)next;
		
		if (ifm->ifm_type == RTM_IFINFO) {
			sdl = (struct sockaddr_dl *)(ifm + 1);
			flags = ifm->ifm_flags;
		} else {
			fprintf(stderr, "out of sync parsing NET_RT_IFLIST\n");
			fprintf(stderr, "expected %d, got %d\n", RTM_IFINFO,
				ifm->ifm_type);
			fprintf(stderr, "msglen = %d\n", ifm->ifm_msglen);
			fprintf(stderr, "buf:%p, next:%p, lim:%p\n", buf, next,
				lim);
			exit (1);
		}

		next += ifm->ifm_msglen;
		ifam = NULL;
		addrcount = 0;
		while (next < lim) {

			nextifm = (struct if_msghdr *)next;

			if (nextifm->ifm_type != RTM_NEWADDR)
				break;

			if (ifam == NULL)
				ifam = (struct ifa_msghdr *)nextifm;

			addrcount++;
			next += nextifm->ifm_msglen;
		}

		if (all || namesonly) {
			if (uponly)
				if ((flags & IFF_UP) == 0)
					continue; /* not up */
			if (downonly)
				if (flags & IFF_UP)
					continue; /* not down */
			strncpy(name, sdl->sdl_data, sdl->sdl_nlen);
			name[sdl->sdl_nlen] = '\0';
			if (namesonly) {
				if (afp == NULL ||
					afp->af_status != ether_status ||
					sdl->sdl_type == IFT_ETHER) {
					if (need_nl)
						putchar(' ');
					fputs(name, stdout);
					need_nl++;
				}
				continue;
			}
		} else {
			if (strlen(name) != sdl->sdl_nlen)
				continue; /* not same len */
			if (strncmp(name, sdl->sdl_data, sdl->sdl_nlen) != 0)
				continue; /* not same name */
		}

		if (argc > 0)
			ifconfig(argc, argv, afp);
		else
			status(afp, addrcount, sdl, ifm, ifam);

		if (all == 0 && namesonly == 0) {
			foundit++; /* flag it as 'done' */
			break;
		}
	}
	free(buf);

	if (namesonly && need_nl > 0)
		putchar('\n');

	if (all == 0 && namesonly == 0 && foundit == 0)
		errx(1, "interface %s does not exist", name);


	exit (0);
}


int
ifconfig(argc, argv, afp)
	int argc;
	char *const *argv;
	const struct afswtch *afp;
{
	int s;

	if (afp == NULL)
		afp = &afs[0];
	ifr.ifr_addr.sa_family = afp->af_af == AF_LINK ? AF_INET : afp->af_af;
	strncpy(ifr.ifr_name, name, sizeof ifr.ifr_name);

	if ((s = socket(ifr.ifr_addr.sa_family, SOCK_DGRAM, 0)) < 0)
		err(1, "socket");

	while (argc > 0) {
		register const struct cmd *p;

		for (p = cmds; p->c_name; p++)
			if (strcmp(*argv, p->c_name) == 0)
				break;
		if (p->c_name == 0 && setaddr)
			p++;	/* got src, do dst */
		if (p->c_func || p->c_func2) {
			if (p->c_parameter == NEXTARG) {
				if (argv[1] == NULL)
					errx(1, "'%s' requires argument",
					    p->c_name);
				(*p->c_func)(argv[1], 0, s, afp);
				argc--, argv++;
			} else if (p->c_parameter == NEXTARG2) {
				if (argc < 3)
					errx(1, "'%s' requires 2 arguments",
					    p->c_name);
				(*p->c_func2)(argv[1], argv[2], s, afp);
				argc -= 2, argv += 2;
			} else
				(*p->c_func)(*argv, p->c_parameter, s, afp);
		}
		argc--, argv++;
	}
#ifdef INET6
	if (ifr.ifr_addr.sa_family == AF_INET6 && explicit_prefix == 0) {
		/* Aggregatable address architecture defines all prefixes
		   are 64. So, it is convenient to set prefixlen to 64 if
		   it is not specified. */
		setifprefixlen("64", 0, s, afp);
		/* in6_getprefix("64", MASK) if MASK is available here... */
	}
#endif
#ifdef NS
	if (setipdst && ifr.ifr_addr.sa_family == AF_NS) {
		struct nsip_req rq;
		int size = sizeof(rq);

		rq.rq_ns = addreq.ifra_addr;
		rq.rq_ip = addreq.ifra_dstaddr;

		if (setsockopt(s, 0, SO_NSIP_ROUTE, &rq, size) < 0)
			Perror("Encapsulation Routing");
	}
#endif
	if (clearaddr) {
		if (afp->af_ridreq == NULL || afp->af_difaddr == 0) {
			warnx("interface %s cannot change %s addresses!",
			      name, afp->af_name);
			clearaddr = NULL;
		}
	}
	if (clearaddr) {
		int ret;
		strncpy(afp->af_ridreq, name, sizeof ifr.ifr_name);
		if ((ret = ioctl(s, afp->af_difaddr, afp->af_ridreq)) < 0) {
			if (errno == EADDRNOTAVAIL && (doalias >= 0)) {
				/* means no previous address for interface */
			} else
				Perror("ioctl (SIOCDIFADDR)");
		}
	}
	if (newaddr) {
		if (afp->af_addreq == NULL || afp->af_aifaddr == 0) {
			warnx("interface %s cannot change %s addresses!",
			      name, afp->af_name);
			newaddr = NULL;
		}
	}
	if (newaddr && (setaddr || setmask)) {
		strncpy(afp->af_addreq, name, sizeof ifr.ifr_name);
		if (ioctl(s, afp->af_aifaddr, afp->af_addreq) < 0)
			Perror("ioctl (SIOCAIFADDR)");
	}
	close(s);
	return(0);
}
#define RIDADDR 0
#define ADDR	1
#define NMASK	2
#define DSTADDR	3

/*ARGSUSED*/
void
setifaddr(addr, param, s, afp)
	const char *addr;
	int param;
	int s;
	const struct afswtch *afp;
{
	if (*afp->af_getaddr == NULL)
		return;
	/*
	 * Delay the ioctl to set the interface addr until flags are all set.
	 * The address interpretation may depend on the flags,
	 * and the flags may change when the address is set.
	 */
	setaddr++;
	if (doalias == 0 && afp->af_af != AF_LINK)
		clearaddr = 1;
	(*afp->af_getaddr)(addr, (doalias >= 0 ? ADDR : RIDADDR));
}

void
settunnel(src, dst, s, afp)
	const char *src, *dst;
	int s;
	const struct afswtch *afp;
{
	struct addrinfo hints, *srcres, *dstres;
	struct ifaliasreq addreq;
	int ecode;
#ifdef INET6
	struct in6_aliasreq in6_addreq; 
#endif

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = afp->af_af;

	if ((ecode = getaddrinfo(src, NULL, NULL, &srcres)) != 0)
		errx(1, "error in parsing address string: %s",
		    gai_strerror(ecode));

	if ((ecode = getaddrinfo(dst, NULL, NULL, &dstres)) != 0)  
		errx(1, "error in parsing address string: %s",
		    gai_strerror(ecode));

	if (srcres->ai_addr->sa_family != dstres->ai_addr->sa_family)
		errx(1,
		    "source and destination address families do not match");

	switch (srcres->ai_addr->sa_family) {
	case AF_INET:
		memset(&addreq, 0, sizeof(addreq));
		strncpy(addreq.ifra_name, name, IFNAMSIZ);
		memcpy(&addreq.ifra_addr, srcres->ai_addr,
		    srcres->ai_addr->sa_len);
		memcpy(&addreq.ifra_dstaddr, dstres->ai_addr,
		    dstres->ai_addr->sa_len);

		if (ioctl(s, SIOCSIFPHYADDR, &addreq) < 0)
			warn("SIOCSIFPHYADDR");
		break;

#ifdef INET6
	case AF_INET6:
		memset(&in6_addreq, 0, sizeof(in6_addreq));
		strncpy(in6_addreq.ifra_name, name, IFNAMSIZ);
		memcpy(&in6_addreq.ifra_addr, srcres->ai_addr,
		    srcres->ai_addr->sa_len);
		memcpy(&in6_addreq.ifra_dstaddr, dstres->ai_addr,
		    dstres->ai_addr->sa_len);

		if (ioctl(s, SIOCSIFPHYADDR_IN6, &in6_addreq) < 0)
			warn("SIOCSIFPHYADDR_IN6");
		break;
#endif /* INET6 */

	default:
		warn("address family not supported");
	}

	freeaddrinfo(srcres);
	freeaddrinfo(dstres);
}

/* ARGSUSED */
void
deletetunnel(vname, param, s, afp)
	const char *vname;
	int param;
	int s;
	const struct afswtch *afp;
{

	if (ioctl(s, SIOCDIFPHYADDR, &ifr) < 0)
		err(1, "SIOCDIFPHYADDR");
}

void
setifnetmask(addr, dummy, s, afp)
	const char *addr;
	int dummy ;
	int s;
	const struct afswtch *afp;
{
	if (*afp->af_getaddr == NULL)
		return;
	setmask++;
	(*afp->af_getaddr)(addr, NMASK);
}

#ifdef INET6
void
setifprefixlen(addr, dummy, s, afp)
        const char *addr;
	int dummy ;
	int s;
	const struct afswtch *afp;
{
        if (*afp->af_getprefix)
                (*afp->af_getprefix)(addr, NMASK);
	explicit_prefix = 1;
}

void
setip6flags(dummyaddr, flag, dummysoc, afp)
	const char *dummyaddr ;
	int flag;
	int dummysoc ;
	const struct afswtch *afp;
{
	if (afp->af_af != AF_INET6)
		err(1, "address flags can be set only for inet6 addresses");

	if (flag < 0)
		in6_addreq.ifra_flags &= ~(-flag);
	else
		in6_addreq.ifra_flags |= flag;
}

void
setip6pltime(seconds, dummy, s, afp)
    	const char *seconds;
	int dummy ;
	int s;
	const struct afswtch *afp;
{
	setip6lifetime("pltime", seconds, s, afp);
}

void
setip6vltime(seconds, dummy, s, afp)
    	const char *seconds;
	int dummy ;
	int s;
	const struct afswtch *afp;
{
	setip6lifetime("vltime", seconds, s, afp);
}

void
setip6lifetime(cmd, val, s, afp)
	const char *cmd;
	const char *val;
	int s;
	const struct afswtch *afp;
{
	time_t newval, t;
	char *ep;

	t = time(NULL);
	newval = (time_t)strtoul(val, &ep, 0);
	if (val == ep)
		errx(1, "invalid %s", cmd);
	if (afp->af_af != AF_INET6)
		errx(1, "%s not allowed for the AF", cmd);
	if (strcmp(cmd, "vltime") == 0) {
		in6_addreq.ifra_lifetime.ia6t_expire = t + newval;
		in6_addreq.ifra_lifetime.ia6t_vltime = newval;
	} else if (strcmp(cmd, "pltime") == 0) {
		in6_addreq.ifra_lifetime.ia6t_preferred = t + newval;
		in6_addreq.ifra_lifetime.ia6t_pltime = newval;
	}
}
#endif

void
setifbroadaddr(addr, dummy, s, afp)
	const char *addr;
	int dummy ;
	int s;
	const struct afswtch *afp;
{
    if (afp->af_getaddr)
	(*afp->af_getaddr)(addr, DSTADDR);
}

void
setifipdst(addr, dummy, s, afp)
	const char *addr;
	int dummy ;
	int s;
	const struct afswtch *afp;
{
	in_getaddr(addr, DSTADDR);
	setipdst++;
	clearaddr = 0;
	newaddr = 0;
}
#define rqtosa(x) (&(((struct ifreq *)(afp->x))->ifr_addr))

void
notealias(addr, param, s, afp)
	const char *addr;
	int param;
	int s;
	const struct afswtch *afp;
{
	if (setaddr && doalias == 0 && param < 0)
		bcopy((caddr_t)rqtosa(af_addreq),
		      (caddr_t)rqtosa(af_ridreq),
		      rqtosa(af_addreq)->sa_len);
	doalias = param;
	if (param < 0) {
		clearaddr = 1;
		newaddr = 0;
	} else
		clearaddr = 0;
}

/*ARGSUSED*/
void
setifdstaddr(addr, param, s, afp)
	const char *addr;
	int param ;
	int s;
	const struct afswtch *afp;
{
	if (*afp->af_getaddr == NULL)
		return;
	(*afp->af_getaddr)(addr, DSTADDR);
}

/*
 * Note: doing an SIOCIGIFFLAGS scribbles on the union portion
 * of the ifreq structure, which may confuse other parts of ifconfig.
 * Make a private copy so we can avoid that.
 */
void
setifflags(vname, value, s, afp)
	const char *vname;
	int value;
	int s;
	const struct afswtch *afp;
{
	struct ifreq		my_ifr;

	bcopy((char *)&ifr, (char *)&my_ifr, sizeof(struct ifreq));

 	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&my_ifr) < 0) {
 		Perror("ioctl (SIOCGIFFLAGS)");
 		exit(1);
 	}
	strncpy(my_ifr.ifr_name, name, sizeof (my_ifr.ifr_name));
 	flags = my_ifr.ifr_flags;

	if (value < 0) {
		value = -value;
		flags &= ~value;
	} else
		flags |= value;
	my_ifr.ifr_flags = flags;
	if (ioctl(s, SIOCSIFFLAGS, (caddr_t)&my_ifr) < 0)
		Perror(vname);
}

void
setifmetric(val, dummy, s, afp)
	const char *val;
	int dummy ;
	int s;
	const struct afswtch *afp;
{
	strncpy(ifr.ifr_name, name, sizeof (ifr.ifr_name));
	ifr.ifr_metric = atoi(val);
	if (ioctl(s, SIOCSIFMETRIC, (caddr_t)&ifr) < 0)
		warn("ioctl (set metric)");
}

void
setifmtu(val, dummy, s, afp)
	const char *val;
	int dummy ;
	int s;
	const struct afswtch *afp;
{
	strncpy(ifr.ifr_name, name, sizeof (ifr.ifr_name));
	ifr.ifr_mtu = atoi(val);
	if (ioctl(s, SIOCSIFMTU, (caddr_t)&ifr) < 0)
		warn("ioctl (set mtu)");
}

void
setiflladdr(val, dummy, s, afp)
	const char *val;
	int dummy;
	int s;
	const struct afswtch *afp;
{
	struct ether_addr	*ea;

	ea = ether_aton(val);
	if (ea == NULL) {
		warn("malformed link-level address");
		return;
	}
	strncpy(ifr.ifr_name, name, sizeof (ifr.ifr_name));
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
	ifr.ifr_addr.sa_family = AF_LINK;
	bcopy(ea, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);
	if (ioctl(s, SIOCSIFLLADDR, (caddr_t)&ifr) < 0)
		warn("ioctl (set lladdr)");

	return;
}

#define	IFFBITS \
"\020\1UP\2BROADCAST\3DEBUG\4LOOPBACK\5POINTOPOINT\6SMART\7RUNNING" \
"\10NOARP\11PROMISC\12ALLMULTI\13OACTIVE\14SIMPLEX\15LINK0\16LINK1\17LINK2" \
"\20MULTICAST"

/*
 * Print the status of the interface.  If an address family was
 * specified, show it and it only; otherwise, show them all.
 */
void
status(afp, addrcount, sdl, ifm, ifam)
	const struct afswtch *afp;
	int addrcount;
	struct	sockaddr_dl *sdl;
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;
{
	const struct afswtch *p = NULL;
	struct	rt_addrinfo info;
	int allfamilies, s;
	struct ifstat ifs;

	if (afp == NULL) {
		allfamilies = 1;
		afp = &afs[0];
	} else
		allfamilies = 0;

	ifr.ifr_addr.sa_family = afp->af_af == AF_LINK ? AF_INET : afp->af_af;
	strncpy(ifr.ifr_name, name, sizeof ifr.ifr_name);

	if ((s = socket(ifr.ifr_addr.sa_family, SOCK_DGRAM, 0)) < 0)
		err(1, "socket");

	/*
	 * XXX is it we are doing a SIOCGIFMETRIC etc for one family.
	 * is it possible that the metric and mtu can be different for
	 * each family?  If so, we have a format problem, because the
	 * metric and mtu is printed on the global the flags line.
	 */
	if (ioctl(s, SIOCGIFMETRIC, (caddr_t)&ifr) < 0)
		warn("ioctl (SIOCGIFMETRIC)");
	else
		metric = ifr.ifr_metric;

	if (ioctl(s, SIOCGIFMTU, (caddr_t)&ifr) < 0)
		warn("ioctl (SIOCGIFMTU)");
	else
		mtu = ifr.ifr_mtu;

	printf("%s: ", name);
	printb("flags", flags, IFFBITS);
	if (metric)
		printf(" metric %d", metric);
	if (mtu)
		printf(" mtu %d", mtu);
	putchar('\n');

	tunnel_status(s);

	while (addrcount > 0) {
		
		info.rti_addrs = ifam->ifam_addrs;

		/* Expand the compacted addresses */
		rt_xaddrs((char *)(ifam + 1), ifam->ifam_msglen + (char *)ifam,
			  &info);

		if (!allfamilies) {
			if (afp->af_af == info.rti_info[RTAX_IFA]->sa_family) {
				p = afp;
				(*p->af_status)(s, &info);
			}
		} else for (p = afs; p->af_name; p++) {
			if (p->af_af == info.rti_info[RTAX_IFA]->sa_family)
				(*p->af_status)(s, &info);
		}
		addrcount--;
		ifam = (struct ifa_msghdr *)((char *)ifam + ifam->ifam_msglen);
	}
	if (allfamilies || afp->af_status == ether_status)
		ether_status(s, (struct rt_addrinfo *)sdl);
#if USE_IF_MEDIA
	if (allfamilies || afp->af_status == media_status)
		media_status(s, NULL);
#endif
#ifdef USE_VLANS
	if (allfamilies || afp->af_status == vlan_status)
		vlan_status(s, NULL);
#endif
#ifdef USE_IEEE80211
	if (allfamilies || afp->af_status == ieee80211_status)
		ieee80211_status(s, NULL);
#endif
	strncpy(ifs.ifs_name, name, sizeof ifs.ifs_name);
	if (ioctl(s, SIOCGIFSTATUS, &ifs) == 0) 
		printf("%s", ifs.ascii);

	if (!allfamilies && !p && afp->af_status != media_status &&
	    afp->af_status != ether_status
#ifdef USE_VLANS
	    && afp->af_status != vlan_status
#endif
		)
		warnx("%s has no %s interface address!", name, afp->af_name);

	close(s);
	return;
}

void
tunnel_status(s)
	int s;
{
	char psrcaddr[NI_MAXHOST];
	char pdstaddr[NI_MAXHOST];
	u_long srccmd, dstcmd;
	struct ifreq *ifrp;
	const char *ver = "";
#ifdef NI_WITHSCOPEID
	const int niflag = NI_NUMERICHOST | NI_WITHSCOPEID;
#else
	const int niflag = NI_NUMERICHOST;
#endif
#ifdef INET6
	struct in6_ifreq in6_ifr;
	int s6;
#endif /* INET6 */

	psrcaddr[0] = pdstaddr[0] = '\0';

#ifdef INET6
	memset(&in6_ifr, 0, sizeof(in6_ifr));
	strncpy(in6_ifr.ifr_name, name, IFNAMSIZ);
	s6 = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s6 < 0) {
		srccmd = SIOCGIFPSRCADDR;
		dstcmd = SIOCGIFPDSTADDR;
		ifrp = &ifr;
	} else {
		close(s6);
		srccmd = SIOCGIFPSRCADDR_IN6;
		dstcmd = SIOCGIFPDSTADDR_IN6;
		ifrp = (struct ifreq *)&in6_ifr;
	}
#else /* INET6 */
	srccmd = SIOCGIFPSRCADDR;
	dstcmd = SIOCGIFPDSTADDR;
	ifrp = &ifr;
#endif /* INET6 */

	if (ioctl(s, srccmd, (caddr_t)ifrp) < 0)
		return;
#ifdef INET6
	if (ifrp->ifr_addr.sa_family == AF_INET6)
		in6_fillscopeid((struct sockaddr_in6 *)&ifrp->ifr_addr);
#endif
	getnameinfo(&ifrp->ifr_addr, ifrp->ifr_addr.sa_len,
	    psrcaddr, sizeof(psrcaddr), 0, 0, niflag);
#ifdef INET6
	if (ifrp->ifr_addr.sa_family == AF_INET6)
		ver = "6";
#endif

	if (ioctl(s, dstcmd, (caddr_t)ifrp) < 0)
		return;
#ifdef INET6
	if (ifrp->ifr_addr.sa_family == AF_INET6)
		in6_fillscopeid((struct sockaddr_in6 *)&ifrp->ifr_addr);
#endif
	getnameinfo(&ifrp->ifr_addr, ifrp->ifr_addr.sa_len,
	    pdstaddr, sizeof(pdstaddr), 0, 0, niflag);

	printf("\ttunnel inet%s %s --> %s\n", ver,
	    psrcaddr, pdstaddr);
}

void
in_status(s, info)
	int s ;
	struct rt_addrinfo * info;
{
	struct sockaddr_in *sin, null_sin;
	
	memset(&null_sin, 0, sizeof(null_sin));

	sin = (struct sockaddr_in *)info->rti_info[RTAX_IFA];
	printf("\tinet %s ", inet_ntoa(sin->sin_addr));

	if (flags & IFF_POINTOPOINT) {
		/* note RTAX_BRD overlap with IFF_BROADCAST */
		sin = (struct sockaddr_in *)info->rti_info[RTAX_BRD];
		if (!sin)
			sin = &null_sin;
		printf("--> %s ", inet_ntoa(sin->sin_addr));
	}

	sin = (struct sockaddr_in *)info->rti_info[RTAX_NETMASK];
	if (!sin)
		sin = &null_sin;
	printf("netmask 0x%lx ", (unsigned long)ntohl(sin->sin_addr.s_addr));

	if (flags & IFF_BROADCAST) {
		/* note RTAX_BRD overlap with IFF_POINTOPOINT */
		sin = (struct sockaddr_in *)info->rti_info[RTAX_BRD];
		if (sin && sin->sin_addr.s_addr != 0)
			printf("broadcast %s", inet_ntoa(sin->sin_addr));
	}
	putchar('\n');
}

#ifdef INET6
void
in6_fillscopeid(sin6)
	struct sockaddr_in6 *sin6;
{
#if defined(__KAME__) && defined(KAME_SCOPEID)
	if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
		sin6->sin6_scope_id =
			ntohs(*(u_int16_t *)&sin6->sin6_addr.s6_addr[2]);
		sin6->sin6_addr.s6_addr[2] = sin6->sin6_addr.s6_addr[3] = 0;
	}
#endif
}

void
in6_status(s, info)
	int s ;
	struct rt_addrinfo * info;
{
	struct sockaddr_in6 *sin, null_sin;
	struct in6_ifreq ifr6;
	int s6;
	u_int32_t flags6;
	struct in6_addrlifetime lifetime;
	time_t t = time(NULL);
	int error;
	u_int32_t scopeid;

	memset(&null_sin, 0, sizeof(null_sin));

	sin = (struct sockaddr_in6 *)info->rti_info[RTAX_IFA];
	strncpy(ifr6.ifr_name, ifr.ifr_name, sizeof(ifr.ifr_name));
	if ((s6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		perror("ifconfig: socket");
		return;
	}
	ifr6.ifr_addr = *sin;
	if (ioctl(s6, SIOCGIFAFLAG_IN6, &ifr6) < 0) {
		perror("ifconfig: ioctl(SIOCGIFAFLAG_IN6)");
		close(s6);
		return;
	}
	flags6 = ifr6.ifr_ifru.ifru_flags6;
	memset(&lifetime, 0, sizeof(lifetime));
	ifr6.ifr_addr = *sin;
	if (ioctl(s6, SIOCGIFALIFETIME_IN6, &ifr6) < 0) {
		perror("ifconfig: ioctl(SIOCGIFALIFETIME_IN6)");
		close(s6);
		return;
	}
	lifetime = ifr6.ifr_ifru.ifru_lifetime;
	close(s6);

	/* XXX: embedded link local addr check */
	if (IN6_IS_ADDR_LINKLOCAL(&sin->sin6_addr) &&
	    *(u_short *)&sin->sin6_addr.s6_addr[2] != 0) {
		u_short index;

		index = *(u_short *)&sin->sin6_addr.s6_addr[2];
		*(u_short *)&sin->sin6_addr.s6_addr[2] = 0;
		if (sin->sin6_scope_id == 0)
			sin->sin6_scope_id = ntohs(index);
	}
	scopeid = sin->sin6_scope_id;

	error = getnameinfo((struct sockaddr *)sin, sin->sin6_len, addr_buf,
			    sizeof(addr_buf), NULL, 0,
			    NI_NUMERICHOST|NI_WITHSCOPEID);
	if (error != 0)
		inet_ntop(AF_INET6, &sin->sin6_addr, addr_buf,
			  sizeof(addr_buf));
	printf("\tinet6 %s ", addr_buf);

	if (flags & IFF_POINTOPOINT) {
		/* note RTAX_BRD overlap with IFF_BROADCAST */
		sin = (struct sockaddr_in6 *)info->rti_info[RTAX_BRD];
		/*
		 * some of the interfaces do not have valid destination
		 * address.
		 */
		if (sin && sin->sin6_family == AF_INET6) {
			int error;

			/* XXX: embedded link local addr check */
			if (IN6_IS_ADDR_LINKLOCAL(&sin->sin6_addr) &&
			    *(u_short *)&sin->sin6_addr.s6_addr[2] != 0) {
				u_short index;

				index = *(u_short *)&sin->sin6_addr.s6_addr[2];
				*(u_short *)&sin->sin6_addr.s6_addr[2] = 0;
				if (sin->sin6_scope_id == 0)
					sin->sin6_scope_id = ntohs(index);
			}

			error = getnameinfo((struct sockaddr *)sin,
					    sin->sin6_len, addr_buf,
					    sizeof(addr_buf), NULL, 0,
					    NI_NUMERICHOST|NI_WITHSCOPEID);
			if (error != 0)
				inet_ntop(AF_INET6, &sin->sin6_addr, addr_buf,
					  sizeof(addr_buf));
			printf("--> %s ", addr_buf);
		}
	}

	sin = (struct sockaddr_in6 *)info->rti_info[RTAX_NETMASK];
	if (!sin)
		sin = &null_sin;
	printf("prefixlen %d ", prefix(&sin->sin6_addr,
		sizeof(struct in6_addr)));

	if ((flags6 & IN6_IFF_ANYCAST) != 0)
		printf("anycast ");
	if ((flags6 & IN6_IFF_TENTATIVE) != 0)
		printf("tentative ");
	if ((flags6 & IN6_IFF_DUPLICATED) != 0)
		printf("duplicated ");
	if ((flags6 & IN6_IFF_DETACHED) != 0)
		printf("detached ");
	if ((flags6 & IN6_IFF_DEPRECATED) != 0)
		printf("deprecated ");
	if ((flags6 & IN6_IFF_AUTOCONF) != 0)
		printf("autoconf ");
	if ((flags6 & IN6_IFF_TEMPORARY) != 0)
		printf("temporary ");

        if (scopeid)
		printf("scopeid 0x%x ", scopeid);

	if (ip6lifetime && (lifetime.ia6t_preferred || lifetime.ia6t_expire)) {
		printf("pltime ");
		if (lifetime.ia6t_preferred) {
			printf("%s ", lifetime.ia6t_preferred < t
				? "0" : sec2str(lifetime.ia6t_preferred - t));
		} else
			printf("infty ");

		printf("vltime ");
		if (lifetime.ia6t_expire) {
			printf("%s ", lifetime.ia6t_expire < t
				? "0" : sec2str(lifetime.ia6t_expire - t));
		} else
			printf("infty ");
	}

	putchar('\n');
}
#endif /*INET6*/

#ifdef NS
void
xns_status(s, info)
	int s ;
	struct rt_addrinfo * info;
{
	struct sockaddr_ns *sns, null_sns;

	memset(&null_sns, 0, sizeof(null_sns));

	sns = (struct sockaddr_ns *)info->rti_info[RTAX_IFA];
	printf("\tns %s ", ns_ntoa(sns->sns_addr));

	if (flags & IFF_POINTOPOINT) {
		sns = (struct sockaddr_ns *)info->rti_info[RTAX_BRD];
		if (!sns)
			sns = &null_sns;
		printf("--> %s ", ns_ntoa(sns->sns_addr));
	}

	putchar('\n');
	close(s);
}
#endif


void
ether_status(s, info)
	int s ;
	struct rt_addrinfo *info;
{
	char *cp;
	int n;
	struct sockaddr_dl *sdl = (struct sockaddr_dl *)info;

	cp = (char *)LLADDR(sdl);
	if ((n = sdl->sdl_alen) > 0) {
		if (sdl->sdl_type == IFT_ETHER)
			printf ("\tether ");
		else
			printf ("\tlladdr ");
             	while (--n >= 0)
			printf("%02x%c",*cp++ & 0xff, n>0? ':' : ' ');
		putchar('\n');
	}
}

void
Perror(cmd)
	const char *cmd;
{
	switch (errno) {

	case ENXIO:
		errx(1, "%s: no such interface", cmd);
		break;

	case EPERM:
		errx(1, "%s: permission denied", cmd);
		break;

	default:
		err(1, "%s", cmd);
	}
}

#define SIN(x) ((struct sockaddr_in *) &(x))
struct sockaddr_in *sintab[] = {
SIN(ridreq.ifr_addr), SIN(addreq.ifra_addr),
SIN(addreq.ifra_mask), SIN(addreq.ifra_broadaddr)};

void
in_getaddr(s, which)
	const char *s;
	int which;
{
	register struct sockaddr_in *sin = sintab[which];
	struct hostent *hp;
	struct netent *np;

	sin->sin_len = sizeof(*sin);
	if (which != NMASK)
		sin->sin_family = AF_INET;

	if (which == ADDR) {
		char *p = NULL;

		if((p = strrchr(s, '/')) != NULL) {
			/* address is `name/masklen' */
			int masklen;
			int ret;
			struct sockaddr_in *min = sintab[NMASK];
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
}

#ifdef INET6
#define	SIN6(x) ((struct sockaddr_in6 *) &(x))
struct	sockaddr_in6 *sin6tab[] = {
SIN6(in6_ridreq.ifr_addr), SIN6(in6_addreq.ifra_addr),
SIN6(in6_addreq.ifra_prefixmask), SIN6(in6_addreq.ifra_dstaddr)};

void
in6_getaddr(s, which)
	const char *s;
	int which;
{
	register struct sockaddr_in6 *sin = sin6tab[which];
	struct addrinfo hints, *res;
	int error = -1;

	newaddr &= 1;

	sin->sin6_len = sizeof(*sin);
	if (which != NMASK)
		sin->sin6_family = AF_INET6;

	if (which == ADDR) {
		char *p = NULL;
		if((p = strrchr(s, '/')) != NULL) {
			*p = '\0';
			in6_getprefix(p + 1, NMASK);
			explicit_prefix = 1;
		}
	}

	if (sin->sin6_family == AF_INET6) {
		bzero(&hints, sizeof(struct addrinfo));
		hints.ai_family = AF_INET6;
		error = getaddrinfo(s, NULL, &hints, &res);
	}
	if (error != 0) {
		if (inet_pton(AF_INET6, s, &sin->sin6_addr) != 1)
			errx(1, "%s: bad value", s);
	} else
		bcopy(res->ai_addr, sin, res->ai_addrlen);
}

void
in6_getprefix(plen, which)
	const char *plen;
	int which;
{
	register struct sockaddr_in6 *sin = sin6tab[which];
	register u_char *cp;
	int len = atoi(plen);

	if ((len < 0) || (len > 128))
		errx(1, "%s: bad value", plen);
	sin->sin6_len = sizeof(*sin);
	if (which != NMASK)
		sin->sin6_family = AF_INET6;
	if ((len == 0) || (len == 128)) {
		memset(&sin->sin6_addr, 0xff, sizeof(struct in6_addr));
		return;
	}
	memset((void *)&sin->sin6_addr, 0x00, sizeof(sin->sin6_addr));
	for (cp = (u_char *)&sin->sin6_addr; len > 7; len -= 8)
		*cp++ = 0xff;
	*cp = 0xff << (8 - len);
}
#endif

/*
 * Print a value a la the %b format of the kernel's printf
 */
void
printb(s, v, bits)
	const char *s;
	register unsigned v;
	register const char *bits;
{
	register int i, any = 0;
	register char c;

	if (bits && *bits == 8)
		printf("%s=%o", s, v);
	else
		printf("%s=%x", s, v);
	bits++;
	if (bits) {
		putchar('<');
		while ((i = *bits++) != '\0') {
			if (v & (1 << (i-1))) {
				if (any)
					putchar(',');
				any = 1;
				for (; (c = *bits) > 32; bits++)
					putchar(c);
			} else
				for (; *bits > 32; bits++)
					;
		}
		putchar('>');
	}
}

void  
ether_getaddr(addr, which)
        const char *addr;
        int which;
{
        struct ether_addr *ea;
        struct sockaddr *sea = &ridreq.ifr_addr;

        ea = ether_aton(addr);
        if (ea == NULL)
                errx(1, "malformed ether address");
        if (which == NMASK)
                errx(1, "Ethernet does not use netmasks");
        sea->sa_family = AF_LINK;
        sea->sa_len = ETHER_ADDR_LEN;      
        bcopy(ea, sea->sa_data, ETHER_ADDR_LEN);
}

#ifdef INET6     
int
prefix(val, size)
        void *val;
        int size;
{
        register u_char *name = (u_char *)val;
        register int byte, bit, plen = 0;

        for (byte = 0; byte < size; byte++, plen += 8)
                if (name[byte] != 0xff)
                        break;
        if (byte == size)
                return (plen);
        for (bit = 7; bit != 0; bit--, plen++)
                if (!(name[byte] & (1 << bit)))
                        break;
        for (; bit != 0; bit--)
                if (name[byte] & (1 << bit))
                        return(0);
        byte++;
        for (; byte < size; byte++)
                if (name[byte])
                        return(0);
        return (plen);
}

static char *
sec2str(total)
        time_t total;
{
        static char result[256];
        int days, hours, mins, secs;
        int first = 1;
        char *p = result;

        if (0) {
                days = total / 3600 / 24;
                hours = (total / 3600) % 24;
                mins = (total / 60) % 60;
                secs = total % 60;

                if (days) {
                        first = 0;
                        p += sprintf(p, "%dd", days);
                }
                if (!first || hours) {
                        first = 0;
                        p += sprintf(p, "%dh", hours);
                }
                if (!first || mins) {
                        first = 0;
                        p += sprintf(p, "%dm", mins);
                }
                sprintf(p, "%ds", secs);
        } else
                sprintf(result, "%lu", (unsigned long)total);

        return(result);
}
#endif /*INET6*/

void
clone_create(void)
{
	int s;
	
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1)
		err(1, "socket");
	
	memset(&ifr, 0, sizeof(ifr));
	(void) strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCIFCREATE, &ifr) < 0)
		err(1, "SIOCIFCREATE");
	
	if (strcmp(name, ifr.ifr_name) != 0) {
		printf("%s\n", ifr.ifr_name);
		strlcpy(name, ifr.ifr_name, sizeof(name));
	}
	
	close(s);
}

void
clone_destroy(const char *val, int d, int s, const struct afswtch *rafp)
{
	
	(void) strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCIFDESTROY, &ifr) < 0)
		err(1, "SIOCIFDESTROY");
}
