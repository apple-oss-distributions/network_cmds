/*
 * Copyright (c) 1983, 1988, 1993
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
/*
static char sccsid[] = "@(#)if.c	8.3 (Berkeley) 4/28/95";
*/
static const char rcsid[] =
	"$Id: if.c,v 1.6.40.1 2006/01/10 05:26:27 lindak Exp $";
#endif /* not lint */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/time.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_mib.h>
#include <net/ethernet.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>

#ifdef IPX
#include <netipx/ipx.h>
#include <netipx/ipx_if.h>
#endif

#ifdef NS
#include <netns/ns.h>
#include <netns/ns_if.h>
#endif
#include <arpa/inet.h>

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>

#include "netstat.h"

#define	YES	1
#define	NO	0

#define ROUNDUP(a, size) (((a) & ((size) - 1)) ? (1 + ((a)|(size - 1))) : (a))

#define NEXT_SA(p) (struct sockaddr *) \
    ((caddr_t)p + (p->sa_len ? ROUNDUP(p->sa_len, sizeof(u_long)) : \
    sizeof(u_long)))

static void sidewaysintpr ();
static void catchalarm (int);

#ifdef INET6
char *netname6 (struct sockaddr_in6 *, struct sockaddr *);
static char ntop_buf[INET6_ADDRSTRLEN];		/* for inet_ntop() */
#endif

#if 0
#ifdef INET6
static int bdg_done;
#endif

/* print bridge statistics */
void
bdg_stats(u_long dummy , char *name, int af )
{
    int i;
    size_t slen ;
    struct bdg_stats s ;
    int mib[4] ;

    slen = sizeof(s);

    mib[0] = CTL_NET ;
    mib[1] = PF_LINK ;
    mib[2] = IFT_ETHER ;
    if (sysctl(mib,4, &s,&slen,NULL,0)==-1)
	return ; /* no bridging */
#ifdef INET6
    if (bdg_done != 0)
	return;
    else
	bdg_done = 1;
#endif
    printf("-- Bridging statistics (%s) --\n", name) ;
    printf(
"Name          In      Out  Forward     Drop    Bcast    Mcast    Local  Unknown\n");
    for (i = 0 ; i < 16 ; i++) {
	if (s.s[i].name[0])
	printf("%-6s %9ld%9ld%9ld%9ld%9ld%9ld%9ld%9ld\n",
	  s.s[i].name,
	  s.s[i].p_in[(int)BDG_IN],
	  s.s[i].p_in[(int)BDG_OUT],
	  s.s[i].p_in[(int)BDG_FORWARD],
	  s.s[i].p_in[(int)BDG_DROP],
	  s.s[i].p_in[(int)BDG_BCAST],
	  s.s[i].p_in[(int)BDG_MCAST],
	  s.s[i].p_in[(int)BDG_LOCAL],
	  s.s[i].p_in[(int)BDG_UNKNOWN] );
    }
}

#endif


/*
 * Display a formatted value, or a '-' in the same space.
 */
static void
show_stat(const char *fmt, int width, u_int64_t value, short showvalue)
{
	char newfmt[32];

	/* Construct the format string */
	if (showvalue) {
		sprintf(newfmt, "%%%d%s", width, fmt);
		printf(newfmt, value);
	} else {
		sprintf(newfmt, "%%%ds", width);
		printf(newfmt, "-");
	}
}

size_t
get_rti_info(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
    int			i;
    size_t		len = 0;

    for (i = 0; i < RTAX_MAX; i++) {
        if (addrs & (1 << i)) {
            rti_info[i] = sa;
            if (sa->sa_len < sizeof(struct sockaddr))
                len += sizeof(struct sockaddr);
            else
                len += sa->sa_len;
            sa = NEXT_SA(sa);
        } else {
            rti_info[i] = NULL;
        }
    }
    return len;
}

static void
multipr(int family, char *buf, char *lim)
{
    char  *next;

    for (next = buf; next < lim; ) {
		struct ifma_msghdr2	*ifmam = (struct ifma_msghdr2 *)next;
		struct sockaddr *rti_info[RTAX_MAX];
		struct sockaddr *sa;
		const char *fmt = 0;
		
		next += ifmam->ifmam_msglen;
		if (ifmam->ifmam_type == RTM_IFINFO2)
			break;
		else if (ifmam->ifmam_type != RTM_NEWMADDR2)
			continue;
		get_rti_info(ifmam->ifmam_addrs, (struct sockaddr*)(ifmam + 1), rti_info);
		sa = rti_info[RTAX_IFA];
		
		if (sa->sa_family != family)
			continue;
		switch (sa->sa_family) {
			case AF_INET: {
				struct sockaddr_in *sin = (struct sockaddr_in *)sa;
				
				fmt = routename(sin->sin_addr.s_addr);
				break;
			}
	#ifdef INET6
			case AF_INET6: {
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

				printf("%23s %-19.19s(refs: %d)\n", "",
						inet_ntop(AF_INET6,
						&sin6->sin6_addr,
						ntop_buf,
						sizeof(ntop_buf)),
						ifmam->ifmam_refcount);
				break;
			}
	#endif /* INET6 */
			case AF_LINK: {
				struct sockaddr_dl *sdl = (struct sockaddr_dl *)sa;
				
				switch (sdl->sdl_type) {
				case IFT_ETHER:
				case IFT_FDDI:
					fmt = ether_ntoa(
						(struct ether_addr *)
						LLADDR(sdl));
					break;
				}
				break;
			}
		}
		if (fmt)
			printf("%23s %s\n", "", fmt);
	}
}

/*
 * Print a description of the network interfaces.
 */
void
intpr(void (*pfunc)(char *))
{
	u_int64_t opackets = 0;
	u_int64_t ipackets = 0;
	u_int64_t obytes = 0;
	u_int64_t ibytes = 0;
	u_int64_t oerrors = 0;
	u_int64_t ierrors = 0;
	u_int64_t collisions = 0;
	u_long mtu = 0;
	short timer = 0;
	int drops = 0;
	struct sockaddr *sa = NULL;
	char name[32];
	short network_layer;
	short link_layer;
    int mib[6];
    char *buf = NULL, *lim, *next;
	size_t len;
	struct if_msghdr *ifm;
	struct sockaddr *rti_info[RTAX_MAX];
	unsigned int ifindex = 0;
	
	if (interval) {
		sidewaysintpr();
		return;
	}
	
	if (interface != 0)
		ifindex = if_nametoindex(interface);
	
	mib[0]	= CTL_NET;			// networking subsystem
	mib[1]	= PF_ROUTE;			// type of information
	mib[2]	= 0;				// protocol (IPPROTO_xxx)
	mib[3]	= 0;				// address family
	mib[4]	= NET_RT_IFLIST2;	// operation
	mib[5]	= 0;
	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
		return;
	if ((buf = malloc(len)) == NULL) {
		printf("malloc failed\n");
		exit(1);
	}
	if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
		if (buf)
			free(buf);
		return;
	}
	if (!pfunc) {
		printf("%-5.5s %-5.5s %-13.13s %-15.15s %8.8s %5.5s",
		       "Name", "Mtu", "Network", "Address", "Ipkts", "Ierrs");
		if (bflag)
			printf(" %10.10s","Ibytes");
		printf(" %8.8s %5.5s", "Opkts", "Oerrs");
		if (bflag)
			printf(" %10.10s","Obytes");
		printf(" %5s", "Coll");
		if (tflag)
			printf(" %s", "Time");
		if (dflag)
			printf(" %s", "Drop");
		putchar('\n');
	}
    lim = buf + len;
    for (next = buf; next < lim; ) {
		char *cp;
		int n, m;
		
		network_layer = 0;
		link_layer = 0;
        ifm = (struct if_msghdr *)next;
		next += ifm->ifm_msglen;

        if (ifm->ifm_type == RTM_IFINFO2) {
			struct if_msghdr2 *if2m = (struct if_msghdr2 *)ifm;
            struct sockaddr_dl	*sdl = (struct sockaddr_dl *)(if2m + 1);

			strncpy(name, sdl->sdl_data, sdl->sdl_nlen);
			name[sdl->sdl_nlen] = 0;
			if (interface != 0 && if2m->ifm_index != ifindex)
				continue;
			cp = index(name, '\0');

			if (pfunc) {
				(*pfunc)(name);
				continue;
			}

			if ((if2m->ifm_flags & IFF_UP) == 0)
				*cp++ = '*';
			*cp = '\0';

			/*
			 * Get the interface stats.  These may get
			 * overriden below on a per-interface basis.
			 */
			opackets = if2m->ifm_data.ifi_opackets;
			ipackets = if2m->ifm_data.ifi_ipackets;
			obytes = if2m->ifm_data.ifi_obytes;
			ibytes = if2m->ifm_data.ifi_ibytes;
			oerrors =if2m->ifm_data.ifi_oerrors;
			ierrors = if2m->ifm_data.ifi_ierrors;
			collisions = if2m->ifm_data.ifi_collisions;
			timer = if2m->ifm_timer;
			drops = if2m->ifm_snd_drops;
			mtu = if2m->ifm_data.ifi_mtu;

            get_rti_info(if2m->ifm_addrs, (struct sockaddr*)(if2m + 1), rti_info);
			sa = rti_info[RTAX_IFP];
        } else if (ifm->ifm_type == RTM_NEWADDR) {
            struct ifa_msghdr	*ifam = (struct ifa_msghdr *)ifm;
			
			if (interface != 0 && ifam->ifam_index != ifindex)
				continue;
            get_rti_info(ifam->ifam_addrs, (struct sockaddr*)(ifam + 1), rti_info);
			sa = rti_info[RTAX_IFA];
		} else
			continue;
		printf("%-5.5s %-5lu ", name, mtu);

		if (sa == 0) {
			printf("%-13.13s ", "none");
			printf("%-15.15s ", "none");
		} else {
			switch (sa->sa_family) {
			case AF_UNSPEC:
				printf("%-13.13s ", "none");
				printf("%-15.15s ", "none");
				break;
			case AF_INET: {
				struct sockaddr_in *sin = (struct sockaddr_in *)sa;
				struct sockaddr_in mask;
				
				mask.sin_addr.s_addr = 0;
				memcpy(&mask, rti_info[RTAX_NETMASK], ((struct sockaddr_in *)rti_info[RTAX_NETMASK])->sin_len);
				
				printf("%-13.13s ", netname(sin->sin_addr.s_addr & mask.sin_addr.s_addr,
				    ntohl(mask.sin_addr.s_addr)));

				printf("%-15.15s ",
				    routename(sin->sin_addr.s_addr));

				network_layer = 1;
				break;
			}
#ifdef INET6
			case AF_INET6: {
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
				struct sockaddr *mask = (struct sockaddr *)rti_info[RTAX_NETMASK];

				printf("%-11.11s ",
				       netname6(sin6,
						mask));
				printf("%-17.17s ",
				    (char *)inet_ntop(AF_INET6,
					&sin6->sin6_addr,
					ntop_buf, sizeof(ntop_buf)));

				network_layer = 1;
				break;
			}
#endif /*INET6*/
			case AF_LINK:
				{
				struct sockaddr_dl *sdl =
					(struct sockaddr_dl *)sa;
				char linknum[10];
				cp = (char *)LLADDR(sdl);
				n = sdl->sdl_alen;
				sprintf(linknum, "<Link#%d>", sdl->sdl_index);
				m = printf("%-11.11s ", linknum);
				}
				goto hexprint;
			default:
				m = printf("(%d)", sa->sa_family);
				for (cp = sa->sa_len + (char *)sa;
					--cp > sa->sa_data && (*cp == 0);) {}
				n = cp - sa->sa_data + 1;
				cp = sa->sa_data;
			hexprint:
				while (--n >= 0)
					m += printf("%02x%c", *cp++ & 0xff,
						    n > 0 ? ':' : ' ');
				m = 30 - m;
				while (m-- > 0)
					putchar(' ');

				link_layer = 1;
				break;
			}
#ifndef __APPLE__
			/*
			 * Fixup the statistics for interfaces that
			 * update stats for their network addresses
			 */
			if (network_layer) {
				opackets = ifaddr.in.ia_ifa.if_opackets;
				ipackets = ifaddr.in.ia_ifa.if_ipackets;
				obytes = ifaddr.in.ia_ifa.if_obytes;
				ibytes = ifaddr.in.ia_ifa.if_ibytes;
			}
#endif
		}

		show_stat("llu", 8, ipackets, link_layer|network_layer);
		printf(" ");
		show_stat("llu", 5, ierrors, link_layer);
		printf(" ");
		if (bflag) {
			show_stat("llu", 10, ibytes, link_layer|network_layer);
			printf(" ");
		}
		show_stat("llu", 8, opackets, link_layer|network_layer);
		printf(" ");
		show_stat("llu", 5, oerrors, link_layer);
		printf(" ");
		if (bflag) {
			show_stat("llu", 10, obytes, link_layer|network_layer);
			printf(" ");
		}
		show_stat("llu", 5, collisions, link_layer);
		if (tflag) {
			printf(" ");
			show_stat("ll", 3, timer, link_layer);
		}
		if (dflag) {
			printf(" ");
			show_stat("ll", 3, drops, link_layer);
		}
		putchar('\n');

		if (aflag) 
			multipr(sa->sa_family, next, lim);
	}
}

struct	iftot {
	SLIST_ENTRY(iftot) chain;
	char		ift_name[16];	/* interface name */
	u_int64_t	ift_ip;			/* input packets */
	u_int64_t	ift_ie;			/* input errors */
	u_int64_t	ift_op;			/* output packets */
	u_int64_t	ift_oe;			/* output errors */
	u_int64_t	ift_co;			/* collisions */
	u_int64_t	ift_dr;			/* drops */
	u_int64_t	ift_ib;			/* input bytes */
	u_int64_t	ift_ob;			/* output bytes */
};

u_char	signalled;			/* set if alarm goes off "early" */

/*
 * Print a running summary of interface statistics.
 * Repeat display every interval seconds, showing statistics
 * collected over that interval.  Assumes that interval is non-zero.
 * First line printed at top of screen is always cumulative.
 * XXX - should be rewritten to use ifmib(4).
 */
static void
sidewaysintpr()
{
	struct iftot *total, *sum, *interesting;
	register int line;
	int oldmask, first;
	int name[6];
	size_t len;
	unsigned int ifcount, i;
	struct ifmibdata *ifmdall = 0;
	int interesting_row;

	/* Common OID prefix */
	name[0] = CTL_NET;
	name[1] = PF_LINK;
	name[2] = NETLINK_GENERIC;

	len = sizeof(int);
	name[3] = IFMIB_SYSTEM;
	name[4] = IFMIB_IFCOUNT;
	if (sysctl(name, 5, &ifcount, &len, 0, 0) == 1)
		err(1, "sysctl IFMIB_IFCOUNT");

	len = ifcount * sizeof(struct ifmibdata);
	ifmdall = malloc(len);
	if (ifmdall == 0)
		err(1, "malloc failed");
	name[3] = IFMIB_IFALLDATA;
	name[4] = 0;
	name[5] = IFDATA_GENERAL;
	if (sysctl(name, 6, ifmdall, &len, (void *)0, 0) == -1)
		err(1, "sysctl IFMIB_IFALLDATA");
	
	interesting = NULL;
	interesting_row = 0;
	for (i = 0; i < ifcount; i++) {
		struct ifmibdata *ifmd = ifmdall + i;
	
		if (interface && strcmp(ifmd->ifmd_name, interface) == 0) {
			if ((interesting = calloc(ifcount, sizeof(struct iftot))) == NULL)
				err(1, "malloc failed");
			interesting_row = i + 1;
			snprintf(interesting->ift_name, 16, "(%s)", ifmd->ifmd_name);;
		}
	}
	if ((total = calloc(1, sizeof(struct iftot))) == NULL)
		err(1, "malloc failed");

	if ((sum = calloc(1, sizeof(struct iftot))) == NULL)
		err(1, "malloc failed");


	(void)signal(SIGALRM, catchalarm);
	signalled = NO;
	(void)alarm(interval);
	first = 1;
banner:
	printf("%17s %14s %16s", "input",
	    interesting ? interesting->ift_name : "(Total)", "output");
	putchar('\n');
	printf("%10s %5s %10s %10s %5s %10s %5s",
	    "packets", "errs", "bytes", "packets", "errs", "bytes", "colls");
	if (dflag)
		printf(" %5.5s", "drops");
	putchar('\n');
	fflush(stdout);
	line = 0;
loop:
	if (interesting != NULL) {
		struct ifmibdata ifmd;
		
		len = sizeof(struct ifmibdata);
		name[3] = IFMIB_IFDATA;
		name[4] = interesting_row;
		name[5] = IFDATA_GENERAL;
		if (sysctl(name, 6, &ifmd, &len, (void *)0, 0) == -1)
			err(1, "sysctl IFDATA_GENERAL %d", interesting_row);

		if (!first) {
			printf("%10llu %5llu %10llu %10llu %5llu %10llu %5llu",
				ifmd.ifmd_data.ifi_ipackets - interesting->ift_ip,
				ifmd.ifmd_data.ifi_ierrors - interesting->ift_ie,
				ifmd.ifmd_data.ifi_ibytes - interesting->ift_ib,
				ifmd.ifmd_data.ifi_opackets - interesting->ift_op,
				ifmd.ifmd_data.ifi_oerrors - interesting->ift_oe,
				ifmd.ifmd_data.ifi_obytes - interesting->ift_ob,
				ifmd.ifmd_data.ifi_collisions - interesting->ift_co);
			if (dflag)
				printf(" %5llu", ifmd.ifmd_snd_drops - interesting->ift_dr);
		}
		interesting->ift_ip = ifmd.ifmd_data.ifi_ipackets;
		interesting->ift_ie = ifmd.ifmd_data.ifi_ierrors;
		interesting->ift_ib = ifmd.ifmd_data.ifi_ibytes;
		interesting->ift_op = ifmd.ifmd_data.ifi_opackets;
		interesting->ift_oe = ifmd.ifmd_data.ifi_oerrors;
		interesting->ift_ob = ifmd.ifmd_data.ifi_obytes;
		interesting->ift_co = ifmd.ifmd_data.ifi_collisions;
		interesting->ift_dr = ifmd.ifmd_snd_drops;
	} else {
		unsigned int latest_ifcount;
		
		len = sizeof(int);
		name[3] = IFMIB_SYSTEM;
		name[4] = IFMIB_IFCOUNT;
		if (sysctl(name, 5, &latest_ifcount, &len, 0, 0) == 1)
			err(1, "sysctl IFMIB_IFCOUNT");
		if (latest_ifcount > ifcount) {
			ifcount = latest_ifcount;
			len = ifcount * sizeof(struct ifmibdata);
			free(ifmdall);
			ifmdall = malloc(len);
			if (ifmdall == 0)
				err(1, "malloc failed");
		} else if (latest_ifcount > ifcount) {
			ifcount = latest_ifcount;
			len = ifcount * sizeof(struct ifmibdata);
		}
		len = ifcount * sizeof(struct ifmibdata);
		name[3] = IFMIB_IFALLDATA;
		name[4] = 0;
		name[5] = IFDATA_GENERAL;
		if (sysctl(name, 6, ifmdall, &len, (void *)0, 0) == -1)
			err(1, "sysctl IFMIB_IFALLDATA");
			
		sum->ift_ip = 0;
		sum->ift_ie = 0;
		sum->ift_ib = 0;
		sum->ift_op = 0;
		sum->ift_oe = 0;
		sum->ift_ob = 0;
		sum->ift_co = 0;
		sum->ift_dr = 0;
		for (i = 0; i < ifcount; i++) {
			struct ifmibdata *ifmd = ifmdall + i;
			
			sum->ift_ip += ifmd->ifmd_data.ifi_ipackets;
			sum->ift_ie += ifmd->ifmd_data.ifi_ierrors;
			sum->ift_ib += ifmd->ifmd_data.ifi_ibytes;
			sum->ift_op += ifmd->ifmd_data.ifi_opackets;
			sum->ift_oe += ifmd->ifmd_data.ifi_oerrors;
			sum->ift_ob += ifmd->ifmd_data.ifi_obytes;
			sum->ift_co += ifmd->ifmd_data.ifi_collisions;
			sum->ift_dr += ifmd->ifmd_snd_drops;
		}
		if (!first) {
			printf("%10llu %5llu %10llu %10llu %5llu %10llu %5llu",
				sum->ift_ip - total->ift_ip,
				sum->ift_ie - total->ift_ie,
				sum->ift_ib - total->ift_ib,
				sum->ift_op - total->ift_op,
				sum->ift_oe - total->ift_oe,
				sum->ift_ob - total->ift_ob,
				sum->ift_co - total->ift_co);
			if (dflag)
				printf(" %5llu", sum->ift_dr - total->ift_dr);
		}
		*total = *sum;
	}
	if (!first)
		putchar('\n');
	fflush(stdout);
	oldmask = sigblock(sigmask(SIGALRM));
	if (! signalled) {
		sigpause(0);
	}
	sigsetmask(oldmask);
	signalled = NO;
	(void)alarm(interval);
	line++;
	first = 0;
	if (line == 21)
		goto banner;
	else
		goto loop;
	/*NOTREACHED*/
}

/*
 * Called if an interval expires before sidewaysintpr has completed a loop.
 * Sets a flag to not wait for the alarm.
 */
static void
catchalarm(int signo )
{
	signalled = YES;
}
