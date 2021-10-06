/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * "Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.0 (the 'License').  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License."
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1989 Stephen Deering
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Stephen Deering of Stanford University.
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
 *
 *	@(#)mroute.c	8.2 (Berkeley) 4/28/95
 */

/*
 * Print DVMRP multicast routing structures and statistics.
 *
 * MROUTING 1.0
 */

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/mbuf.h>
#include <sys/time.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/igmp.h>
#include <net/route.h>
#include <netinet/ip_mroute.h>

#include <stdio.h>
#include <stdlib.h>
#include "netstat.h"

void
mroutepr(mfcaddr, vifaddr)
	u_long mfcaddr, vifaddr;
{
	u_int mrtproto;
	struct mfc *mfctable[MFCTBLSIZ];
	struct vif viftable[MAXVIFS];
	struct mfc mfc, *m;
	register struct vif *v;
	register vifi_t vifi;
	register int i;
	register int banner_printed;
	register int saved_nflag;
	vifi_t maxvif = 0;

	if (mfcaddr == 0 || vifaddr == 0) {
		printf("No IPv4 multicast routing compiled into this system.\n");
		return;
	}

	saved_nflag = nflag;
	nflag = 1;

	kread(vifaddr, (char *)&viftable, sizeof(viftable));
	banner_printed = 0;
	for (vifi = 0, v = viftable; vifi < MAXVIFS; ++vifi, ++v) {
		if (v->v_lcl_addr.s_addr == 0)
			continue;

		maxvif = vifi;
		if (!banner_printed) {
			printf("\nVirtual Interface Table\n"
			       " Vif   Thresh   Rate   Local-Address   "
			       "Remote-Address    Pkts-In   Pkts-Out\n");
			banner_printed = 1;
		}

		printf(" %2u    %6u   %4d   %-15.15s",
					/* opposite math of add_vif() */
		    vifi, v->v_threshold, v->v_rate_limit * 1000 / 1024, 
		    routename(v->v_lcl_addr.s_addr));
		printf(" %-15.15s", (v->v_flags & VIFF_TUNNEL) ?
		    routename(v->v_rmt_addr.s_addr) : "");

		printf(" %9lu  %9lu\n", v->v_pkt_in, v->v_pkt_out);
	}
	if (!banner_printed)
		printf("\nVirtual Interface Table is empty\n");

	kread(mfcaddr, (char *)&mfctable, sizeof(mfctable));
	banner_printed = 0;
	for (i = 0; i < MFCTBLSIZ; ++i) {
		m = mfctable[i];
		while(m) {
			kread((u_long)m, (char *)&mfc, sizeof mfc);

			if (!banner_printed) {
				printf("\nIPv4 Multicast Forwarding Cache\n"
				       " Origin          Group            "
				       " Packets In-Vif  Out-Vifs:Ttls\n");
				banner_printed = 1;
			}

			printf(" %-15.15s", routename(mfc.mfc_origin.s_addr));
			printf(" %-15.15s", routename(mfc.mfc_mcastgrp.s_addr));
			printf(" %9lu", mfc.mfc_pkt_cnt);
			printf("  %3d   ", mfc.mfc_parent);
			for (vifi = 0; vifi <= maxvif; vifi++) {
				if (mfc.mfc_ttls[vifi] > 0)
					printf(" %u:%u", vifi, 
					       mfc.mfc_ttls[vifi]);
			}
			printf("\n");
			m = mfc.mfc_next;
		}
	}
	if (!banner_printed)
		printf("\nMulticast Routing Table is empty\n");

	printf("\n");
	nflag = saved_nflag;
}


void
mrt_stats(mstaddr)
	u_long mstaddr;
{
	struct mrtstat mrtstat;

	if (mstaddr == 0) {
		printf("No IPv4 multicast routing compiled into this system.\n");
		return;
	}

	kread(mstaddr, (char *)&mrtstat, sizeof(mrtstat));
	printf("IPv4 multicast forwarding:\n");
	printf(" %10lu multicast forwarding cache lookup%s\n",
	  mrtstat.mrts_mfc_lookups, plural(mrtstat.mrts_mfc_lookups));
	printf(" %10lu multicast forwarding cache miss%s\n",
	  mrtstat.mrts_mfc_misses, plurales(mrtstat.mrts_mfc_misses));
	printf(" %10lu upcall%s to mrouted\n",
	  mrtstat.mrts_upcalls, plural(mrtstat.mrts_upcalls));
	printf(" %10lu upcall queue overflow%s\n",
	  mrtstat.mrts_upq_ovflw, plural(mrtstat.mrts_upq_ovflw));
	printf(" %10lu upcall%s dropped due to full socket buffer\n",
	  mrtstat.mrts_upq_sockfull, plural(mrtstat.mrts_upq_sockfull));
	printf(" %10lu cache cleanup%s\n",
	  mrtstat.mrts_cache_cleanups, plural(mrtstat.mrts_cache_cleanups));
	printf(" %10lu datagram%s with no route for origin\n",
	  mrtstat.mrts_no_route, plural(mrtstat.mrts_no_route));
	printf(" %10lu datagram%s arrived with bad tunneling\n",
	  mrtstat.mrts_bad_tunnel, plural(mrtstat.mrts_bad_tunnel));
	printf(" %10lu datagram%s could not be tunneled\n",
	  mrtstat.mrts_cant_tunnel, plural(mrtstat.mrts_cant_tunnel));
	printf(" %10lu datagram%s arrived on wrong interface\n",
	  mrtstat.mrts_wrong_if, plural(mrtstat.mrts_wrong_if));
	printf(" %10lu datagram%s selectively dropped\n",
	  mrtstat.mrts_drop_sel, plural(mrtstat.mrts_drop_sel));
	printf(" %10lu datagram%s dropped due to queue overflow\n",
	  mrtstat.mrts_q_overflow, plural(mrtstat.mrts_q_overflow));
	printf(" %10lu datagram%s dropped for being too large\n",
	  mrtstat.mrts_pkt2large, plural(mrtstat.mrts_pkt2large));
}
