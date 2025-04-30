/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/sockio_private.h>

#include <net/if_mib.h>
#include <net/if_ports_used.h>
#include <net/net_api_stats.h>

#include <netinet/in.h>

#include <err.h>
#include <stdio.h>
#include <strings.h>
#include <sysexits.h>
#include <unistd.h>

#include "netstat.h"

void
print_net_api_stats(uint32_t off __unused, char *name, int af __unused)
{
	static struct net_api_stats pnet_api_stats;
	struct net_api_stats net_api_stats;
	size_t len = sizeof(struct net_api_stats);
	const char *mibvar = "net.api_stats";

	if (sysctlbyname(mibvar, &net_api_stats, &len, 0, 0) < 0) {
		warn("sysctl: %s", mibvar);
		return;
	}

#define	STATDIFF(f) (net_api_stats.f - pnet_api_stats.f)
#define	p(f, m) if (STATDIFF(f) || sflag <= 1) \
	printf(m, STATDIFF(f), plural(STATDIFF(f)))
#define	p1a(f, m) if (STATDIFF(f) || sflag <= 1) \
	printf(m, STATDIFF(f))

	if (interval && vflag > 0)
		print_time();
	printf ("%s:\n", name);

	p(nas_iflt_attach_count, "\t%lld interface filter%s currently attached\n");
#ifdef NAS_HAS_FLTR_OS_COUNTS
	p(nas_iflt_attach_os_count, "\t%lld interface filter%s currently attached by OS\n");
#endif /* NAS_HAS_FLTR_OS_COUNTS */
	p(nas_iflt_attach_total, "\t%lld interface filter%s attached since boot\n");
	p(nas_iflt_attach_os_total, "\t%lld interface filter%s attached since boot by OS\n");

	p(nas_ipf_add_count, "\t%lld IP filter%s currently attached\n");
#ifdef NAS_HAS_FLTR_OS_COUNTS
	p(nas_ipf_add_os_count, "\t%lld interface filter%s currently attached by OS\n");
#endif /* NAS_HAS_FLTR_OS_COUNTS */
	p(nas_ipf_add_total, "\t%lld IP filter%s attached since boot\n");
	p(nas_ipf_add_os_total, "\t%lld IP filter%s attached since boot by OS\n");

	p(nas_sfltr_register_count, "\t%lld socket filter%s currently attached\n");
#ifdef NAS_HAS_FLTR_OS_COUNTS
	p(nas_sfltr_register_os_count, "\t%lld socket filter%s currently attached by OS\n");
#endif /* NAS_HAS_FLTR_OS_COUNTS */
	p(nas_sfltr_register_total, "\t%lld socket filter%s attached since boot\n");
	p(nas_sfltr_register_os_total, "\t%lld socket filter%s attached since boot by OS\n");

	p(nas_socket_alloc_total, "\t%lld socket%s allocated since boot\n");
	p(nas_socket_in_kernel_total, "\t%lld socket%s allocated in-kernel since boot\n");
	p(nas_socket_in_kernel_os_total, "\t%lld socket%s allocated in-kernel by OS\n");
	p(nas_socket_necp_clientuuid_total, "\t%lld socket%s with NECP client UUID since boot\n");

	p(nas_socket_domain_local_total, "\t%lld local domain socket%s allocated since boot\n");
	p(nas_socket_domain_route_total, "\t%lld route domain socket%s allocated since boot\n");
	p(nas_socket_domain_inet_total, "\t%lld inet domain socket%s allocated since boot\n");
	p(nas_socket_domain_inet6_total, "\t%lld inet6 domain socket%s allocated since boot\n");
	p(nas_socket_domain_system_total, "\t%lld system domain socket%s allocated since boot\n");
	p(nas_socket_domain_multipath_total, "\t%lld multipath domain socket%s allocated since boot\n");
	p(nas_socket_domain_key_total, "\t%lld key domain socket%s allocated since boot\n");
	p(nas_socket_domain_ndrv_total, "\t%lld ndrv domain socket%s allocated since boot\n");
	p(nas_socket_domain_other_total, "\t%lld other domains socket%s allocated since boot\n");

	p(nas_socket_inet_stream_total, "\t%lld IPv4 stream socket%s created since boot\n");
	p(nas_socket_inet_dgram_total, "\t%lld IPv4 datagram socket%s created since boot\n");
	p(nas_socket_inet_dgram_connected, "\t%lld IPv4 datagram socket%s connected\n");
	p(nas_socket_inet_dgram_dns, "\t%lld IPv4 DNS socket%s\n");
	p(nas_socket_inet_dgram_no_data, "\t%lld IPv4 datagram socket%s without data\n");

	p(nas_socket_inet6_stream_total, "\t%lld IPv6 stream socket%s created since boot\n");
	p(nas_socket_inet6_dgram_total, "\t%lld IPv6 datagram socket%s created since boot\n");
	p(nas_socket_inet6_dgram_connected, "\t%lld IPv6 datagram socket%s connected\n");
	p(nas_socket_inet6_dgram_dns, "\t%lld IPv6 DNS socket%s\n");
	p(nas_socket_inet6_dgram_no_data, "\t%lld IPv6 datagram socket%s without data\n");

	p(nas_socket_mcast_join_total, "\t%lld socket multicast join%s since boot\n");
	p(nas_socket_mcast_join_os_total, "\t%lld socket multicast join%s since boot by OS\n");

	p(nas_nx_flow_inet_stream_total, "\t%lld IPv4 stream nexus flow%s added since boot\n");
	p(nas_nx_flow_inet_dgram_total, "\t%lld IPv4 datagram nexus flow%s added since boot\n");

	p(nas_nx_flow_inet6_stream_total, "\t%lld IPv6 stream nexus flow%s added since boot\n");
	p(nas_nx_flow_inet6_dgram_total, "\t%lld IPv6 datagram nexus flow%s added since boot\n");

	p(nas_ifnet_alloc_count, "\t%lld interface%s currently allocated\n");
	p(nas_ifnet_alloc_total, "\t%lld interface%s allocated since boot\n");
	p(nas_ifnet_alloc_os_count, "\t%lld interface%s currently allocated by OS\n");
	p(nas_ifnet_alloc_os_total, "\t%lld extended interface%s allocated since boot by OS\n");

	p(nas_pf_addrule_total, "\t%lld PF addrule operation%s since boot\n");
	p(nas_pf_addrule_os, "\t%lld PF addrule operation%s since boot by OS\n");

	p(nas_vmnet_total, "\t%lld vmnet start%s since boot\n");

#undef STATDIFF
#undef p
#undef p1a

	if (interval > 0) {
		bcopy(&net_api_stats, &pnet_api_stats, len);
	}
}

void
print_if_ports_used_stats(uint32_t off __unused, char *name, int af __unused)
{
#ifdef IF_PORTS_USED_STATS_LIST
	static struct if_ports_used_stats pif_ports_used_stats = {};
	struct if_ports_used_stats if_ports_used_stats = {};
	const char *mibvar = "net.link.generic.system.port_used.stats";
	size_t len;

	if (sysctlbyname(mibvar, NULL, &len, 0, 0) < 0) {
		warn("sysctl: %s len: %lu", mibvar, len);
	}
	if (len > sizeof(struct if_ports_used_stats)) {
		len = sizeof(struct if_ports_used_stats);
	}
	if (sysctlbyname(mibvar, &if_ports_used_stats, &len, 0, 0) < 0) {
		warn("sysctl: %s len: %lu", mibvar, len);
		return;
	}

	if (interval && vflag > 0)
		print_time();
	printf ("%s:\n", name);

#define	STATDIFF(_field) (if_ports_used_stats._field - pif_ports_used_stats._field)
#define	p(_field, _description, _singular, _plural) \
if (STATDIFF(_field) != 0 || sflag <= 1) { \
	printf("\t%llu " _description "\n", STATDIFF(_field), STATDIFF(_field) == 0 ? _singular : _plural); \
}

#define X(_type, _field, _description, _singular, _plural, ...) p(_field, _description, _singular, _plural)
	IF_PORTS_USED_STATS_LIST
#undef X

#undef STATDIFF
#undef p

	if (interval > 0) {
		bcopy(&if_ports_used_stats, &pif_ports_used_stats, len);
	}
#endif /* IF_PORTS_USED_STATS_LIST */
}

void
print_if_link_heuristics_stats(char *name)
{
	struct ifreq ifr = { 0 };

	strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

#ifdef SIOCGLINKHEURISTICS
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);

	if (s < 0) {
		err(EX_OSERR, "socket");
	}

	if (ioctl(s, SIOCGLINKHEURISTICS, &ifr) == -1) {
		warn("ioctl SIOCGLINKHEURISTICS");
		return;
	}
	close(s);
	s = -1;
#endif /* SIOCGLINKHEURISTICS */

#ifdef HAS_IF_LINK_HEURISTICS_STATS
	struct if_linkheuristics if_linkheuristics = { 0 };
	size_t miblen = sizeof(struct if_linkheuristics);
	int mib[6];

	/* Common OID prefix */
	mib[0] = CTL_NET;
	mib[1] = PF_LINK;
	mib[2] = NETLINK_GENERIC;
	mib[3] = IFMIB_IFDATA;
	mib[4] = if_nametoindex(name);
	mib[5] = IFDATA_LINKHEURISTICS;
	if (sysctl(mib, 6, &if_linkheuristics, &miblen, (void *)0, 0) == -1) {
		warn("sysctl IFDATA_LINKHEURISTICS");
		return;
	}

	/*
	 * Do not bother to cluter the output if there is nothing to report
	 */
	if (ifr.ifr_intval == 0 &&
		if_linkheuristics.iflh_link_heuristics_cnt == 0 &&
		if_linkheuristics.iflh_congested_link_cnt == 0 &&
		if_linkheuristics.iflh_lqm_good_cnt == 0 &&
		if_linkheuristics.iflh_lqm_poor_cnt == 0 &&
		if_linkheuristics.iflh_lqm_bad_cnt == 0) {
		return;
	}

	printf("link heuristics on %s\n", name);

	printf("\tenabled: %s\n", ifr.ifr_intval ? "true" : "false");

#define	p(f, m) if (if_linkheuristics.f || sflag <= 1) \
    printf(m, if_linkheuristics.f, plural(if_linkheuristics.f))

#define	p1(f, m) if (if_linkheuristics.f || sflag <= 1) \
	printf(m, if_linkheuristics.f / 1000, if_linkheuristics.f % 1000)

	p(iflh_link_heuristics_cnt, "\t%llu time%s link heuristics enabled\n");
	p1(iflh_link_heuristics_time, "\t%llu.%03llu seconds link heuristics enabled\n");

	p(iflh_congested_link_cnt, "\t%llu time%s link congested enabled\n");
	p1(iflh_congested_link_time, "\t%llu.%03llu seconds link congested\n");

	p(iflh_lqm_good_cnt, "\t%llu time%s good link quality enabled\n");
	p1(iflh_lqm_good_time, "\t%llu.%03llu seconds of good link quality\n");

	p(iflh_lqm_poor_cnt, "\t%llu time%s poor link quality enabled\n");
	p1(iflh_lqm_poor_time, "\t%llu.%03llu seconds of poor link quality\n");

	p(iflh_lqm_min_viable_cnt, "\t%llu time%s minimally viable link quality enabled\n");
	p1(iflh_lqm_min_viable_time, "\t%llu.%03llu seconds of minimally viable link quality\n");

	p(iflh_lqm_bad_cnt, "\t%llu time%s bad link quality enabled\n");
	p1(iflh_lqm_bad_time, "\t%llu.%03llu seconds of bad link quality\n");

	p(iflh_tcp_linkheur_stealthdrop, "\t%llu stealth TCP packet%s to closed port\n");

	p(iflh_tcp_linkheur_noackpri, "\t%llu TCP packet%s ACK/SYN no prioritized\n");

	p(iflh_tcp_linkheur_comprxmt, "\t%llu TCP data retransmission%s compressed\n");

	p(iflh_tcp_linkheur_synrxmt, "\t%llu TCP SYN retransmission%s standard backoff\n");

	p(iflh_tcp_linkheur_rxmtfloor, "\t%llu TCP retransmission%s delayed to floor\n");

	p(iflh_udp_linkheur_stealthdrop, "\t%llu stealth UDP packet%s to closed port\n");

#endif /* HAS_IF_LINK_HEURISTICS_STATS */
}
