/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include <rpcsvc/sm_inter.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rpc/pmap_clnt.h>
#include <string.h>
#include <netdb.h>
#include <signal.h>
#include <sys/ttycom.h>
#ifdef __cplusplus
#include <sysent.h>
#endif /* __cplusplus */
#include <memory.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <syslog.h>

#ifdef __STDC__
#define SIG_PF void(*)(int)
#endif

#ifdef DEBUG
#define RPC_SVC_FG
#endif

#define _RPCSVC_CLOSEDOWN 120
#ifndef lint
/*static char sccsid[] = "from: @(#)sm_inter.x 1.7 87/06/24 Copyr 1987 Sun Micro";*/
/*static char sccsid[] = "from: @(#)sm_inter.x	2.2 88/08/01 4.0 RPCSRC";*/
static char rcsid[] = "$Id: sm_inter_svc.c,v 1.2 2002/09/27 05:04:10 lindak Exp $";
#endif /* not lint */

void sm_prog_1(struct svc_req *rqstp, SVCXPRT *transp);

void
sm_prog_1(struct svc_req *rqstp, SVCXPRT *transp)
{
	union {
		struct sm_name sm_stat_1_arg;
		struct mon sm_mon_1_arg;
		struct mon_id sm_unmon_1_arg;
		struct my_id sm_unmon_all_1_arg;
		struct stat_chge sm_notify_1_arg;
	} argument;
	char *result;
	xdrproc_t xdr_argument, xdr_result;
	char *(*local)(char *, struct svc_req *);

	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void) svc_sendreply(transp, (xdrproc_t) xdr_void, (char *)NULL);
		return;

	case SM_STAT:
		xdr_argument = (xdrproc_t) xdr_sm_name;
		xdr_result = (xdrproc_t) xdr_sm_stat_res;
		local = (char *(*)(char *, struct svc_req *)) sm_stat_1_svc;
		break;

	case SM_MON:
		xdr_argument = (xdrproc_t) xdr_mon;
		xdr_result = (xdrproc_t) xdr_sm_stat_res;
		local = (char *(*)(char *, struct svc_req *)) sm_mon_1_svc;
		break;

	case SM_UNMON:
		xdr_argument = (xdrproc_t) xdr_mon_id;
		xdr_result = (xdrproc_t) xdr_sm_stat;
		local = (char *(*)(char *, struct svc_req *)) sm_unmon_1_svc;
		break;

	case SM_UNMON_ALL:
		xdr_argument = (xdrproc_t) xdr_my_id;
		xdr_result = (xdrproc_t) xdr_sm_stat;
		local = (char *(*)(char *, struct svc_req *)) sm_unmon_all_1_svc;
		break;

	case SM_SIMU_CRASH:
		xdr_argument = (xdrproc_t) xdr_void;
		xdr_result = (xdrproc_t) xdr_void;
		local = (char *(*)(char *, struct svc_req *)) sm_simu_crash_1_svc;
		break;

	case SM_NOTIFY:
		xdr_argument = (xdrproc_t) xdr_stat_chge;
		xdr_result = (xdrproc_t) xdr_void;
		local = (char *(*)(char *, struct svc_req *)) sm_notify_1_svc;
		break;

	default:
		svcerr_noproc(transp);
		return;
	}
	(void) memset((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, xdr_argument, (caddr_t) &argument)) {
		svcerr_decode(transp);
		return;
	}
	result = (*local)((char *)&argument, rqstp);
	if (result != NULL && !svc_sendreply(transp, xdr_result, result)) {
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, xdr_argument, (caddr_t) &argument)) {
		syslog(LOG_ERR, "unable to free arguments");
		exit(1);
	}
	return;
}