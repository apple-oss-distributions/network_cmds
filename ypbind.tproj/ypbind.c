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
 * Copyright (c) 1992, 1993 Theo de Raadt <deraadt@fsa.ca>
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Theo de Raadt.
 * 4. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef LINT
static char rcsid[] = "$Id: ypbind.c,v 1.1.1.1 1999/05/02 03:59:00 wsanchez Exp $";
#endif
#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/uio.h>
#include <syslog.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <netdb.h>
#include <string.h>
#include <err.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <rpc/pmap_clnt.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_rmt.h>
#include <unistd.h>
#include <rpcsvc/yp.h>
// #include <rpcsvc/yp_prot.h>
// #include <rpcsvc/ypclnt.h>

#define _PATH_YPBIND_LOCK "/var/run/ypbind.lock"
#define YPSERVERSSUFF	".ypservers"
#define BINDINGDIR	"/var/yp/binding"

#ifndef O_SHLOCK
#define O_SHLOCK 0
#endif

#define BUFSIZE		1400

struct _dom_binding
{
	struct _dom_binding *dom_pnext;
	char dom_domain[YPMAXDOMAIN + 1];
	struct sockaddr_in dom_server_addr;
	unsigned short int dom_server_port;
	int dom_socket;
	CLIENT *dom_client;
	long dom_vers;
	time_t dom_check_t;
	time_t dom_ask_t;
	int dom_lockfd;
	int dom_alive;
	u_int32_t dom_xid;
};

static char *dname;

static struct _dom_binding *ypbindlist;
static int check;

typedef enum
{
	YPBIND_DIRECT,
	YPBIND_BROADCAST,
	YPBIND_SETLOCAL,
	YPBIND_SETALL
} ypbind_mode_t;

ypbind_mode_t ypbindmode;

/*
 * If ypbindmode is YPBIND_SETLOCAL or YPBIND_SETALL, this indicates
 * whether or not we've been "ypset".  If we haven't, we behave like
 * YPBIND_BROADCAST.  If we have, we behave like YPBIND_DIRECT.
 */
int been_ypset;

static int insecure;
static int rpcsock, pingsock;
static struct rmtcallargs rmtca;
static struct rmtcallres rmtcr;
static bool_t rmtcr_outval;
static u_long rmtcr_port;
static SVCXPRT *udptransp, *tcptransp;

int	main __P((int, char *[]));

static void usage __P((void));
static struct _dom_binding *makebinding __P((const char *));
static int makelock __P((struct _dom_binding *));
static void removelock __P((struct _dom_binding *));
static void checkwork __P((void));
static int ping __P((struct _dom_binding *));
static int nag_servers __P((struct _dom_binding *));
static enum clnt_stat handle_replies __P((void));
static enum clnt_stat handle_ping __P((void));
static void rpc_received __P((char *, struct sockaddr_in *, int));
static struct _dom_binding *xid2ypdb __P((u_int32_t));
static u_int32_t unique_xid __P((struct _dom_binding *));
static int broadcast __P((char *, int));
static int direct __P((char *, int));
static int direct_set __P((char *, int, struct _dom_binding *));

#define DEBUG_NONE 0
#define DEBUG_STDERR 1
#define DEBUG_SYSLOG 2

static int debug;
static char *msg_str = NULL;

void
sys_openlog(int debug, char *str, int flags, int facility)
{
	if (msg_str != NULL) free(msg_str);
	msg_str = NULL;
	if (str != NULL)
	{
		msg_str = malloc(strlen(str) + 1);
		strcpy(msg_str, str);
	}

	if (debug & DEBUG_SYSLOG) openlog(msg_str, flags, facility);
}

void
sys_msg(int debug, int priority, char *message, ...)
{
	va_list ap;

	va_start(ap, message);

	if (debug & DEBUG_SYSLOG) vsyslog(priority, message, ap);

	if (debug & DEBUG_STDERR)
	{
		if (msg_str != NULL) fprintf(stderr, "%s: ", msg_str);
		vfprintf(stderr, message, ap);
		fprintf(stderr, "\n");
		fflush(stderr);
	}

	va_end(ap);
}

static void
usage()
{
	fprintf(stderr,
	    "Usage: ypbind [-broadcast] [-insecure] [-ypset] [-ypsetme] [-d]\n");
	exit(1);
}
	
static struct _dom_binding *
makebinding(const char *dm)
{
	struct _dom_binding *ypdb;

	ypdb = (struct _dom_binding *)malloc(sizeof *ypdb);
	memset(ypdb, 0, sizeof *ypdb);
	strncpy(ypdb->dom_domain, dm, sizeof ypdb->dom_domain);
	ypdb->dom_domain[sizeof(ypdb->dom_domain) - 1] = '\0';

	return ypdb;
}

static int
makelock(struct _dom_binding *ypdb)
{
	int fd;
	char path[MAXPATHLEN];

	snprintf(path, sizeof(path), "%s/%s.%ld", BINDINGDIR,
	    ypdb->dom_domain, ypdb->dom_vers);

	fd = open(path, O_CREAT|O_SHLOCK|O_RDWR|O_TRUNC, 0644);
	if (fd == -1)
	{
		mkdir(BINDINGDIR, 0755);
		fd = open(path, O_CREAT|O_SHLOCK|O_RDWR|O_TRUNC, 0644);
		if (fd == -1) return -1;
	}

#if O_SHLOCK == 0
	flock(fd, LOCK_SH);
#endif
	return fd;
}

static void
removelock(struct _dom_binding *ypdb)
{
	char path[MAXPATHLEN];

	snprintf(path, sizeof(path), "%s/%s.%ld",
	    BINDINGDIR, ypdb->dom_domain, ypdb->dom_vers);
	unlink(path);
}

static void *
svc_ypbindproc_null_2(void *argp, SVCXPRT *transp)
{
	static char res;

	sys_msg(debug, LOG_DEBUG, "ypbindproc_null_2");

	memset(&res, 0, sizeof(res));
	return (void *)&res;
}

static void *
svc_ypbindproc_domain_2(void *argp, SVCXPRT *transp)
{
	static struct ypbind_resp res;
	struct _dom_binding *ypdb;
	char *arg = *(char **) argp;
	int count;

	sys_msg(debug, LOG_DEBUG, "ypbindproc_domain_2 %s", arg);

	memset(&res, 0, sizeof res);
	res.ypbind_status = YPBIND_FAIL_VAL;

	for (count = 0, ypdb = ypbindlist;
		ypdb != NULL;
		ypdb = ypdb->dom_pnext, count++)
	{
		/* prevent denial of service */
		if (count > 100) return NULL;
		if (!strcmp(ypdb->dom_domain, arg)) break;
	}

	if (ypdb == NULL)
	{
		ypdb = makebinding(arg);
		ypdb->dom_vers = YPVERS;
		ypdb->dom_alive = 0;
		ypdb->dom_lockfd = -1;
		removelock(ypdb);
		ypdb->dom_xid = unique_xid(ypdb);
		ypdb->dom_pnext = ypbindlist;
		ypbindlist = ypdb;
		check++;
		sys_msg(debug, LOG_ERR, "unknown domain %s", arg);
		return NULL;
	}

	if (ypdb->dom_alive == 0)
	{
		sys_msg(debug, LOG_ERR, "dead domain %s", arg);
		return NULL;
	}

#ifdef HEURISTIC
	time(&now);
	if (now < ypdb->dom_ask_t + 5)
	{
		/*
		 * Hmm. More than 2 requests in 5 seconds have indicated
		 * that my binding is possibly incorrect.
		 * Ok, do an immediate poll of the server.
		 */
		if (ypdb->dom_check_t >= now)
		{
			/* don't flood it */
			ypdb->dom_check_t = 0;
			check++;
		}
	}
	ypdb->dom_ask_t = now;
#endif

	res.ypbind_status = YPBIND_SUCC_VAL;
	bcopy(&ypdb->dom_server_addr.sin_addr.s_addr,
		res.ypbind_resp_u.ypbind_bindinfo.ypbind_binding_addr, 4);
	bcopy(&ypdb->dom_server_port,
		res.ypbind_resp_u.ypbind_bindinfo.ypbind_binding_port, 2);

	sys_msg(debug, LOG_DEBUG, "domain %s at %s/%d", ypdb->dom_domain,
		    inet_ntoa(ypdb->dom_server_addr.sin_addr),
		    ntohs(ypdb->dom_server_addr.sin_port));
	return &res;
}

static void *
svc_ypbindproc_setdom_2(void *argp, SVCXPRT *transp)
{
	struct ypbind_setdom *sd = argp;
	struct sockaddr_in *fromsin, bindsin;
	static bool_t res;

	memset(&bindsin, 0, sizeof bindsin);
	bindsin.sin_family = AF_INET;
	bindsin.sin_len = sizeof(bindsin);
	bcopy(&sd->ypsetdom_binding.ypbind_binding_addr,
		&bindsin.sin_addr.s_addr, 4);
	bcopy(&sd->ypsetdom_binding.ypbind_binding_port,
		&bindsin.sin_port, 2);
	fromsin = svc_getcaller(transp);

	memset(&res, 0, sizeof(res));

	switch (ypbindmode)
	{
		case YPBIND_SETLOCAL:
			if (fromsin->sin_addr.s_addr != htonl(INADDR_LOOPBACK))
			{
				sys_msg(debug, LOG_ERR, "ypset from %s denied",
					inet_ntoa(fromsin->sin_addr));
				return NULL;
			}

		/* FALLTHROUGH */

		case YPBIND_SETALL:
			been_ypset = 1;
			break;

		case YPBIND_DIRECT:
		case YPBIND_BROADCAST:
		default:
			sys_msg(debug, LOG_ERR, "ypset denied");
			return NULL;
	}

	if (ntohs(fromsin->sin_port) >= IPPORT_RESERVED)
	{
		sys_msg(debug, LOG_ERR, "ypset from unpriviledged port denied");
		return &res;
	}

	if (sd->ypsetdom_vers != YPVERS)
	{
		sys_msg(debug, LOG_ERR, "ypset with wrong version denied");
		sys_msg(debug, LOG_DEBUG, "ypsetdom_vers = %lu   YPVERS = %lu",
			sd->ypsetdom_vers, YPVERS);
		return &res;
	}

	rpc_received(sd->ypsetdom_domain, &bindsin, 1);

	sys_msg(debug, LOG_DEBUG, "ypset to %s succeeded",
		inet_ntoa(bindsin.sin_addr));
	res = 1;
	return &res;
}

static void
ypbindprog_2(struct svc_req *rqstp,	register SVCXPRT *transp)
{
	union
	{
		char ypbindproc_domain_2_arg[YPMAXDOMAIN + 1];
		struct ypbind_setdom ypbindproc_setdom_2_arg;
	} argument;
	struct authunix_parms *creds;
	char *result;
	xdrproc_t xdr_argument, xdr_result;
	void *(*local) __P((void *, SVCXPRT *));

	switch (rqstp->rq_proc)
	{
		case YPBINDPROC_NULL:
			xdr_argument = xdr_void;
			xdr_result = xdr_void;
			local = svc_ypbindproc_null_2;
			break;

		case YPBINDPROC_DOMAIN:
			xdr_argument = xdr_domainname;
			xdr_result = xdr_ypbind_resp;
			local = svc_ypbindproc_domain_2;
			break;

		case YPBINDPROC_SETDOM:
			switch (rqstp->rq_cred.oa_flavor)
			{
				case AUTH_UNIX:
					creds = (struct authunix_parms *)rqstp->rq_clntcred;
					if (creds->aup_uid != 0)
					{
						svcerr_auth(transp, AUTH_BADCRED);
						return;
					}
					break;

				default:
					svcerr_auth(transp, AUTH_TOOWEAK);
					return;
			}

			xdr_argument = xdr_ypbind_setdom;
			xdr_result = xdr_void;
			local = svc_ypbindproc_setdom_2;
			break;

		default:
			svcerr_noproc(transp);
			return;
	}
		
	memset(&argument, 0, sizeof(argument));
	if (!svc_getargs(transp, xdr_argument, (caddr_t)&argument))
	{
		svcerr_decode(transp);
		return;
	}
	
	result = (*local)(&argument, transp);
	if (result != NULL && !svc_sendreply(transp, xdr_result, result))
	{
		svcerr_systemerr(transp);
	}

	return;
}

int
main(int argc, char *argv[])
{
	struct timeval tv;
	fd_set fdsr;
	int width, lockfd;
	int evil = 0, one, i;
	char pathname[MAXPATHLEN];
	struct stat st;

	yp_get_default_domain(&dname);
	if (dname[0] == '\0')
	{
		fprintf(stderr, "Domainname not set. Aborting.\n");
		exit(1);
	}

	debug = DEBUG_SYSLOG;
	ypbindmode = YPBIND_DIRECT;
	for (i = 1; i < argc; i++)
	{
		if (!strcmp(argv[i], "-insecure"))
			insecure = 1;

		else if (!strcmp(argv[i], "-ypset"))
			ypbindmode = YPBIND_SETALL;

		else if (!strcmp(argv[i], "-ypsetme"))
			ypbindmode = YPBIND_SETLOCAL;

		else if (!strcmp(argv[i], "-broadcast"))
			ypbindmode = YPBIND_BROADCAST;

		else if (!strcmp(argv[i], "-d"))
			debug = DEBUG_STDERR;

		else
			usage();
	}

	sys_openlog(debug, "ypbind", LOG_NDELAY | LOG_PID, LOG_DAEMON);

	/*
	 * Per traditional ypbind(8) semantics, if a ypservers
	 * file does not exist, we default to broadcast mode.
	 * If the file does exist, we default to direct mode.
	 * Note that we can still override direct mode by passing
	 * the -broadcast flag.
	 */
	snprintf(pathname, sizeof(pathname), "%s/%s%s",
		BINDINGDIR, dname, YPSERVERSSUFF);
		
	if ((ypbindmode == YPBIND_DIRECT) && (stat(pathname, &st) < 0))
	{
		sys_msg(debug, LOG_DEBUG, "%s does not exist, defaulting to broadcast.",
			pathname);
		ypbindmode = YPBIND_BROADCAST;
	}
	
	/* blow away everything in BINDINGDIR */

	lockfd = open(_PATH_YPBIND_LOCK, O_CREAT|O_SHLOCK|O_RDWR|O_TRUNC, 0644);
	if (lockfd == -1)
	{
		sys_msg(debug, LOG_ERR, "Cannot create %s", _PATH_YPBIND_LOCK);
		exit(1);
	}

#if O_SHLOCK == 0
	flock(lockfd, LOCK_SH);
#endif

	pmap_unset(YPBINDPROG, YPBINDVERS);

	udptransp = svcudp_create(RPC_ANYSOCK);
	if (udptransp == NULL)
	{
		sys_msg(debug, LOG_ERR, "Cannot create udp service.");
		exit(1);
	}

	if (!svc_register(udptransp, YPBINDPROG, YPBINDVERS, ypbindprog_2,
	    IPPROTO_UDP))
	{
		sys_msg(debug, LOG_ERR,
			"Unable to register (YPBINDPROG, YPBINDVERS, udp).");
		exit(1);
	}

	tcptransp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (tcptransp == NULL)
	{
		sys_msg(debug, LOG_ERR, "Cannot create tcp service.");
		exit(1);
	}

	if (!svc_register(tcptransp, YPBINDPROG, YPBINDVERS, ypbindprog_2,
	    IPPROTO_TCP))
	{
		sys_msg(debug, LOG_ERR,
			"Unable to register (YPBINDPROG, YPBINDVERS, tcp).");
		exit(1);
	}

	/* XXX use SOCK_STREAM for direct queries? */
	rpcsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (rpcsock == -1)
	{
		sys_msg(debug, LOG_ERR, "rpc socket() failed.");
		exit(1);
	}

	pingsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (pingsock == -1)
	{
		sys_msg(debug, LOG_ERR, "ping socket() failed.");
		exit(1);
	}
	
	fcntl(rpcsock, F_SETFL, fcntl(rpcsock, F_GETFL, 0) | FNDELAY);
	fcntl(pingsock, F_SETFL, fcntl(pingsock, F_GETFL, 0) | FNDELAY);

	one = 1;
	setsockopt(rpcsock, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));
	rmtca.prog = YPPROG;
	rmtca.vers = YPVERS;
	rmtca.proc = YPPROC_DOMAIN_NONACK;
	rmtca.xdr_args = NULL;		/* set at call time */
	rmtca.args_ptr = NULL;		/* set at call time */
	rmtcr.port_ptr = &rmtcr_port;
	rmtcr.xdr_results = xdr_bool;
	rmtcr.results_ptr = (caddr_t)&rmtcr_outval;

	/* build initial domain binding, make it "unsuccessful" */
	ypbindlist = makebinding(dname);
	ypbindlist->dom_vers = YPVERS;
	ypbindlist->dom_alive = 0;
	ypbindlist->dom_lockfd = -1;
	removelock(ypbindlist);

	checkwork();

//	width = svc_maxfd;
	width = FD_SETSIZE;
	width = 32;
	if (rpcsock > width)
		width = rpcsock;
	if (pingsock > width)
		width = pingsock;
	width++;

	for (;;)
	{
		fdsr = svc_fdset;
		FD_SET(rpcsock, &fdsr);
		FD_SET(pingsock, &fdsr);
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		switch (select(width, &fdsr, NULL, NULL, &tv))
		{
			case 0:
				checkwork();
				break;

			case -1:
				sys_msg(debug, LOG_WARNING, "select: %s", strerror(errno));
				break;

			default:
				if (FD_ISSET(rpcsock, &fdsr)) handle_replies();
				if (FD_ISSET(pingsock, &fdsr)) handle_ping();
				svc_getreqset(&fdsr);
				if (check) checkwork();
				break;
		}

		if ((evil == 0) && (ypbindlist->dom_alive != 0))
		{
			evil = 1;
			if (debug == DEBUG_SYSLOG) daemon(0, 0);
		}
	}
}

/*
 * State transition is done like this: 
 *
 * STATE	EVENT		ACTION			NEWSTATE	TIMEOUT
 * no binding	timeout		broadcast 		no binding	5 sec
 * no binding	answer		--			binding		60 sec
 * binding	timeout		ping server		checking	5 sec
 * checking	timeout		ping server + broadcast	checking	5 sec
 * checking	answer		--			binding		60 sec
 */
void
checkwork()
{
	struct _dom_binding *ypdb;
	time_t t;

	check = 0;

	time(&t);
	for (ypdb = ypbindlist; ypdb; ypdb = ypdb->dom_pnext)
	{
		if (ypdb->dom_check_t < t)
		{
			if (ypdb->dom_alive == 1) ping(ypdb);
			else nag_servers(ypdb);
			time(&t);
			ypdb->dom_check_t = t + 5;
		}
	}
}

int
ping(struct _dom_binding *ypdb)
{
	char *dom = ypdb->dom_domain;
	struct rpc_msg msg;
	char buf[BUFSIZE];
	enum clnt_stat st;
	int outlen;
	AUTH *rpcua;
	XDR xdr;

	memset(&xdr, 0, sizeof xdr);
	memset(&msg, 0, sizeof msg);

	rpcua = authunix_create_default();
	if (rpcua == NULL)
	{
		sys_msg(debug, LOG_ERR, "ping: cannot get unix auth");
		return RPC_SYSTEMERROR;
	}

	msg.rm_direction = CALL;
	msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
	msg.rm_call.cb_prog = YPPROG;
	msg.rm_call.cb_vers = YPVERS;
	msg.rm_call.cb_proc = YPPROC_DOMAIN_NONACK;
	msg.rm_call.cb_cred = rpcua->ah_cred;
	msg.rm_call.cb_verf = rpcua->ah_verf;

	msg.rm_xid = ypdb->dom_xid;
	xdrmem_create(&xdr, buf, sizeof buf, XDR_ENCODE);
	if (!xdr_callmsg(&xdr, &msg))
	{
		st = RPC_CANTENCODEARGS;
		AUTH_DESTROY(rpcua);
		return st;
	}

	if (!xdr_domainname(&xdr, (void *)&dom))
	{
		st = RPC_CANTENCODEARGS;
		AUTH_DESTROY(rpcua);
		return st;
	}

	outlen = (int)xdr_getpos(&xdr);
	xdr_destroy(&xdr);
	if (outlen < 1)
	{
		st = RPC_CANTENCODEARGS;
		AUTH_DESTROY(rpcua);
		return st;
	}

	AUTH_DESTROY(rpcua);

	ypdb->dom_alive = 2;
	if (sendto(pingsock, buf, outlen, 0, 
		   (struct sockaddr *)&ypdb->dom_server_addr,
		   sizeof ypdb->dom_server_addr) == -1)
		sys_msg(debug, LOG_WARNING, "ping: sendto");
	return 0;

}

static int
nag_servers(struct _dom_binding *ypdb)
{
	char *dom = ypdb->dom_domain;
	struct rpc_msg msg;
	char buf[BUFSIZE];
	enum clnt_stat st;
	int outlen;
	AUTH *rpcua;
	XDR xdr;

	rmtca.xdr_args = xdr_domainname;
	rmtca.args_ptr = (char *)&dom;

	memset(&xdr, 0, sizeof xdr);
	memset(&msg, 0, sizeof msg);

	rpcua = authunix_create_default();
	if (rpcua == NULL)
	{
		sys_msg(debug, LOG_ERR, "ping: cannot get unix auth");
		return RPC_SYSTEMERROR;
	}

	msg.rm_direction = CALL;
	msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
	msg.rm_call.cb_prog = PMAPPROG;
	msg.rm_call.cb_vers = PMAPVERS;
	msg.rm_call.cb_proc = PMAPPROC_CALLIT;
	msg.rm_call.cb_cred = rpcua->ah_cred;
	msg.rm_call.cb_verf = rpcua->ah_verf;

	msg.rm_xid = ypdb->dom_xid;
	xdrmem_create(&xdr, buf, sizeof buf, XDR_ENCODE);
	if (!xdr_callmsg(&xdr, &msg))
	{
		st = RPC_CANTENCODEARGS;
		AUTH_DESTROY(rpcua);
		return st;
	}

	if (!xdr_rmtcall_args(&xdr, &rmtca))
	{
		st = RPC_CANTENCODEARGS;
		AUTH_DESTROY(rpcua);
		return st;
	}

	outlen = (int)xdr_getpos(&xdr);
	xdr_destroy(&xdr);
	if (outlen < 1)
	{
		st = RPC_CANTENCODEARGS;
		AUTH_DESTROY(rpcua);
		return st;
	}

	AUTH_DESTROY(rpcua);

	if (ypdb->dom_lockfd != -1)
	{
		close(ypdb->dom_lockfd);
		ypdb->dom_lockfd = -1;
		removelock(ypdb);
	}

	if (ypdb->dom_alive == 2)
	{
		/*
		 * This resolves the following situation:
		 * ypserver on other subnet was once bound,
		 * but rebooted and is now using a different port
		 */
		struct sockaddr_in bindsin;

		memset(&bindsin, 0, sizeof bindsin);
		bindsin.sin_family = AF_INET;
		bindsin.sin_len = sizeof(bindsin);
		bindsin.sin_port = htons(PMAPPORT);
		bindsin.sin_addr = ypdb->dom_server_addr.sin_addr;

		if (sendto(rpcsock, buf, outlen, 0, (struct sockaddr *)&bindsin,
			   sizeof bindsin) == -1)
			sys_msg(debug, LOG_WARNING, "broadcast: sendto");
	}

	switch (ypbindmode)
	{
		case YPBIND_SETALL:
		case YPBIND_SETLOCAL:
			if (been_ypset) return direct_set(buf, outlen, ypdb);
			/* FALLTHROUGH */

		case YPBIND_BROADCAST:
			return broadcast(buf, outlen);

		case YPBIND_DIRECT:
			return direct(buf, outlen);
	}

	return -1;
}

static int
broadcast(char *buf, int outlen)
{
	struct ifconf ifc;
	struct ifreq *ifr;
	int offset, addrlen;
	struct in_addr in;
	int sock;
	char inbuf[8192];
	struct sockaddr_in bindsin;

	/* find all networks and send the RPC packet out them all */
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1)
	{
		sys_msg(debug, LOG_WARNING, "broadcast: socket: %s", strerror(errno));
		return -1;
	}

	memset(&bindsin, 0, sizeof bindsin);
	bindsin.sin_family = AF_INET;
	bindsin.sin_len = sizeof(bindsin);
	bindsin.sin_port = htons(PMAPPORT);

	ifc.ifc_len = sizeof inbuf;
	ifc.ifc_buf = inbuf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) < 0)
	{
		close(sock);
		sys_msg(debug, LOG_WARNING, "broadcast: ioctl(SIOCGIFCONF): %s",
			strerror(errno));
		return -1;
	}

	addrlen = sizeof(struct ifreq) - IFNAMSIZ;
	offset = 0;

	while (offset <= ifc.ifc_len)
	{
		ifr = (struct ifreq *)(ifc.ifc_buf + offset);
		offset += IFNAMSIZ;
		if (ifr->ifr_addr.sa_len > addrlen) offset += ifr->ifr_addr.sa_len;
		else offset += addrlen;

		if (ifr->ifr_addr.sa_family != AF_INET) continue;
		if (ioctl(sock, SIOCGIFFLAGS, ifr) < 0) continue;
		if ((ifr->ifr_flags & IFF_UP) == 0) continue;

		if (ifr->ifr_flags & IFF_BROADCAST)
		{
			if (ioctl(sock, SIOCGIFBRDADDR, ifr) < 0)
			{
				sys_msg(debug, LOG_WARNING,
					"broadcast: ioctl(SIOCGIFBRDADDR): %s", strerror(errno));
				continue;
			}
		}
		else if (ifr->ifr_flags & IFF_LOOPBACK)
		{
			if (ioctl(sock, SIOCGIFADDR, ifr) < 0)
			{
				sys_msg(debug, LOG_WARNING,
					"broadcast: ioctl(SIOCGIFADDR): %s", strerror(errno));
				continue;
			}
		}
		else continue;

		in = ((struct sockaddr_in *)&(ifr->ifr_addr))->sin_addr;
		bindsin.sin_addr = in;
		if (sendto(rpcsock, buf, outlen, 0, (struct sockaddr *)&bindsin,
			   sizeof bindsin) == -1)
			sys_msg(debug, LOG_WARNING, "broadcast: sendto: %s",
				strerror(errno));
	}

	close(sock);
	return 0;
}

static int
direct(char *buf, int outlen)
{
	static FILE *df;
	static char ypservers_path[MAXPATHLEN];
	char line[_POSIX2_LINE_MAX];
	char *p;
	struct hostent *hp;
	struct sockaddr_in bindsin;
	int i, count = 0;

	if (df) rewind(df);
	else {
		snprintf(ypservers_path, sizeof(ypservers_path),
		    "%s/%s%s", BINDINGDIR, dname, YPSERVERSSUFF);
		df = fopen(ypservers_path, "r");
		if (df == NULL)
		{
			sys_msg(debug, LOG_ALERT, "Missing file %s, aborting.",
				ypservers_path);
			exit(1);
		}
	}

	memset(&bindsin, 0, sizeof bindsin);
	bindsin.sin_family = AF_INET;
	bindsin.sin_len = sizeof(bindsin);
	bindsin.sin_port = htons(PMAPPORT);

	while(fgets(line, sizeof(line), df) != NULL)
	{
		/* skip lines that are too big */
		p = strchr(line, '\n');
		if (p == NULL)
		{
			int c;

			while ((c = getc(df)) != '\n' && c != EOF);
			continue;
		}

		*p = '\0';
		p = line;
		while (isspace(*p)) p++;
		if (*p == '#') continue;
		hp = gethostbyname(p);
		if (hp == NULL)
		{
			sys_msg(debug, LOG_ERR, "Can't find host: %s", p);
			continue;
		}
	
		/* step through all addresses in case first is unavailable */
		for (i = 0; hp->h_addr_list[i]; i++)
		{
			memmove(&bindsin.sin_addr, hp->h_addr_list[0],
			    hp->h_length);
			if (sendto(rpcsock, buf, outlen, 0,
			    (struct sockaddr *)&bindsin, sizeof bindsin) < 0)
			{
				sys_msg(debug, LOG_WARNING, "direct: sendto: %s",
					strerror(errno));
				continue;
			}
			else count++;
		}
	}
	
	if (count == 0)
	{
		sys_msg(debug, LOG_ALERT,
			"Can't contact any servers listed in %s.  Aborting", ypservers_path);
		exit(1);
	}

	return 0;
}

static int
direct_set(char *buf, int outlen, struct _dom_binding *ypdb)
{
	struct sockaddr_in bindsin;
	char path[MAXPATHLEN];
	struct iovec iov[2];
	struct ypbind_resp ybr;
	SVCXPRT dummy_svc;
	int fd, bytes;

	/*
	 * Gack, we lose if binding file went away.  We reset
	 * "been_set" if this happens, otherwise we'll never
	 * bind again.
	 */
	snprintf(path, sizeof(path), "%s/%s.%ld", BINDINGDIR,
	    ypdb->dom_domain, ypdb->dom_vers);

	if ((fd = open(path, O_SHLOCK|O_RDONLY, 0644)) == -1)
	{
		sys_msg(debug, LOG_WARNING, "Can't open file %s", path);
		been_ypset = 0;
		return -1;
	}

#if O_SHLOCK == 0
	flock(fd, LOCK_SH);
#endif

	/* Read the binding file... */
	iov[0].iov_base = (caddr_t)&(dummy_svc.xp_port);
	iov[0].iov_len = sizeof(dummy_svc.xp_port);
	iov[1].iov_base = (caddr_t)&ybr;
	iov[1].iov_len = sizeof(ybr);
	bytes = readv(fd, iov, 2);
	close(fd);

	if (bytes != (iov[0].iov_len + iov[1].iov_len))
	{
		/* Binding file corrupt? */
		sys_msg(debug, LOG_WARNING, "Can't parse file %s", path);
		been_ypset = 0;
		return -1;
	}

	bcopy(&ybr.ypbind_resp_u.ypbind_bindinfo.ypbind_binding_addr,
		&bindsin.sin_addr, 4);

	if (sendto(rpcsock, buf, outlen, 0, (struct sockaddr *)&bindsin,
	    sizeof(bindsin)) < 0)
	{
		sys_msg(debug, LOG_WARNING, "direct_set: sendto: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static enum clnt_stat
handle_replies()
{
	char buf[BUFSIZE];
	int fromlen, inlen;
	struct _dom_binding *ypdb;
	struct sockaddr_in raddr;
	struct rpc_msg msg;
	XDR xdr;

recv_again:
	memset(&xdr, 0, sizeof(xdr));
	memset(&msg, 0, sizeof(msg));
	msg.acpted_rply.ar_verf = _null_auth;
	msg.acpted_rply.ar_results.where = (caddr_t)&rmtcr;
	msg.acpted_rply.ar_results.proc = xdr_rmtcallres;

try_again:
	fromlen = sizeof (struct sockaddr);
	inlen = recvfrom(rpcsock, buf, sizeof buf, 0,
		(struct sockaddr *)&raddr, &fromlen);
	if (inlen < 0)
	{
		if (errno == EINTR) goto try_again;
		return RPC_CANTRECV;
	}

	if (inlen < sizeof(u_int32_t)) goto recv_again;

	/*
	 * see if reply transaction id matches sent id.
	 * If so, decode the results.
	 */
	xdrmem_create(&xdr, buf, (u_int)inlen, XDR_DECODE);
	if (xdr_replymsg(&xdr, &msg))
	{
		if ((msg.rm_reply.rp_stat == MSG_ACCEPTED) &&
		    (msg.acpted_rply.ar_stat == SUCCESS)) {
			raddr.sin_port = htons((u_short)rmtcr_port);
			ypdb = xid2ypdb(msg.rm_xid);
			if (ypdb != NULL) rpc_received(ypdb->dom_domain, &raddr, 0);
		}
	}

	xdr.x_op = XDR_FREE;
	msg.acpted_rply.ar_results.proc = xdr_void;
	xdr_destroy(&xdr);

	return RPC_SUCCESS;
}

static enum clnt_stat
handle_ping()
{
	char buf[BUFSIZE];
	int fromlen, inlen;
	struct _dom_binding *ypdb;
	struct sockaddr_in raddr;
	struct rpc_msg msg;
	XDR xdr;
	bool_t res;

recv_again:
	memset(&xdr, 0, sizeof(xdr));
	memset(&msg, 0, sizeof(msg));
	msg.acpted_rply.ar_verf = _null_auth;
	msg.acpted_rply.ar_results.where = (caddr_t)&res;
	msg.acpted_rply.ar_results.proc = xdr_bool;

try_again:
	fromlen = sizeof (struct sockaddr);
	inlen = recvfrom(pingsock, buf, sizeof buf, 0,
		(struct sockaddr *)&raddr, &fromlen);
	if (inlen < 0)
	{
		if (errno == EINTR) goto try_again;
		return RPC_CANTRECV;
	}

	if (inlen < sizeof(u_int32_t)) goto recv_again;

	/*
	 * see if reply transaction id matches sent id.
	 * If so, decode the results.
	 */
	xdrmem_create(&xdr, buf, (u_int)inlen, XDR_DECODE);
	if (xdr_replymsg(&xdr, &msg))
	{
		if ((msg.rm_reply.rp_stat == MSG_ACCEPTED) &&
		    (msg.acpted_rply.ar_stat == SUCCESS))
		{
			ypdb = xid2ypdb(msg.rm_xid);
			if (ypdb != NULL) rpc_received(ypdb->dom_domain, &raddr, 0);
		}
	}

	xdr.x_op = XDR_FREE;
	msg.acpted_rply.ar_results.proc = xdr_void;
	xdr_destroy(&xdr);

	return RPC_SUCCESS;
}

/*
 * LOOPBACK IS MORE IMPORTANT: PUT IN HACK
 */
void
rpc_received(char *dom, struct sockaddr_in *raddrp, int force)
{
	struct _dom_binding *ypdb;
	struct iovec iov[2];
	struct ypbind_resp ybr;
	int fd;

	sys_msg(debug, LOG_DEBUG, "returned from %s about %s",
		inet_ntoa(raddrp->sin_addr), dom);

	if (dom == NULL) return;

	/* don't support insecure servers by default */
	if (!insecure && ntohs(raddrp->sin_port) >= IPPORT_RESERVED) return;

	for (ypdb = ypbindlist; ypdb; ypdb = ypdb->dom_pnext)
	{
		if (!strcmp(ypdb->dom_domain, dom)) break;
	}

	if (ypdb == NULL)
	{
		if (force == 0) return;
		ypdb = makebinding(dom);
		ypdb->dom_lockfd = -1;
		ypdb->dom_pnext = ypbindlist;
		ypbindlist = ypdb;
	}

	/* soft update, alive */
	if (ypdb->dom_alive == 1 && force == 0)
	{
		if (!memcmp(&ypdb->dom_server_addr, raddrp,
			sizeof ypdb->dom_server_addr))
		{
			ypdb->dom_alive = 1;
			/* recheck binding in 60 sec */
			ypdb->dom_check_t = time(NULL) + 60;
		}
		return;
	}
	
	memcpy(&ypdb->dom_server_addr, raddrp, sizeof ypdb->dom_server_addr);
	/* recheck binding in 60 seconds */
	ypdb->dom_check_t = time(NULL) + 60;
	ypdb->dom_vers = YPVERS;
	ypdb->dom_alive = 1;

	if (ypdb->dom_lockfd != -1) close(ypdb->dom_lockfd);

	if ((fd = makelock(ypdb)) == -1) return;

	/*
	 * ok, if BINDINGDIR exists, and we can create the binding file,
	 * then write to it..
	 */
	ypdb->dom_lockfd = fd;

	iov[0].iov_base = (caddr_t)&(udptransp->xp_port);
	iov[0].iov_len = sizeof udptransp->xp_port;
	iov[1].iov_base = (caddr_t)&ybr;
	iov[1].iov_len = sizeof ybr;

	memset(&ybr, 0, sizeof ybr);
	ybr.ypbind_status = YPBIND_SUCC_VAL;
	bcopy(&raddrp->sin_addr.s_addr,
		ybr.ypbind_resp_u.ypbind_bindinfo.ypbind_binding_addr, 4);
	bcopy(&raddrp->sin_port,
		ybr.ypbind_resp_u.ypbind_bindinfo.ypbind_binding_port, 2);
	
	if (writev(ypdb->dom_lockfd, iov, 2) !=
	    iov[0].iov_len + iov[1].iov_len)
	{
		sys_msg(debug, LOG_WARNING, "writev: %s", strerror(errno));
		close(ypdb->dom_lockfd);
		removelock(ypdb);
		ypdb->dom_lockfd = -1;
	}
}

static struct _dom_binding *
xid2ypdb(u_int32_t xid)
{
	struct _dom_binding *ypdb;

	for (ypdb = ypbindlist; ypdb; ypdb = ypdb->dom_pnext)
	{
		if (ypdb->dom_xid == xid) break;
	}

	return (ypdb);
}

static u_int32_t
unique_xid(struct _dom_binding *ypdb)
{
	u_int32_t tmp_xid;

	tmp_xid = (u_int32_t)(((u_long)ypdb) & 0xffffffff);
	while (xid2ypdb(tmp_xid) != NULL) tmp_xid++;

	return tmp_xid;
}
