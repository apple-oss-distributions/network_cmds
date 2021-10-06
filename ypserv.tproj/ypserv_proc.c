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
/*	$OpenBSD: ypserv_proc.c,v 1.14 1997/09/12 01:44:57 deraadt Exp $ */

/*
 * Copyright (c) 1994 Mats O Jansson <moj@stacken.kth.se>
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
 *	This product includes software developed by Mats O Jansson
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
static char rcsid[] = "$OpenBSD: ypserv_proc.c,v 1.14 1997/09/12 01:44:57 deraadt Exp $";
#endif

#include <rpc/rpc.h>
#include "yp.h"
#include "ypv1.h"
#include <rpcsvc/ypclnt.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ypdb.h"
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "yplog.h"
#include "ypdef.h"

#ifdef DEBUG
#define YPLOG yplog
#else /* DEBUG */
#define YPLOG if (!ok) yplog
#endif /* DEBUG */

extern ypresp_val ypdb_get_record();
extern ypresp_key_val ypdb_get_first();
extern ypresp_key_val ypdb_get_next();
extern ypresp_order ypdb_get_order();
extern ypresp_master ypdb_get_master();
extern bool_t ypdb_xdr_get_all();
extern void ypdb_close_all();
extern int ypdb_secure();

static char *True = "true";
static char *False = "FALSE";
#define TORF(N) ((N) ? True : False)
void *
ypproc_null_2_svc(argp, rqstp)
	void *argp;
        struct svc_req *rqstp;
{
	static char *result;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);

	YPLOG("null_2: caller=[%s].%d, auth_ok=%s",
	      inet_ntoa(caller->sin_addr), ntohs(caller->sin_port), TORF(ok));

	if (!ok) {
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	result = NULL;

	return ((void *)&result);
}

bool_t *
ypproc_domain_2_svc(argp, rqstp)
	domainname *argp;
        struct svc_req *rqstp;
{
	static bool_t result; /* is domain_served? */
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	static char domain_path[MAXPATHLEN];
	struct stat finfo;

	if (strchr(*argp, '/'))
		goto bail;
	snprintf(domain_path, sizeof(domain_path), "%s/%s", YP_DB_PATH, *argp);
	result = (bool_t) ((stat(domain_path, &finfo) == 0) &&
				    (finfo.st_mode & S_IFDIR));

	YPLOG("domain_2: caller=[%s].%d, auth_ok=%s, domain=%s, served=%s",
	      inet_ntoa(caller->sin_addr), ntohs(caller->sin_port), 
	      TORF(ok), *argp, TORF(result));

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	return (&result);
}

bool_t *
ypproc_domain_nonack_2_svc(argp, rqstp)
	domainname *argp;
        struct svc_req *rqstp;
{
	static bool_t result; /* is domain served? */
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	static char domain_path[MAXPATHLEN];
	struct stat finfo;

	if (strchr(*argp, '/'))
		goto bail;
	snprintf(domain_path, sizeof(domain_path), "%s/%s", YP_DB_PATH, *argp);
	result = (bool_t) ((stat(domain_path, &finfo) == 0) &&
				    (finfo.st_mode & S_IFDIR));

	YPLOG(
	  "domain_nonack_2: caller=[%s].%d, auth_ok=%s, domain=%s, served=%s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port), TORF(ok), 
	  *argp, TORF(result));

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	if (!result) {
		return(NULL); /* don't send nack */
	}

	return (&result);
}

ypresp_val *
ypproc_match_2_svc(argp, rqstp)
	ypreq_key *argp;
        struct svc_req *rqstp;
{
	static ypresp_val res;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	int secure = ypdb_secure(argp->domain,argp->map);

	if (strchr(argp->domain, '/') || strchr(argp->map, '/'))
		goto bail;
	YPLOG(
	  "match_2: caller=[%s].%d, auth_ok=%s, secure=%s, domain=%s, map=%s, key=%.*s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port),
	  TORF(ok), TORF(secure),
	  argp->domain, argp->map, argp->key.keydat_len, argp->key.keydat_val);

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	if (secure && (ntohs(caller->sin_port) >= IPPORT_RESERVED)) {
		res.stat = YP_YPERR;
	} else {
		res = ypdb_get_record(argp->domain,argp->map,argp->key, FALSE);
	}

#ifdef DEBUG
	yplog("  match2_status: %s", yperr_string(ypprot_err(res.stat)));
#endif

	return (&res);
}

ypresp_key_val *
ypproc_first_2_svc(argp, rqstp)
	ypreq_nokey *argp;
        struct svc_req *rqstp;
{
	static ypresp_key_val res;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	int secure = ypdb_secure(argp->domain,argp->map);

	if (strchr(argp->domain, '/') || strchr(argp->map, '/'))
		goto bail;
	YPLOG( "first_2: caller=[%s].%d, auth_ok=%s, secure=%s, domain=%s, map=%s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port),
	  TORF(ok), TORF(secure),
	  argp->domain, argp->map);
	
	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	if (secure && (ntohs(caller->sin_port) >= IPPORT_RESERVED)) {
		res.stat = YP_YPERR;
	} else {
		res = ypdb_get_first(argp->domain,argp->map,FALSE);
	}

#ifdef DEBUG
	yplog("  first2_status: %s", yperr_string(ypprot_err(res.stat)));
#endif

	return (&res);
}

ypresp_key_val *
ypproc_next_2_svc(argp, rqstp)
	ypreq_key *argp;
        struct svc_req *rqstp;
{
	static ypresp_key_val res;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	int secure = ypdb_secure(argp->domain,argp->map);

	if (strchr(argp->domain, '/') || strchr(argp->map, '/'))
		goto bail;
	YPLOG(
	  "next_2: caller=[%s].%d, auth_ok=%s, secure=%s, domain=%s, map=%s, key=%.*s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port),
	  TORF(ok), TORF(secure),
	  argp->domain, argp->map, argp->key.keydat_len, argp->key.keydat_val);

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	if (secure && (ntohs(caller->sin_port) >= IPPORT_RESERVED)) {
		res.stat = YP_YPERR;
	} else {
		res = ypdb_get_next(argp->domain,argp->map,argp->key,FALSE);
	}

#ifdef DEBUG
	yplog("  next2_status: %s", yperr_string(ypprot_err(res.stat)));
#endif

	return (&res);
}

ypresp_xfr *
ypproc_xfr_2_svc(argp, rqstp)
	ypreq_xfr *argp;
        struct svc_req *rqstp;
{
	static ypresp_xfr res;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	pid_t	pid;
	char	tid[11];
	char	prog[11];
	char	port[11];
	char	ypxfr_proc[] = YPXFR_PROC;
	char	*ipadd;

	bzero((char *)&res, sizeof(res));

	YPLOG("xfr_2: caller=[%s].%d, auth_ok=%s, domain=%s, tid=%d, prog=%d",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port), TORF(ok), 
	  argp->map_parms.domain, argp->transid, argp->prog);
	YPLOG("       ipadd=%s, port=%d, map=%s", inet_ntoa(caller->sin_addr),
	  argp->port, argp->map_parms.map);

	if (strchr(argp->map_parms.domain, '/') ||
	    strchr(argp->map_parms.map, '/') ||
	    ntohs(caller->sin_port) >= IPPORT_RESERVED) {
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	snprintf(tid, sizeof(tid), "%d",argp->transid);
	snprintf(prog, sizeof(prog), "%d", argp->prog);
	snprintf(port, sizeof(port), "%d", argp->port);
	ipadd = inet_ntoa(caller->sin_addr);

	pid = vfork();
	if (pid == -1) {
		svcerr_systemerr(rqstp->rq_xprt);
		return(NULL);
	}
	if (pid == 0) {
		execl(ypxfr_proc, "ypxfr", "-d", argp->map_parms.domain,
		    "-C",tid, prog, ipadd, port, argp->map_parms.map, NULL);
		_exit(1);
	}
	
	/*
	 * XXX: fill in res
	 */
	return (&res);
}

void *
ypproc_clear_2_svc(argp, rqstp)
	void *argp;
        struct svc_req *rqstp;
{
	static char *res;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);

	YPLOG( "clear_2: caller=[%s].%d, auth_ok=%s, opt=%s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port), TORF(ok),
#ifdef OPTDB
		True
#else
		False
#endif
	);

	if (ntohs(caller->sin_port) >= IPPORT_RESERVED)
		ok = FALSE;

	if (!ok) {
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	res = NULL;
	
#ifdef OPTDB
        ypdb_close_all();
#endif

	return ((void *)&res);
}

ypresp_all *
ypproc_all_2_svc(argp, rqstp)
	ypreq_nokey *argp;
        struct svc_req *rqstp;
{
	static ypresp_all res;
	pid_t pid;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	int secure = ypdb_secure(argp->domain,argp->map);

	if (strchr(argp->domain, '/') || strchr(argp->map, '/'))
		goto bail;
	YPLOG( "all_2: caller=[%s].%d, auth_ok=%s, secure=%s, domain=%s, map=%s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port),
	  TORF(ok), TORF(secure), argp->domain, argp->map);

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	bzero((char *)&res, sizeof(res));
	
	if (secure && (ntohs(caller->sin_port) >= IPPORT_RESERVED)) {
		res.ypresp_all_u.val.stat = YP_YPERR;
		return(&res);
	}

	pid = fork();

	if (pid) {

		if (pid == -1) {
			/* XXXCDC An error has occurred */
		}
		
		return(NULL); /* PARENT: continue */
		
	}
	/* CHILD: send result, then exit */

	if (!svc_sendreply(rqstp->rq_xprt, ypdb_xdr_get_all, (char *) argp)) {
		svcerr_systemerr(rqstp->rq_xprt);
	}

	/* note: no need to free args, we are exiting */

	exit(0);
}

ypresp_master *
ypproc_master_2_svc(argp, rqstp)
	ypreq_nokey *argp;
        struct svc_req *rqstp;
{
	static ypresp_master res;
	static peername nopeer = "";
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	int secure = ypdb_secure(argp->domain,argp->map);

	if (strchr(argp->domain, '/') || strchr(argp->map, '/'))
		goto bail;
	YPLOG( "master_2: caller=[%s].%d, auth_ok=%s, secure=%s, domain=%s, map=%s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port),
	  TORF(ok), TORF(secure), argp->domain, argp->map);

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	if (secure && (ntohs(caller->sin_port) >= IPPORT_RESERVED)) {
		res.stat = YP_YPERR;
	} else {
		res = ypdb_get_master(argp->domain,argp->map);
	}

#ifdef DEBUG
	yplog("  master2_status: %s", yperr_string(ypprot_err(res.stat)));
#endif

	/* This code was added because a yppoll <unknown-domain> */
	/* from a sun crashed the server in xdr_string, trying   */
	/* to access the peer through a NULL-pointer. yppoll in  */
	/* this server start asking for order. If order is ok    */
	/* then it will ask for master. SunOS 4 asks for both    */
	/* always. I'm not sure this is the best place for the   */
	/* fix, but for now it will do. xdr_peername or          */
	/* xdr_string in ypserv_xdr.c may be a better place?     */
	
	if (res.peer == NULL) {
		res.peer = nopeer;
	}

	/* End of fix                                            */

	return (&res);
}


ypresp_order *
ypproc_order_2_svc(argp, rqstp)
	ypreq_nokey *argp;
        struct svc_req *rqstp;
{
	static ypresp_order res;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	int secure = ypdb_secure(argp->domain,argp->map);

	if (strchr(argp->domain, '/'))
		goto bail;
	YPLOG( "order_2: caller=[%s].%d, auth_ok=%s, secure=%s, domain=%s, map=%s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port),
	  TORF(ok), TORF(secure), argp->domain, argp->map);

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	if (secure && (ntohs(caller->sin_port) >= IPPORT_RESERVED)) {
		res.stat = YP_YPERR;
	} else if (strchr(argp->map, '/')) {
		res.stat = YP_NOMAP;
	} else {
		res = ypdb_get_order(argp->domain,argp->map);
	}

#ifdef DEBUG
	yplog("  order2_status: %s", yperr_string(ypprot_err(res.stat)));
#endif

	return (&res);
}


ypresp_maplist *
ypproc_maplist_2_svc(argp, rqstp)
	domainname *argp;
        struct svc_req *rqstp;
{
	static ypresp_maplist res;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	static char domain_path[MAXPATHLEN];
	struct stat finfo;
	DIR   *dirp = NULL;
	struct dirent *dp;
	char  *suffix;
	ypstat status;
	struct ypmaplist *m;
	char  *map_name;

	if (strchr(*argp, '/'))
		goto bail;
	YPLOG("maplist_2: caller=[%s].%d, auth_ok=%s, domain=%s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port), TORF(ok),
	  *argp);

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	bzero((char *)&res, sizeof(res));
	
	snprintf(domain_path,MAXPATHLEN, "%s/%s",YP_DB_PATH,*argp);

	status = YP_TRUE;

	res.maps = NULL;

	if (!((stat(domain_path, &finfo) == 0) &&
		((finfo.st_mode & S_IFMT) == S_IFDIR))) 
		status = YP_NODOM;

	if (status >= 0) {
	  if ((dirp = opendir(domain_path)) == NULL) {
	    status = YP_NODOM;
	  }
	}

	if (status >= 0) {
	  for(dp = readdir(dirp); dp != NULL; dp = readdir(dirp)) {
	    if ((!strcmp(dp->d_name, ".")) ||
		((!strcmp(dp->d_name, ".."))) ||
		(dp->d_namlen < 4))
	      continue;
	    suffix = (char *) &dp->d_name[dp->d_namlen-3];
	    if (strcmp(suffix,".db") == 0) {

	      if ((m = (struct ypmaplist *)
		   malloc((unsigned) sizeof(struct ypmaplist))) == NULL) {
		status = YP_YPERR;
		break;
	      }

	      if ((map_name = (char *)
		   malloc((unsigned) dp->d_namlen - 2)) == NULL) {
		status = YP_YPERR;
		break;
	      }

	      m->next = res.maps;
	      m->map = map_name;
	      res.maps = m;
	      strncpy(map_name, dp->d_name, dp->d_namlen - 3);
	      m->map[dp->d_namlen - 3] = '\0';
	      
	    }
	  }
	}
	
	if (dirp != NULL) {
	  closedir(dirp);
	}

	res.stat = status;
	
#ifdef DEBUG
	yplog("  maplist_status: %s", yperr_string(ypprot_err(res.stat)));
#endif

	return (&res);
}

void *
ypproc_null_1_svc(argp, rqstp)
	void *argp;
        struct svc_req *rqstp;
{
	static char *result;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);

	YPLOG("null_1: caller=[%s].%d, auth_ok=%s",
	      inet_ntoa(caller->sin_addr), ntohs(caller->sin_port), TORF(ok));

	if (!ok) {
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	result = NULL;

	return ((void *)&result);
}

bool_t *
ypproc_domain_1_svc(argp, rqstp)
	domainname *argp;
        struct svc_req *rqstp;
{
	static bool_t result; /* is domain_served? */
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	static char domain_path[MAXPATHLEN];
	struct stat finfo;

	if (strchr(*argp, '/'))
		goto bail;
	snprintf(domain_path, sizeof(domain_path), "%s/%s", YP_DB_PATH, *argp);
	result = (bool_t) ((stat(domain_path, &finfo) == 0) &&
				    (finfo.st_mode & S_IFDIR));

	YPLOG("domain_1: caller=[%s].%d, auth_ok=%s, domain=%s, served=%s",
	      inet_ntoa(caller->sin_addr), ntohs(caller->sin_port), 
	      TORF(ok), *argp, TORF(result));

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	return (&result);
}

bool_t *
ypproc_domain_nonack_1_svc(argp, rqstp)
	domainname *argp;
        struct svc_req *rqstp;
{
	static bool_t result; /* is domain served? */
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	static char domain_path[MAXPATHLEN];
	struct stat finfo;

	if (strchr(*argp, '/'))
		goto bail;
	snprintf(domain_path, sizeof(domain_path), "%s/%s", YP_DB_PATH, *argp);
	result = (bool_t) ((stat(domain_path, &finfo) == 0) &&
				    (finfo.st_mode & S_IFDIR));

	YPLOG(
	  "domain_nonack_1: caller=[%s].%d, auth_ok=%s, domain=%s, served=%s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port), TORF(ok), 
	  *argp, TORF(result));

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	if (!result) {
		return(NULL); /* don't send nack */
	}

	return (&result);
}

ypresponse *
ypproc_match_1_svc(argp, rqstp)
	yprequest *argp;
        struct svc_req *rqstp;
{
	static ypresponse res;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	int secure;

	if (strchr(argp->ypmatch_req_domain, '/') ||
	    strchr(argp->ypmatch_req_map, '/'))
		goto bail;
	res.yp_resptype = YPMATCH_RESPTYPE;
	res.ypmatch_resp_valptr = "";
	res.ypmatch_resp_valsize = 0;

	if (argp->yp_reqtype != YPMATCH_REQTYPE) {
		res.ypmatch_resp_status = YP_BADARGS;
		return(&res);
	}

	secure = ypdb_secure(argp->ypmatch_req_domain, argp->ypmatch_req_map);

	YPLOG(
	  "match_1: caller=[%s].%d, auth_ok=%s, secure=%s, domain=%s, map=%s, key=%.*s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port),
	  TORF(ok), TORF(secure),
	  argp->ypmatch_req_domain,  argp->ypmatch_req_map,
	  argp->ypmatch_req_keysize, argp->ypmatch_req_keyptr);

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	if (secure && (ntohs(caller->sin_port) >= IPPORT_RESERVED)) {
		res.ypmatch_resp_status = YP_YPERR;
	} else {
		res.ypmatch_resp_val =
		      ypdb_get_record(argp->ypmatch_req_domain,
				      argp->ypmatch_req_map,
				      argp->ypmatch_req_keydat,
				      FALSE);
	}

#ifdef DEBUG
	yplog("  match1_status: %s",
	      yperr_string(ypprot_err(res.ypmatch_resp_status)));
#endif

	return (&res);
}

ypresponse *
ypproc_first_1_svc(argp, rqstp)
	yprequest *argp;
        struct svc_req *rqstp;
{
	static ypresponse res;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	int secure;

	if (strchr(argp->ypfirst_req_domain, '/') ||
	    strchr(argp->ypfirst_req_map, '/'))
		goto bail;
	res.yp_resptype = YPFIRST_RESPTYPE;
	res.ypfirst_resp_valptr  = res.ypfirst_resp_keyptr  = "";
	res.ypfirst_resp_valsize = res.ypfirst_resp_keysize = 0;

	if (argp->yp_reqtype != YPREQ_NOKEY) {
		res.ypfirst_resp_status = YP_BADARGS;
		return(&res);
	}

	secure = ypdb_secure(argp->ypfirst_req_domain, argp->ypfirst_req_map);

	YPLOG( "first_1: caller=[%s].%d, auth_ok=%s, secure=%s, domain=%s, map=%s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port),
	  TORF(ok), TORF(secure),
	  argp->ypfirst_req_domain, argp->ypfirst_req_map);
	
	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	if (secure && (ntohs(caller->sin_port) >= IPPORT_RESERVED)) {
		res.ypfirst_resp_status = YP_YPERR;
	} else {
		res.ypfirst_resp_val =
		      ypdb_get_first(argp->ypfirst_req_domain,
				     argp->ypfirst_req_map,
				     FALSE);
	}

#ifdef DEBUG
	yplog("  first1_status: %s",
	      yperr_string(ypprot_err(res.ypfirst_resp_status)));
#endif

	return (&res);
}

ypresponse *
ypproc_next_1_svc(argp, rqstp)
	yprequest *argp;
        struct svc_req *rqstp;
{
	static ypresponse res;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	int secure;

	if (strchr(argp->ypnext_req_domain, '/') ||
	    strchr(argp->ypnext_req_map, '/'))
		goto bail;
	res.yp_resptype = YPNEXT_RESPTYPE;
	res.ypnext_resp_valptr  = res.ypnext_resp_keyptr  = "";
	res.ypnext_resp_valsize = res.ypnext_resp_keysize = 0;

	if (argp->yp_reqtype != YPNEXT_REQTYPE) {
		res.ypnext_resp_status = YP_BADARGS;
		return(&res);
	}

	secure = ypdb_secure(argp->ypnext_req_domain, argp->ypnext_req_map);

	YPLOG(
	  "next_1: caller=[%s].%d, auth_ok=%s, secure=%s, domain=%s, map=%s, key=%.*s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port),
	  TORF(ok), TORF(secure),
	  argp->ypnext_req_domain,  argp->ypnext_req_map,
	  argp->ypnext_req_keysize, argp->ypnext_req_keyptr);

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	if (secure && (ntohs(caller->sin_port) >= IPPORT_RESERVED)) {
		res.ypnext_resp_status = YP_YPERR;
	} else {
		res.ypnext_resp_val =
		      ypdb_get_next(argp->ypnext_req_domain,
				    argp->ypnext_req_map,
				    argp->ypnext_req_keydat,
				    FALSE);
	}

#ifdef DEBUG
	yplog("  next1_status: %s",
	      yperr_string(ypprot_err(res.ypnext_resp_status)));
#endif

	return (&res);
}

ypresponse *
ypproc_poll_1_svc(argp, rqstp)
	yprequest *argp;
        struct svc_req *rqstp;
{
	static ypresponse res;
	ypresp_order order;
	ypresp_master master;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	int secure;

	if (strchr(argp->yppoll_req_domain, '/') ||
	    strchr(argp->yppoll_req_map, '/'))
		goto bail;
	res.yp_resptype = YPPOLL_RESPTYPE;
	res.yppoll_resp_domain = argp->yppoll_req_domain;
	res.yppoll_resp_map = argp->yppoll_req_map;
	res.yppoll_resp_ordernum = 0;
	res.yppoll_resp_owner = "";

	if (argp->yp_reqtype != YPPOLL_REQTYPE) {
		return(&res);
	}

	secure = ypdb_secure(argp->yppoll_req_domain, argp->yppoll_req_map);

	YPLOG( "poll_1: caller=[%s].%d, auth_ok=%s, secure=%s, domain=%s, map=%s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port),
	  TORF(ok), TORF(secure),
	  argp->yppoll_req_domain, argp->yppoll_req_map);

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	if (!(secure && (ntohs(caller->sin_port) >= IPPORT_RESERVED))) {
		order = ypdb_get_order(argp->yppoll_req_domain,
				       argp->yppoll_req_map);
		master = ypdb_get_master(argp->yppoll_req_domain,
					 argp->yppoll_req_map);
		res.yppoll_resp_ordernum = order.ordernum;
		res.yppoll_resp_owner = master.peer;
	}

#ifdef DEBUG
	yplog("  poll1_status: %s", "none");
#endif
	return (&res);
}

void *
ypproc_push_1_svc(argp, rqstp)
	yprequest *argp;
        struct svc_req *rqstp;
{
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	int secure;
	pid_t	pid;
	char	yppush_proc[] = YPPUSH_PROC;

	if (strchr(argp->yppush_req_domain, '/') ||
	    strchr(argp->yppush_req_map, '/'))
		goto bail;
	if (argp->yp_reqtype != YPPUSH_REQTYPE) {
		return(NULL);
	}

	secure = ypdb_secure(argp->yppush_req_domain, argp->yppush_req_map);

	YPLOG( "push_1: caller=[%s].%d, auth_ok=%s, secure=%s, domain=%s, map=%s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port),
	  TORF(ok), TORF(secure),
	  argp->yppush_req_domain, argp->yppush_req_map);

	if (ntohs(caller->sin_port) >= IPPORT_RESERVED)
		ok = FALSE;

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	pid = vfork();
	if (pid == -1) {
		svcerr_systemerr(rqstp->rq_xprt);
		return(NULL);
	}
	if (pid == 0) {
		execl(yppush_proc, "yppush", "-d", argp->yppush_req_domain,
		      argp->yppush_req_map, NULL);
		_exit(1);
	}
	
	return (NULL);
}

void *
ypproc_pull_1_svc(argp, rqstp)
	yprequest *argp;
        struct svc_req *rqstp;
{
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	int secure;
	pid_t	pid;
	char	ypxfr_proc[] = YPXFR_PROC;

	if (strchr(argp->yppull_req_domain, '/') ||
	    strchr(argp->yppull_req_map, '/'))
		goto bail;
	if (argp->yp_reqtype != YPPULL_REQTYPE) {
		return(NULL);
	}

	secure = ypdb_secure(argp->yppull_req_domain, argp->yppull_req_map);

	YPLOG( "pull_1: caller=[%s].%d, auth_ok=%s, secure=%s, domain=%s, map=%s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port),
	  TORF(ok), TORF(secure),
	  argp->yppull_req_domain, argp->yppull_req_map);

	if (ntohs(caller->sin_port) >= IPPORT_RESERVED)
		ok = FALSE;

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	pid = vfork();
	if (pid == -1) {
		svcerr_systemerr(rqstp->rq_xprt);
		return(NULL);
	}
	if (pid == 0) {
		execl(ypxfr_proc, "ypxfr", "-d", argp->yppull_req_domain,
		      argp->yppull_req_map, NULL);
		_exit(1);
	}
	
	return (NULL);
}

void *
ypproc_get_1_svc(argp, rqstp)
	yprequest *argp;
        struct svc_req *rqstp;
{
	char *res;
	struct sockaddr_in *caller = svc_getcaller(rqstp->rq_xprt);
	int ok = yp_acl_check_host(&caller->sin_addr);
	int secure;
	pid_t	pid;
	char	ypxfr_proc[] = YPXFR_PROC;

	if (strchr(argp->ypget_req_domain, '/') ||
	    strchr(argp->ypget_req_map, '/'))
		goto bail;
	if (argp->yp_reqtype != YPGET_REQTYPE) {
		return(NULL);
	}

	secure = ypdb_secure(argp->ypget_req_domain, argp->ypget_req_map);

	YPLOG( "get_1: caller=[%s].%d, auth_ok=%s, secure=%s, domain=%s, map=%s, owner=%s",
	  inet_ntoa(caller->sin_addr), ntohs(caller->sin_port),
	  TORF(ok), TORF(secure),
	  argp->ypget_req_domain, argp->ypget_req_map,
	  argp->ypget_req_owner);

	if (ntohs(caller->sin_port) >= IPPORT_RESERVED)
		ok = FALSE;

	if (!ok) {
bail:
		svcerr_auth(rqstp->rq_xprt, AUTH_FAILED);
		return(NULL);
	}

	pid = vfork();
	if (pid == -1) {
		svcerr_systemerr(rqstp->rq_xprt);
		return(NULL);
	}
	if (pid == 0) {
		execl(ypxfr_proc, "ypxfr", "-d", argp->ypget_req_domain, "-h",
		      argp->ypget_req_owner, argp->yppush_req_map, NULL);
		_exit(1);
	}
	
	return (NULL);
}
