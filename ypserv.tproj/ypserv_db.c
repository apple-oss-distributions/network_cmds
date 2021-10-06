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
/*	$OpenBSD: ypserv_db.c,v 1.13 1997/08/09 23:10:12 maja Exp $ */

/*
 * Copyright (c) 1994 Mats O Jansson <moj@stacken.kth.se>
 * Copyright (c) 1996 Charles D. Cranor
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
 *	and Charles D. Cranor.
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
static char rcsid[] = "$OpenBSD: ypserv_db.c,v 1.13 1997/08/09 23:10:12 maja Exp $";
#endif

/*
 * major revision/cleanup of Mats' version 
 * done by Chuck Cranor <chuck@ccrc.wustl.edu>
 * Jan 1996.
 */


#include <rpc/rpc.h>
#include <rpcsvc/yp.h>
#include <rpcsvc/ypclnt.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/errno.h>
#include "yplog.h"
#include "ypdb.h"
#include "ypdef.h"

LIST_HEAD(domainlist, opt_domain);	/* LIST of domains */
LIST_HEAD(maplist, opt_map);		/* LIST of maps (in a domain) */
CIRCLEQ_HEAD(mapq, opt_map);		/* CIRCLEQ of maps (LRU) */

struct opt_map {
	mapname	map;			/* map name (malloc'd) */
	DBM	*db;			/* database */
	struct opt_domain *dom;		/* back ptr to our domain */
	int	host_lookup;		/* host lookup */
	int	secure;			/* secure map? */
	CIRCLEQ_ENTRY(opt_map) mapsq;	/* map queue pointers */
	LIST_ENTRY(opt_map) mapsl;	/* map list pointers */
};

struct opt_domain {
	domainname	domain;		/* domain name (malloc'd) */
	struct maplist	dmaps;		/* the domain's active maps */
	LIST_ENTRY(opt_domain) domsl;   /* global linked list of domains */
};


struct domainlist doms;			/* global list of domains */
struct mapq maps;			/* global queue of maps (LRU) */

extern int usedns;

/*
 * ypdb_init: init the queues and lists
 */

void
ypdb_init()

{
	LIST_INIT(&doms);
	CIRCLEQ_INIT(&maps);
}


/*
 * yp_private:
 * Check if key is a YP private key. Return TRUE if it is and
 * ypprivate is FALSE.
 */

int
yp_private(key,ypprivate)
	datum	key;
	int	ypprivate;
{
/*	int	result; */

  	if (ypprivate)
	    return (FALSE);

	if (key.dsize == 0 || key.dptr == NULL)
		return (FALSE);

	if (key.dsize == YP_LAST_LEN &&
	    strncmp(key.dptr,YP_LAST_KEY,YP_LAST_LEN) == 0)
		return(TRUE);
	if (key.dsize == YP_INPUT_LEN &&
	    strncmp(key.dptr,YP_INPUT_KEY,YP_INPUT_LEN) == 0)
		return(TRUE);
	if (key.dsize == YP_OUTPUT_LEN &&
	    strncmp(key.dptr,YP_OUTPUT_KEY,YP_OUTPUT_LEN) == 0)
		return(TRUE);
	if (key.dsize == YP_MASTER_LEN &&
	    strncmp(key.dptr,YP_MASTER_KEY,YP_MASTER_LEN) == 0)
		return(TRUE);
	if (key.dsize == YP_DOMAIN_LEN &&
	    strncmp(key.dptr,YP_DOMAIN_KEY,YP_DOMAIN_LEN) == 0)
		return(TRUE);
	if (key.dsize == YP_INTERDOMAIN_LEN &&
	    strncmp(key.dptr,YP_INTERDOMAIN_KEY,YP_INTERDOMAIN_LEN) == 0)
		return(TRUE);
	if (key.dsize == YP_SECURE_LEN &&
	    strncmp(key.dptr,YP_SECURE_KEY,YP_SECURE_LEN) == 0)
		return(TRUE);
	
	return(FALSE);
}     

/*
 * Close least recent used map. This routine is called when we have
 * no more file descripotors free, or we want to close all maps.
 */

void
ypdb_close_last()
{
	struct opt_map *last = maps.cqh_last;

	if (last == (void*)&maps) {
		yplog("  ypdb_close_last: LRU list is empty!");
		return;
	}

	CIRCLEQ_REMOVE(&maps, last, mapsq);	/* remove from LRU circleq */
	LIST_REMOVE(last, mapsl);		/* remove from domain list */

#ifdef DEBUG
	yplog("  ypdb_close_last: closing map %s in domain %s [db=0x%x]",
		last->map, last->dom->domain, last->db);
#endif

	ypdb_close(last->db);			/* close DB */
	free(last->map);			/* free map name */
	free(last);				/* free map */

	
}

/*
 * Close all open maps.
 */

void
ypdb_close_all()
{
	
#ifdef DEBUG
	yplog("  ypdb_close_all(): start");
#endif
	while (maps.cqh_first != (void *)&maps) {
		ypdb_close_last();
	}
#ifdef DEBUG
	yplog("  ypdb_close_all(): done");
#endif
}

/*
 * Close Database if Open/Close Optimization isn't turned on.
 */

void
ypdb_close_db(db)
	DBM	*db;
{
#ifdef DEBUG
	yplog("  ypdb_close_db(0x%x)", db);
#endif
#ifndef OPTDB
	ypdb_close_all();
#endif
}

/*
 * ypdb_open_db
 */

DBM *
ypdb_open_db(domain, map, status, map_info)
	domainname	domain;
	mapname		map;
	ypstat		*status;
	struct opt_map	**map_info;
{
	char map_path[MAXPATHLEN];
	static char   *domain_key = YP_INTERDOMAIN_KEY;
	static char   *secure_key = YP_SECURE_KEY;
/*	struct	stat finfo; */
	DBM	*db;
/*	int	fd; */
	struct opt_domain *d = NULL;
	struct opt_map	*m = NULL;
	datum	k,v;
#ifdef OPTDB
	int	i;
#endif
	/*
	 * check for preloaded domain, map
	 */

	for (d = doms.lh_first ; d != NULL ; d = d->domsl.le_next) {
		if (strcmp(domain, d->domain) == 0) break;
	}

	if (d) {
		for (m = d->dmaps.lh_first ; m != NULL ; m = m->mapsl.le_next)
			if (strcmp(map, m->map) == 0) break;
	}

	/*
	 * map found open?
	 */

	if (m) {
#ifdef DEBUG
		yplog("  ypdb_open_db: cached open: domain=%s, map=%s, db=0x%x",
			domain, map, m->db);
#endif
		CIRCLEQ_REMOVE(&maps, m, mapsq);	/* adjust LRU queue */
		CIRCLEQ_INSERT_HEAD(&maps, m, mapsq);
		*status = YP_TRUE;
		return(m->db);
	}

	/* Check for illegal charcaters */

	if (strchr(domain, '/')) {
		*status = YP_NODOM;
		return (NULL);
	}
	if (strchr(map, '/')) {
		*status = YP_NOMAP;
		return (NULL);
	}


	/*
	 * open map
	 */
#ifdef OPTDB
	i = 0;
	while (i == 0) {
#endif
		snprintf(map_path, sizeof(map_path), "%s/%s/%s", YP_DB_PATH, 
			 domain, map);
		db = ypdb_open(map_path, O_RDONLY, 0444);
#ifdef OPTDB
		if (db == NULL) {
#ifdef DEBUG
			yplog("  ypdb_open_db: errno %d (%s)",
		        errno,sys_errlist[errno]);
#endif
			if ((errno == ENFILE) || (errno == EMFILE)) {
				ypdb_close_last();
			} else {
				i = errno;
			}
		} else {
			i = 4711;
		}
	};
#endif
	*status = YP_NOMAP;		/* see note below */
	if (db == NULL) {
		if (errno == ENOENT) {
#ifdef DEBUG
			yplog("  ypdb_open_db: no map %s (domain=%s)",
			      map, domain);
#endif
			return(NULL);
		}
#ifdef DEBUG
		yplog("  ypdb_open_db: ypdb_open FAILED: map %s (domain=%s)", 
			map, domain);
#endif
		return(NULL);
	}
	
	/*
	 * note: status now YP_NOMAP
	 */

	if (d == NULL) {		/* allocate new domain? */
		d = (struct opt_domain *) malloc(sizeof(*d));
		if (d) d->domain = strdup(domain);
		if (d == NULL || d->domain == NULL) {
			yplog("  ypdb_open_db: MALLOC failed");
			ypdb_close(db);
			if (d) free(d);
			return(NULL);
		}
		LIST_INIT(&d->dmaps);
		LIST_INSERT_HEAD(&doms, d, domsl);
#ifdef DEBUG
		yplog("  ypdb_open_db: NEW DOMAIN %s", domain);
#endif
	}

	/*
	 * m must be NULL since we couldn't find a map.  allocate new one
	 */

	m = (struct opt_map *) malloc(sizeof(*m));
	if (m) {
		m->map = strdup(map);
	}
	if (m == NULL || m->map == NULL) {
		if (m) free(m);
		yplog("  ypdb_open_db: MALLOC failed");
		ypdb_close(db);
		return(NULL);
	}
	m->db = db;
	m->dom = d;
	m->host_lookup = FALSE;
	CIRCLEQ_INSERT_HEAD(&maps, m, mapsq);
	LIST_INSERT_HEAD(&d->dmaps, m, mapsl);
	if (strcmp(map, YP_HOSTNAME) == 0 || strcmp(map, YP_HOSTADDR) == 0) {
		if (!usedns) {
			k.dptr = domain_key;
			k.dsize = YP_INTERDOMAIN_LEN;
			v = ypdb_fetch(db,k);
			if (v.dptr) m->host_lookup = TRUE;
		} else {
			m->host_lookup = TRUE;
		}
	}
	m->secure = FALSE;
	k.dptr = secure_key;
	k.dsize = YP_SECURE_LEN;
	v = ypdb_fetch(db,k);
	if (v.dptr) m->secure = TRUE;
	*status = YP_TRUE;
	if (map_info) *map_info = m;
#ifdef DEBUG
	     yplog("  ypdb_open_db: NEW MAP domain=%s, map=%s, hl=%d, s=%d, db=0x%x", 
			domain, map, m->host_lookup, m->secure, m->db);
#endif
	return(m->db);
}

#if 0
/*
 * lookup host. Not needed for Rhapsody, lookupd does this stuff.
 */

ypstat
lookup_host(nametable, host_lookup, db, keystr, result)
	int	nametable;
	int	host_lookup;
	DBM	*db;
	char	*keystr;
	ypresp_val *result;
{
	struct	hostent	*host;
	struct  in_addr *addr_name;
	struct	in_addr addr_addr;
	static  char val[BUFSIZ+1]; /* match libc */
	static	hostname[MAXHOSTNAMELEN];
	char	tmpbuf[MAXHOSTNAMELEN + 20];
	char *v;
	int l;
	char	*ptr;
	
	if (!host_lookup) return(YP_NOKEY);

	if ((_res.options & RES_INIT) == 0)
		res_init();
	bcopy("b", _res.lookups, sizeof("b"));

	if (nametable) {
		host = gethostbyname(keystr);
		if (host == NULL || host->h_addrtype != AF_INET) 
			return(YP_NOKEY);
		addr_name = (struct in_addr *) *host->h_addr_list;
		v = val;
		for (; host->h_addr_list[0] != NULL; host->h_addr_list++) {
			addr_name = (struct in_addr *)host->h_addr_list[0];
			snprintf(tmpbuf,sizeof(tmpbuf), "%s %s\n",
				inet_ntoa(*addr_name), host->h_name);
			if (v - val + strlen(tmpbuf) + 1 > sizeof(val))
				break;
			strcpy(v, tmpbuf);
			v = v + strlen(tmpbuf);
		}
		result->val.valdat_val = val;
		result->val.valdat_len = v - val;
		return(YP_TRUE);
	}

	inet_aton(keystr, &addr_addr);
	host = gethostbyaddr((char *) &addr_addr, sizeof(addr_addr), AF_INET);
	if (host == NULL) return(YP_NOKEY);

	strncpy((char *)hostname, host->h_name, sizeof(hostname) - 1);
	hostname[sizeof(hostname) - 1] = '\0';
	host = gethostbyname((char *)hostname);
	if (host == NULL) return(YP_NOKEY);

	l = 0;
	for(; host->h_addr_list[0] != NULL; host->h_addr_list++)
		if (!bcmp(host->h_addr_list[0], &addr_addr, sizeof(addr_addr)))
			l++;
	if (l == 0) {
		yplog("lookup_host: address %s not listed for host %s\n",
		       inet_ntoa(addr_addr), hostname);
		syslog(LOG_NOTICE,
		       "ypserv: address %s not listed for host %s\n",
		       inet_ntoa(addr_addr), hostname);
		return(YP_NOKEY);
	}

	snprintf(val,sizeof(val),"%s %s",keystr,host->h_name);
	l = strlen(val);
	v = val + l;
	while ((ptr = *(host->h_aliases)) != NULL) {
		l = strlen(ptr);
		if ((v - val) + l + 1 > BUFSIZ)
			break;
		strcpy(v, " ");
		v += 1;
		strcpy(v, ptr);
		v += l;
		host->h_aliases++;
	}
	result->val.valdat_val = val;
	result->val.valdat_len = v - val;

	return(YP_TRUE);
}
#endif 

ypresp_val
ypdb_get_record(domain, map, key, ypprivate)
	domainname	domain;
	mapname		map;
	keydat		key;
	int		ypprivate;
{
	static	ypresp_val res;
/*	static	char keystr[YPMAXRECORD+1]; */
	DBM	*db;
	datum	k,v;
	int	host_lookup;
	struct opt_map *map_info = NULL;

	bzero((char *)&res, sizeof(res));
	
	db = ypdb_open_db(domain, map, &res.stat, &map_info);
	if (!db || res.stat < 0) 
		return(res);
	if (map_info)
		host_lookup = map_info->host_lookup;

	k.dptr = key.keydat_val;
	k.dsize = key.keydat_len;
	
	if (yp_private(k,ypprivate)) {
		res.stat = YP_NOKEY;
		goto done;
	}

	v = ypdb_fetch(db, k);

	/* lookupd does DNS resolution, not ypserv. */
	if (v.dptr == NULL) {
		res.stat = YP_NOKEY;
		res.val.valdat_val = NULL;
		res.val.valdat_len = 0;
	} else {
		res.val.valdat_val = v.dptr;
		res.val.valdat_len = v.dsize;
	}

done:
	ypdb_close_db(db);
	return(res);
	
}

ypresp_key_val
ypdb_get_first(domain, map, ypprivate)
	domainname domain;
	mapname map;
	int ypprivate;
{
	static ypresp_key_val res;
	DBM	*db;
	datum	k,v;

	bzero((char *)&res, sizeof(res));
	
	db = ypdb_open_db(domain, map, &res.stat, NULL);

	if (res.stat >= 0) {

	  k = ypdb_firstkey(db);
	  
	  while (yp_private(k,ypprivate)) {
	    k = ypdb_nextkey(db);
	  };
	  
	  if (k.dptr == NULL) {
	    res.stat = YP_NOKEY;
	  } else {
	    res.key.keydat_val = k.dptr;
	    res.key.keydat_len = k.dsize;
	    v = ypdb_fetch(db,k);
	    if (v.dptr == NULL) {
	      res.stat = YP_NOKEY;
	    } else {
	      res.val.valdat_val = v.dptr;
	      res.val.valdat_len = v.dsize;
	    }
	  }
	}

	ypdb_close_db(db);
	
	return (res);
}

ypresp_key_val
ypdb_get_next(domain, map, key, ypprivate)
	domainname domain;
	mapname map;
	keydat key;
	int ypprivate;
{
	static ypresp_key_val res;
	DBM	*db;
	datum	k,v,n;

	bzero((char *)&res, sizeof(res));
	
	db = ypdb_open_db(domain, map, &res.stat, NULL);
	
	if (res.stat >= 0) {

	  n.dptr = key.keydat_val;
	  n.dsize = key.keydat_len;
	  v.dptr = NULL;
	  v.dsize = 0;
	  k.dptr = NULL;
	  k.dsize = 0;

	  n = ypdb_setkey(db,n);

	  if (n.dptr != NULL) {
	    k = ypdb_nextkey(db);
	  } else {
	    k.dptr = NULL;
	  };

	  if (k.dptr != NULL) {
	    while (yp_private(k,ypprivate)) {
	      k = ypdb_nextkey(db);
	    };
	  };

	  if (k.dptr == NULL) {
	    res.stat = YP_NOMORE;
	  } else {
	    res.key.keydat_val = k.dptr;
	    res.key.keydat_len = k.dsize;
	    v = ypdb_fetch(db,k);
	    if (v.dptr == NULL) {
	      res.stat = YP_NOMORE;
	    } else {
	      res.val.valdat_val = v.dptr;
	      res.val.valdat_len = v.dsize;
	    }
	  }
	}

	ypdb_close_db(db);
	
	return (res);
}

ypresp_order
ypdb_get_order(domain, map)
	domainname domain;
	mapname map;
{
	static ypresp_order res;
	static char   *order_key = YP_LAST_KEY;
	char   order[MAX_LAST_LEN+1];
	DBM	*db;
	datum	k,v;

	bzero((char *)&res, sizeof(res));
	
	db = ypdb_open_db(domain, map, &res.stat, NULL);
	
	if (res.stat >= 0) {

	  k.dptr = order_key;
	  k.dsize = YP_LAST_LEN;

	  v = ypdb_fetch(db,k);
	  if (v.dptr == NULL) {
	    res.stat = YP_NOKEY;
	  } else {
	    strncpy(order, v.dptr, v.dsize);
	    order[v.dsize] = '\0';
	    res.ordernum = (u_int32_t)atol(order);
	  }
	}

	ypdb_close_db(db);
	
	return (res);
}

ypresp_master
ypdb_get_master(domain, map)
	domainname domain;
	mapname map;
{
	static ypresp_master res;
	static char   *master_key = YP_MASTER_KEY;
	static char   master[MAX_MASTER_LEN+1];
	DBM	*db;
	datum	k,v;

	bzero((char *)&res, sizeof(res));
	
	db = ypdb_open_db(domain, map, &res.stat, NULL);
	
	if (res.stat >= 0) {

	  k.dptr = master_key;
	  k.dsize = YP_MASTER_LEN;

	  v = ypdb_fetch(db,k);
	  if (v.dptr == NULL) {
	    res.stat = YP_NOKEY;
	  } else {
	    strncpy(master, v.dptr, v.dsize);
	    master[v.dsize] = '\0';
	    res.peer = (peername) &master;
	  }
	}

	ypdb_close_db(db);
	
	return (res);
}

bool_t
ypdb_xdr_get_all(xdrs, req)
	XDR *xdrs;
	ypreq_nokey *req;
{
	static ypresp_all resp;
	DBM	*db;
	datum	k,v;

	bzero((char *)&resp, sizeof(resp));
	
	/*
	 * open db, and advance past any private keys we may see
	 */

	db = ypdb_open_db(req->domain, req->map, 
			&resp.ypresp_all_u.val.stat, NULL);
	if (!db || resp.ypresp_all_u.val.stat < 0) 
		return(FALSE);
	k = ypdb_firstkey(db);
	while (yp_private(k,FALSE)) {
		k = ypdb_nextkey(db);
	};
	
	while(1) {
		
		if (k.dptr == NULL) 
			break;

		v = ypdb_fetch(db,k);

		if (v.dptr == NULL) 
			break;

		resp.more = TRUE;
		resp.ypresp_all_u.val.stat = YP_TRUE;
		resp.ypresp_all_u.val.key.keydat_val = k.dptr;
		resp.ypresp_all_u.val.key.keydat_len = k.dsize;
		resp.ypresp_all_u.val.val.valdat_val = v.dptr;
		resp.ypresp_all_u.val.val.valdat_len = v.dsize;
			
		if (!xdr_ypresp_all(xdrs, &resp)) {
#ifdef DEBUG
			yplog("  ypdb_xdr_get_all: xdr_ypresp_all failed");
#endif					
			return(FALSE);
		}
			
		/* advance past private keys */
		k = ypdb_nextkey(db);
		while (yp_private(k,FALSE)) {
			k = ypdb_nextkey(db);
		}
	}
		
	bzero((char *)&resp, sizeof(resp));
	resp.ypresp_all_u.val.stat = YP_NOKEY;
	resp.more = FALSE;
	
	if (!xdr_ypresp_all(xdrs, &resp)) {
#ifdef DEBUG
		yplog("  ypdb_xdr_get_all: final xdr_ypresp_all failed");
#endif
		return(FALSE);
	}
		
	ypdb_close_db(db);
	
	return (TRUE);
}

int
ypdb_secure(domain, map)
	domainname	domain;
	mapname		map;
{
	static	ypresp_val res;
	DBM	*db;
	int	secure;
	struct opt_map *map_info = NULL;

	bzero((char *)&res, sizeof(res));
	secure = FALSE;

	db = ypdb_open_db(domain, map, &res.stat, &map_info);
	if (!db || res.stat < 0) 
		return(secure);			/* ? */
	if (map_info)
		secure = map_info->secure;

	ypdb_close_db(db);
	return(secure);
}

