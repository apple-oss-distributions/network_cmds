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
/*	$OpenBSD: acl.c,v 1.5 1997/08/05 09:26:55 maja Exp $ */

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
static char rcsid[] = "$OpenBSD: acl.c,v 1.5 1997/08/05 09:26:55 maja Exp $";
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <netdb.h>
#include "acl.h"

#define TRUE 1
#define FALSE 0

static	struct aclent *acl_root = NULL;

static int acl_read_line(fp, buf, size)
FILE *fp;
char *buf;
int size;
{
  int   len = 0;
  char *c,*p,l;

  /* Read a line, and remove any comment, trim space */

  do {
    while (fgets(buf, size, fp)) {
      c = buf;
      while(*c != '\0') {
	if ((*c == '#') || (*c == '\n')) {
	  *c = '\0';
	} else {
	  c++;
	}
      }

      c = p = buf; l = ' ';
      while(*c != '\0') {
	if ((isspace(l) != 0) && (isspace(*c) != 0)) {
	  c++;
	} else {
	  l = *c++; *p = l; p++;
	}
      }
      *p = '\0';
      
      if (p != buf) {
	--p;
	if (isspace(*p) != 0) {
	  *p = '\0';
	}
      }

      len = strlen(buf);
      return len + 1;
    }
  } while (size > 0 && !feof(fp));
  
  return len;
}

int
acl_check_host(addr)
struct in_addr *addr;
{
  struct aclent *p;
  
  p = acl_root;
  while (p != NULL) {
    if ((addr->s_addr & p->s_mask) == p->s_addr) {
      return(p->allow);
    }
    p = p->next;
  }
  return(TRUE);
}

void
acl_add_net(allow,addr,mask)
int	allow;
struct in_addr *addr,*mask;
{
  
  struct aclent *acl,*p;
  
  acl = (struct aclent *) malloc((unsigned) sizeof(struct aclent));
  
  acl->next   = NULL;
  acl->allow  = allow;
  acl->s_addr = addr->s_addr;
  acl->s_mask = mask->s_addr;
  
  if (acl_root == NULL) {
    acl_root = acl;
  } else {
    p = acl_root;
    while (p->next != NULL)
      p = p->next;
    p->next = acl;
  }
  
} 

void
acl_add_host(allow,addr)
int	allow;
struct in_addr *addr;
{
  	struct in_addr mask;

	mask.s_addr = htonl(0xffffffff);
	
	acl_add_net(allow,addr,&mask);
}

int
acl_init(file)
char *file;
{
  char	 data_line[1024];
  int	 line_no = 0;
  int	 len,i;
  int	 allow = TRUE;
  int	 error_cnt = 0;
  char	*p,*k;
  int	 state;
  struct in_addr addr,mask,*host_addr;
  struct hostent *host;
  struct netent  *net;
  FILE  *data_file = NULL;
  
  if (file != NULL) {
    data_file = fopen(file,"r");
  };

  while ((data_file != NULL) &&
	 (acl_read_line(data_file,data_line,sizeof(data_line)))) {
    
    line_no++;
    
    len = strlen(data_line);
    if (len == 0) {
      continue;
    }

    p = (char *) &data_line;

    /* State 1: Initial State */

    state = ACLS_INIT;
    addr.s_addr = mask.s_addr = 0;

    k = p; i = 0;				/* save start of verb */
    while ((*p != '\0') &&
	   (!isspace(*p = tolower(*p)))) {
      p++; i++;
    };

    if (*p != '\0') {
      *p++ = '\0';
    }

    if (strcmp(k,"allow") == 0) {
      allow = TRUE;
      state = ACLS_ALLOW;
    }

    if (strcmp(k,"deny") == 0) {
      allow = FALSE;
      state = ACLS_DENY;
    }

    if (state == ACLS_INIT) {
      state = ACLE_UVERB;
    }

    /* State 2: allow row */
    /* State 3: deny row */

    if ((*p != '\0') &&
	((state == ACLS_ALLOW) || (state == ACLS_DENY))) {
      
      k = p; i = 0;				/* save start of verb */
      while ((*p != '\0') &&
	     (!isspace(*p = tolower(*p)))) {
	p++; i++;
      };
      
      if (*p != '\0') {
	*p++ = '\0';
      }

      if (strcmp(k,"all") == 0) {
	state = state + ACLD_ALL;
      }

      if (strcmp(k,"host") == 0) {
	state = state + ACLD_HOST;
      }

      if (strcmp(k,"net") == 0) {
	state = state + ACLD_NET;
      }

      if ((state == ACLS_ALLOW) || (state == ACLS_DENY)) {
	state = ACLE_U2VERB;
      }
      
    }

    if ((state == ACLS_ALLOW) || (state == ACLS_DENY)) {
      state = ACLE_UEOL;
    }

    /* State 4 & 5: all state, remove any comment */

    if ((*p == '\0') &&
	((state == ACLS_ALLOW_ALL) || (state == ACLS_DENY_ALL))) {
      acl_add_net(allow,&addr,&mask);
      state = ACLE_OK;
    }
      
    /* State 6 & 7: host line */
    /* State 8 & 9: net line */

    if ((*p != '\0') &&
	(state >= ACLS_ALLOW_HOST) && (state <= ACLS_DENY_NET)) {
      
      k = p; i = 0;				/* save start of verb */
      while ((*p != '\0') &&
	     (!isspace(*p = tolower(*p)))) {
	p++; i++;
      };
      
      if (*p != '\0') {
	*p++ = '\0';
      }
      
      if ((state == ACLS_ALLOW_HOST) || (state == ACLS_DENY_HOST)) {
	if ((*k >= '0') && (*k <= '9')) {
	  (void)inet_aton(k,&addr);
	  acl_add_host(allow,&addr);
	  state = state + ACLD_HOST_DONE;
        } else {
	  host = gethostbyname(k);
	  if (host == NULL) {
	    state = ACLE_NOHOST;
	  } else {
	    if (host->h_addrtype == AF_INET) {
	      while ((host_addr = (struct in_addr *) *host->h_addr_list++)
		     != NULL)
		acl_add_host(allow,host_addr);
	    }
	    state = state + ACLD_HOST_DONE;
	  }
	}
      }

      if ((state == ACLS_ALLOW_NET) || (state == ACLS_DENY_NET)) {
	if ((*k >= '0') && (*k <= '9')) {
	  (void)inet_aton(k,&addr);
	  state = state + ACLD_NET_DONE;
        } else {
	  net = getnetbyname(k);
	  if (net == NULL) {
	    state = ACLE_NONET;
	  } else {
	    addr.s_addr = ntohl(net->n_net);
	    state = state + ACLD_NET_DONE;
	  }
	}
      }

    }

    if ((state >= ACLS_ALLOW_HOST) && (state <= ACLS_DENY_NET)) {
      state = ACLE_UEOL;
    }

    /* State 10 & 11: allow/deny host line */

    if ((*p == '\0') &&
	((state == ACLS_ALLOW_HOST_DONE) || (state == ACLS_DENY_HOST_DONE))) {
      state = ACLE_OK;
    }
      
    /* State 12 & 13: allow/deny net line */

    if ((*p == '\0') &&
	((state == ACLS_ALLOW_NET_DONE) || (state == ACLS_DENY_NET_DONE))) {
      mask.s_addr = htonl(0xffffff00);
      if (ntohl(addr.s_addr) < 0xc0000000) {
	mask.s_addr = htonl(0xffff0000);
      }
      if (ntohl(addr.s_addr) < 0x80000000) {
	mask.s_addr = htonl(0xff000000);
      }
      acl_add_net(allow,&addr,&mask);
      state = ACLE_OK;
    }

    if ((*p != '\0') &&
	((state == ACLS_ALLOW_NET_DONE) || (state == ACLS_DENY_NET_DONE))) {
      
      k = p; i = 0;				/* save start of verb */
      while ((*p != '\0') &&
	     (!isspace(*p = tolower(*p)))) {
	p++; i++;
      };
      
      if (*p != '\0') {
	*p++ = '\0';
      }

      if (strcmp(k,"netmask") == 0) {
	state = state + ACLD_NET_MASK;
      }

      if ((state == ACLS_ALLOW_NET_DONE) || (state == ACLS_DENY_NET_DONE)) {
	state = ACLE_NONETMASK;
      }
      
    }

    /* State 14 & 15: allow/deny net netmask line */

    if ((*p != '\0') &&
	((state == ACLS_ALLOW_NET_MASK) || (state == ACLS_DENY_NET_MASK))) {
      
      k = p; i = 0;				/* save start of verb */
      while ((*p != '\0') &&
	     (!isspace(*p = tolower(*p)))) {
	p++; i++;
      };
      
      if (*p != '\0') {
	*p++ = '\0';
      }

      if ((state == ACLS_ALLOW_NET_MASK) || (state == ACLS_DENY_NET_MASK)) {
	if ((*k >= '0') && (*k <= '9')) {
	  (void)inet_aton(k,&mask);
	  state = state + ACLD_NET_EOL;
        } else {
	  net = getnetbyname(k);
	  if (net == NULL) {
	    state = ACLE_NONET;
	  } else {
	    mask.s_addr = ntohl(net->n_net);
	    state = state + ACLD_NET_EOL;
	  }
	}
      }

    }

    if ((state == ACLS_ALLOW_NET_MASK) || (state == ACLS_DENY_NET_MASK)) {
      state = ACLE_UEOL;
    }

    /* State 16 & 17: allow/deny host line */

    if ((*p == '\0') &&
	((state == ACLS_ALLOW_NET_EOL) || (state == ACLS_DENY_NET_EOL))) {
      acl_add_net(allow,&addr,&mask);
      state = ACLE_OK;
    }
      
    switch (state) {
    case  ACLE_NONETMASK:
      fprintf(stderr,"acl: excpected \"netmask\" missing at line %d\n",line_no);
      break;
    case  ACLE_NONET:
      error_cnt++;
      fprintf(stderr,"acl: unknown network at line %d\n",line_no);
      break;
    case  ACLE_NOHOST:
      error_cnt++;
      fprintf(stderr,"acl: unknown host at line %d\n",line_no);
      break;
    case  ACLE_UVERB:
      error_cnt++;
      fprintf(stderr,"acl: unknown verb at line %d\n",line_no);
      break;
    case ACLE_U2VERB:
      error_cnt++;
      fprintf(stderr,"acl: unknown secondary verb at line %d\n",line_no);
      break;
    case ACLE_UEOL:
      error_cnt++;
      fprintf(stderr,"acl: unexpected end of line at line %d\n",line_no);
      break;
    case ACLE_OK:
      break;
    default:
      error_cnt++;
      fprintf(stderr,"acl: unexpected state %d %s\n",state,k);
    }

  }

  if (data_file != NULL) {
    (void)fflush(stderr);
    (void)fclose(data_file);
  }

  /* Always add a last allow all if file don't exists or */
  /* the file doesn't cover all cases.                   */
  
  addr.s_addr = mask.s_addr = 0;
  allow = TRUE;
  acl_add_net(allow,&addr,&mask);

  return(error_cnt);

}

int
acl_securenet(file)
char *file;
{
  char	 data_line[1024];
  int	 line_no = 0;
  int	 len,i;
  int	 allow = TRUE;
  int	 error_cnt = 0;
  char	*p,*k;
  int	 state;
  struct in_addr addr,mask;
  struct netent  *net;
  FILE  *data_file = NULL;
  
  if (file != NULL) {
    data_file = fopen(file,"r");
  };

  /* Always add a localhost allow first, to be compatable with sun */
  
  addr.s_addr = htonl(0x7f000001);
  mask.s_addr = htonl(0xffffffff);
  allow = TRUE;
  acl_add_net(allow,&addr,&mask);

  while ((data_file != NULL) &&
	 (acl_read_line(data_file,data_line,sizeof(data_line)))) {
    
    line_no++;
    
    len = strlen(data_line);
    if (len == 0) {
      continue;
    }

    p = (char *) &data_line;

    /* State 1: Initial State */

    state = ACLS_INIT;
    addr.s_addr = mask.s_addr = 0;

    k = p; i = 0;				/* save start of verb */
    while ((*p != '\0') &&
	   (!isspace(*p = tolower(*p)))) {
      p++; i++;
    };
    
    if (*p != '\0') {
      *p++ = '\0';
      state = ACLS_ALLOW_NET_MASK;
    }
    
    if (state == ACLS_INIT) {
      state = ACLE_UEOL;
    }

    if (state == ACLS_ALLOW_NET_MASK) {
      
      if ((*k >= '0') && (*k <= '9')) {
	(void)inet_aton(k,&mask);
	state = ACLS_ALLOW_NET;
      } else {
	net = getnetbyname(k);
	if (net == NULL) {
	  state = ACLE_NONET;
	} else {
	  mask.s_addr = ntohl(net->n_net);
	  state = ACLS_ALLOW_NET;
	}
      }
      
      k = p; i = 0;				/* save start of verb */
      while ((*p != '\0') &&
	     (!isspace(*p = tolower(*p)))) {
	p++; i++;
      };
      
      if (*p != '\0') {
	*p++ = '\0';
      }
    }
    
    if ((state == ACLS_ALLOW_NET_MASK)) {
      state = ACLE_UEOL;
    }

    if (state == ACLS_ALLOW_NET) {
      
      if ((*k >= '0') && (*k <= '9')) {
	(void)inet_aton(k,&addr);
	state = ACLS_ALLOW_NET_EOL;
      } else {
	net = getnetbyname(k);
	if (net == NULL) {
	  state = ACLE_NONET;
	} else {
	  addr.s_addr = ntohl(net->n_net);
	  state = ACLS_ALLOW_NET_EOL;
	}
      }
    }
      
    if ((state == ACLS_ALLOW_NET)) {
      state = ACLE_UEOL;
    }

    if ((*p == '\0') &&	(state == ACLS_ALLOW_NET_EOL)) {
      acl_add_net(allow,&addr,&mask);
      state = ACLE_OK;
    }
      
    switch (state) {
    case  ACLE_NONET:
      error_cnt++;
      fprintf(stderr,"securenet: unknown network at line %d\n",line_no);
      break;
    case ACLE_UEOL:
      error_cnt++;
      fprintf(stderr,"securenet: unexpected end of line at line %d\n",line_no);
      break;
    case ACLE_OK:
      break;
    default:
      error_cnt++;
      fprintf(stderr,"securenet: unexpected state %d %s\n",state,k);
    }

  }

  if (data_file != NULL) {
    (void)fflush(stderr);
    (void)fclose(data_file);
    
    /* Always add a last deny all if file exists */
    
    addr.s_addr = mask.s_addr = 0;
    allow = FALSE;
    acl_add_net(allow,&addr,&mask);

  }

  /* Always add a last allow all if file don't exists */
  
  addr.s_addr = mask.s_addr = 0;
  allow = TRUE;
  acl_add_net(allow,&addr,&mask);

  return(error_cnt);

}

void
acl_reset()
{
	struct aclent *p;

	while (acl_root != NULL) {
		p = acl_root->next;
		free(acl_root);
		acl_root = p;
	}
}
