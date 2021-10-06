/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*	$OpenBSD: acl.h,v 1.4 1996/06/30 19:46:05 maja Exp $ */

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

#ifndef _ACL_H_
#define _ACL_H_

#define ACLD_ALL		2
#define ACLD_HOST		4
#define ACLD_NET		6
#define ACLD_HOST_DONE		4
#define ACLD_NET_DONE		4
#define ACLD_NET_MASK		2
#define ACLD_NET_EOL		2

#define ACLS_INIT		1
#define ACLS_ALLOW		2
#define ACLS_DENY		3
#define ACLS_ALLOW_ALL		ACLS_ALLOW+ACLD_ALL		  /*  4 */
#define ACLS_DENY_ALL		ACLS_DENY+ACLD_ALL		  /*  5 */
#define ACLS_ALLOW_HOST		ACLS_ALLOW+ACLD_HOST		  /*  6 */
#define ACLS_DENY_HOST		ACLS_DENY+ACLD_HOST		  /*  7 */
#define ACLS_ALLOW_NET		ACLS_ALLOW+ACLD_NET		  /*  8 */
#define ACLS_DENY_NET		ACLS_DENY+ACLD_NET		  /*  9 */
#define ACLS_ALLOW_HOST_DONE	ACLS_ALLOW_HOST+ACLD_HOST_DONE	  /* 10 */
#define ACLS_DENY_HOST_DONE	ACLS_DENY_HOST+ACLD_HOST_DONE	  /* 11 */
#define ACLS_ALLOW_NET_DONE	ACLS_ALLOW_NET+ACLD_NET_DONE	  /* 12 */
#define ACLS_DENY_NET_DONE	ACLS_DENY_NET+ACLD_NET_DONE	  /* 13 */
#define ACLS_ALLOW_NET_MASK	ACLS_ALLOW_NET_DONE+ACLD_NET_MASK /* 14 */
#define ACLS_DENY_NET_MASK	ACLS_DENY_NET_DONE+ACLD_NET_MASK  /* 15 */
#define ACLS_ALLOW_NET_EOL	ACLS_ALLOW_NET_MASK+ACLD_NET_EOL  /* 16 */
#define ACLS_DENY_NET_EOL	ACLS_DENY_NET_MASK+ACLD_NET_EOL   /* 17 */

#define ACLE_NONETMASK		18
#define ACLE_NONET		19
#define ACLE_NOHOST		20
#define ACLE_UVERB		21
#define ACLE_U2VERB		22
#define ACLE_UEOL		23
#define ACLE_OK			24

struct	aclent {
struct	aclent	*next;
	int	allow;
	u_long	s_addr;
	u_long	s_mask;
};

__BEGIN_DECLS
int		yp_acl_check_host __P((struct in_addr *));
int		yp_acl_init __P((char *));
int		yp_acl_securenet __P((char *));
void		yp_acl_reset __P((void));
__END_DECLS

#endif /* !_ACL_H_ */


