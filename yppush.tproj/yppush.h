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
/*	$OpenBSD: yppush.h,v 1.3 1997/07/25 20:12:32 mickey Exp $ */

/*
 * Copyright (c) 1996 Mats O Jansson <moj@stacken.kth.se>
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

#ifndef _YPPUSH_H_RPCGEN
#define _YPPUSH_H_RPCGEN

#include <rpc/rpc.h>


enum yppush_status {
	YPPUSH_SUCC = 1,
	YPPUSH_AGE = 2,
	YPPUSH_NOMAP = -1,
	YPPUSH_NODOM = -2,
	YPPUSH_RSRC = -3,
	YPPUSH_RPC = -4,
	YPPUSH_MADDR = -5,
	YPPUSH_YPERR = -6,
	YPPUSH_BADARGS = -7,
	YPPUSH_DBM = -8,
	YPPUSH_FILE = -9,
	YPPUSH_SKEW = -10,
	YPPUSH_CLEAR = -11,
	YPPUSH_FORCE = -12,
	YPPUSH_XFRERR = -13,
	YPPUSH_REFUSED = -14,
};
typedef enum yppush_status yppush_status;
#ifdef __cplusplus 
extern "C" bool_t xdr_yppush_status(XDR *, yppush_status*);
#elif defined(__STDC__)
extern  bool_t xdr_yppush_status(XDR *, yppush_status*);
#else /* Old Style C */ 
bool_t xdr_yppush_status();
#endif /* Old Style C */ 


struct yppushresp_xfr {
	u_int transid;
	yppush_status status;
};
typedef struct yppushresp_xfr yppushresp_xfr;
#ifdef __cplusplus 
extern "C" bool_t xdr_yppushresp_xfr(XDR *, yppushresp_xfr*);
#elif defined(__STDC__)
extern  bool_t xdr_yppushresp_xfr(XDR *, yppushresp_xfr*);
#else /* Old Style C */ 
bool_t xdr_yppushresp_xfr();
#endif /* Old Style C */ 


#define YPPUSH_XFRRESPPROG ((u_long)0x40000000)
#define YPPUSH_XFRRESPVERS ((u_long)1)

#ifdef __cplusplus
#define YPPUSHPROC_NULL ((u_long)0)
extern "C" void * yppushproc_null_1(void *, CLIENT *);
extern "C" void * yppushproc_null_1_svc(void *, struct svc_req *);
#define YPPUSHPROC_XFRRESP ((u_long)1)
extern "C" void * yppushproc_xfrresp_1(yppushresp_xfr *, CLIENT *);
extern "C" void * yppushproc_xfrresp_1_svc(yppushresp_xfr *, struct svc_req *);

#elif defined(__STDC__)
#define YPPUSHPROC_NULL ((u_long)0)
extern  void * yppushproc_null_1(void *, CLIENT *);
extern  void * yppushproc_null_1_svc(void *, struct svc_req *);
#define YPPUSHPROC_XFRRESP ((u_long)1)
extern  void * yppushproc_xfrresp_1(yppushresp_xfr *, CLIENT *);
extern  void * yppushproc_xfrresp_1_svc(yppushresp_xfr *, struct svc_req *);

#else /* Old Style C */ 
#define YPPUSHPROC_NULL ((u_long)0)
extern  void * yppushproc_null_1();
extern  void * yppushproc_null_1_svc();
#define YPPUSHPROC_XFRRESP ((u_long)1)
extern  void * yppushproc_xfrresp_1();
extern  void * yppushproc_xfrresp_1_svc();
#endif /* Old Style C */ 

#endif /* !_YPPUSH_H_RPCGEN */
