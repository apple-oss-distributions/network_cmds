/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/*-
 * Written by Atsushi Murai <amurai@spec.co.jp>
 * Copyright (c) 1998, System Planning and Engineering Co.
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Based upon:
 * $FreeBSD: src/lib/libalias/alias_nbt.c,v 1.4.2.3 2001/08/01 09:52:26 obrien Exp $
 *
 *  TODO:
 *       oClean up. 
 *       oConsidering for word alignment for other platform.
 */
/*
    alias_nbt.c performs special processing for NetBios over TCP/IP
    sessions by UDP.

    Initial version:  May, 1998  (Atsushi Murai <amurai@spec.co.jp>)

    See HISTORY file for record of revisions.
*/

/* Includes */
#include <ctype.h>
#include <stdio.h> 
#include <string.h>
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "alias_local.h"

typedef struct {
	struct in_addr		oldaddr;
	u_short 			oldport;
	struct in_addr		newaddr;
	u_short 			newport;
	u_short 			*uh_sum;
} NBTArguments;

typedef struct {
	unsigned char   type;
	unsigned char   flags;
	u_short  		id;
	struct in_addr  source_ip;
	u_short			source_port;
	u_short			len;
	u_short			offset;
} NbtDataHeader;

#define OpQuery		0
#define OpUnknown	4
#define OpRegist	5
#define OpRelease	6
#define OpWACK		7
#define OpRefresh	8
typedef struct {
	u_short			nametrid;
	u_short 		dir:1, opcode:4, nmflags:7, rcode:4;
	u_short			qdcount;
	u_short			ancount;
	u_short			nscount;
	u_short			arcount;
} NbtNSHeader;

#define FMT_ERR		0x1
#define SRV_ERR		0x2
#define IMP_ERR		0x4
#define RFS_ERR		0x5
#define ACT_ERR		0x6
#define CFT_ERR		0x7


#ifdef DEBUG
static void PrintRcode( u_char rcode )  {

	switch (rcode) {
		case FMT_ERR:
			printf("\nFormat Error.");
		case SRV_ERR:
			printf("\nSever failure.");
		case IMP_ERR:
			printf("\nUnsupported request error.\n");
		case RFS_ERR:
			printf("\nRefused error.\n");
		case ACT_ERR:
			printf("\nActive error.\n");
		case CFT_ERR:
			printf("\nName in conflict error.\n");
		default:
			printf("\n???=%0x\n", rcode );

	}	
}
#endif


/* Handling Name field */
static u_char *AliasHandleName ( u_char *p, char *pmax ) {

	u_char *s;
	u_char c;
	int		compress;

	/* Following length field */

	if (p == NULL || (char *)p >= pmax)
		return(NULL);

	if (*p & 0xc0 ) {
		p = p + 2;
		if ((char *)p > pmax)
			return(NULL);
		return ((u_char *)p);
	}
	while ( ( *p & 0x3f) != 0x00 ) {
		s = p + 1;
		if ( *p == 0x20 )
			compress = 1;
		else
			compress = 0;
		
	 	/* Get next length field */
		p = (u_char *)(p + (*p & 0x3f) + 1);
		if ((char *)p > pmax) {
			p = NULL;
			break;
		}
#ifdef DEBUG
		printf(":");
#endif
		while (s < p) {
			if ( compress == 1 ) {
				c = (u_char )(((((*s & 0x0f) << 4) | (*(s+1) & 0x0f)) - 0x11));
#ifdef DEBUG
				if (isprint( c ) )
					printf("%c", c );
				else
					printf("<0x%02x>", c );
#endif
				s +=2;
			} else {
#ifdef DEBUG
				printf("%c", *s);
#endif
				s++;
			}
		}
#ifdef DEBUG
		printf(":");
#endif
		fflush(stdout);
    }

	/* Set up to out of Name field */
	if (p == NULL || (char *)p >= pmax)
	    p = NULL;
	else
	    p++;
	return ((u_char *)p);
}

/* 
 * NetBios Datagram Handler (IP/UDP)
 */
#define DGM_DIRECT_UNIQ		0x10
#define DGM_DIRECT_GROUP	0x11
#define DGM_BROADCAST		0x12
#define DGM_ERROR			0x13
#define DGM_QUERY			0x14
#define DGM_POSITIVE_RES	0x15
#define DGM_NEGATIVE_RES	0x16

int AliasHandleUdpNbt(
	struct ip 		  	*pip,	 /* IP packet to examine/patch */
	struct alias_link 	*link,
	struct in_addr		*alias_address,
    u_short 		alias_port
) {
    struct udphdr *	uh;
    NbtDataHeader 	*ndh;
    u_char		*p = NULL;
    char		*pmax;
        
    /* Calculate data length of UDP packet */
    uh =  (struct udphdr *) ((char *) pip + (pip->ip_hl << 2));
    pmax = (char *)uh + ntohs( uh->uh_ulen );

	ndh = (NbtDataHeader *)((char *)uh + (sizeof (struct udphdr)));
    if ((char *)(ndh + 1) > pmax)
	    return(-1);
#ifdef DEBUG
	printf("\nType=%02x,", ndh->type );
#endif
	switch ( ndh->type ) {
		case DGM_DIRECT_UNIQ:
		case DGM_DIRECT_GROUP:
		case DGM_BROADCAST:
			p = (u_char *)ndh + 14;
		    p = AliasHandleName ( p, pmax ); /* Source Name */
		    p = AliasHandleName ( p, pmax ); /* Destination Name */
			break;
		case DGM_ERROR:
			p = (u_char *)ndh + 11;
			break;
		case DGM_QUERY:
		case DGM_POSITIVE_RES:
		case DGM_NEGATIVE_RES:
			p = (u_char *)ndh + 10;
		    p = AliasHandleName ( p, pmax ); /* Destination Name */
			break;
	}
    if (p == NULL || (char *)p > pmax)
	    p = NULL;
#ifdef DEBUG
	printf("%s:%d-->", inet_ntoa(ndh->source_ip), ntohs(ndh->source_port) );
#endif
	/* Doing a IP address and Port number Translation */
	if ( uh->uh_sum != 0 ) {
		int				acc;
		u_short			*sptr;
		acc  = ndh->source_port;
		acc -= alias_port;
		sptr = (u_short *) &(ndh->source_ip);
		acc += *sptr++;
		acc += *sptr;
		sptr = (u_short *) alias_address;
		acc -= *sptr++;
		acc -= *sptr;
		ADJUST_CHECKSUM(acc, uh->uh_sum);
	}
    ndh->source_ip = *alias_address;
    ndh->source_port = alias_port;
#ifdef DEBUG
	printf("%s:%d\n", inet_ntoa(ndh->source_ip), ntohs(ndh->source_port) );
	fflush(stdout);
#endif
    return((p == NULL) ? -1 : 0);
}
/* Question Section */
#define QS_TYPE_NB		0x0020
#define QS_TYPE_NBSTAT	0x0021
#define QS_CLAS_IN		0x0001
typedef struct {
	u_short	type;	/* The type of Request */
	u_short	class;	/* The class of Request */
} NBTNsQuestion;

static u_char *
AliasHandleQuestion(
    u_short count,
							NBTNsQuestion *q,
    char *pmax,
							NBTArguments  *nbtarg)
{

	while ( count != 0 ) {
		/* Name Filed */
		q = (NBTNsQuestion *)AliasHandleName((u_char *)q, pmax);

		if (q == NULL || (char *)(q + 1) > pmax) {
			q = NULL;
			break;
		}

		/* Type and Class filed */
		switch ( ntohs(q->type) ) {
			case QS_TYPE_NB:
			case QS_TYPE_NBSTAT:
				q= q+1;
			break;
			default:
#ifdef DEBUG
				printf("\nUnknown Type on Question %0x\n", ntohs(q->type) );
#endif
			break;
		}
		count--;
	}

	/* Set up to out of Question Section */
	return ((u_char *)q);
}

/* Resource Record */
#define RR_TYPE_A		0x0001
#define RR_TYPE_NS		0x0002
#define RR_TYPE_NULL	0x000a
#define RR_TYPE_NB		0x0020
#define RR_TYPE_NBSTAT	0x0021
#define RR_CLAS_IN		0x0001
#define SizeOfNsResource	8
typedef struct {
 	u_short type;
 	u_short class;
 	unsigned int ttl;
 	u_short rdlen;
} NBTNsResource;

#define SizeOfNsRNB			6
typedef struct {
	u_short g:1, ont:2, resv:13;
	struct	in_addr	addr;
} NBTNsRNB;

static u_char *
AliasHandleResourceNB( 
    NBTNsResource *q,
    char *pmax, 
							   NBTArguments  *nbtarg)
{
	NBTNsRNB	*nb;
	u_short bcount;

	if (q == NULL || (char *)(q + 1) > pmax)
		return(NULL);
	/* Check out a length */
	bcount = ntohs(q->rdlen);

	/* Forward to Resource NB position */
	nb = (NBTNsRNB *)((u_char *)q + SizeOfNsResource);

	/* Processing all in_addr array */
#ifdef DEBUG
	printf("NB rec[%s", inet_ntoa(nbtarg->oldaddr));
            printf("->%s, %dbytes] ",inet_ntoa(nbtarg->newaddr ), bcount);
#endif
	while ( nb != NULL && bcount != 0 )  {
		if ((char *)(nb + 1) > pmax) {
			nb = NULL;
			break;
		}
#ifdef DEBUG
		printf("<%s>", inet_ntoa(nb->addr) );
#endif
		if (!bcmp(&nbtarg->oldaddr,&nb->addr, sizeof(struct in_addr) ) ) {
			if ( *nbtarg->uh_sum != 0 ) {
            	int acc;
            	u_short *sptr;

            	sptr = (u_short *) &(nb->addr);
            	acc = *sptr++;
            	acc += *sptr;
            	sptr = (u_short *) &(nbtarg->newaddr);
            	acc -= *sptr++;
            	acc -= *sptr;
            	ADJUST_CHECKSUM(acc, *nbtarg->uh_sum);
			}

			nb->addr = nbtarg->newaddr;
#ifdef DEBUG
			printf("O");
#endif
		}
#ifdef DEBUG
		 else {
			printf(".");
		}
#endif
		nb=(NBTNsRNB *)((u_char *)nb + SizeOfNsRNB);
	 	bcount -= SizeOfNsRNB;
	}
	if (nb == NULL || (char *)(nb + 1) > pmax) {
		nb = NULL;
	}

	return ((u_char *)nb);
}

#define SizeOfResourceA		6
typedef struct {
	struct	in_addr	addr;
} NBTNsResourceA;

static u_char *
AliasHandleResourceA( 
    NBTNsResource *q,
    char *pmax,
						 	  NBTArguments  *nbtarg)
{
	NBTNsResourceA	*a;
	u_short bcount;

	if (q == NULL || (char *)(q + 1) > pmax)
		return(NULL);

	/* Forward to Resource A position */
	a = (NBTNsResourceA *)( (u_char *)q + sizeof(NBTNsResource) );

	/* Check out of length */
	bcount = ntohs(q->rdlen);

	/* Processing all in_addr array */
#ifdef DEBUG
	printf("Arec [%s", inet_ntoa(nbtarg->oldaddr));
        printf("->%s]",inet_ntoa(nbtarg->newaddr ));
#endif
	while ( bcount != 0 )  {
		if (a == NULL || (char *)(a + 1) > pmax)
			return(NULL);
#ifdef DEBUG
		printf("..%s", inet_ntoa(a->addr) );
#endif
		if ( !bcmp(&nbtarg->oldaddr, &a->addr, sizeof(struct in_addr) ) ) {
			if ( *nbtarg->uh_sum != 0 ) {
            	int acc;
            	u_short *sptr;

            	sptr = (u_short *) &(a->addr);		 /* Old */
            	acc = *sptr++;
            	acc += *sptr;
            	sptr = (u_short *) &nbtarg->newaddr; /* New */
            	acc -= *sptr++;
            	acc -= *sptr;
            	ADJUST_CHECKSUM(acc, *nbtarg->uh_sum);
			}

			a->addr = nbtarg->newaddr;
		}
		a++;	/*XXXX*/
		bcount -= SizeOfResourceA;
	}
	if (a == NULL || (char *)(a + 1) > pmax)
		a =  NULL;
	return ((u_char *)a);
}

typedef struct {
	u_short opcode:4, flags:8, resv:4;
} NBTNsResourceNULL;

static u_char *
AliasHandleResourceNULL( 
    NBTNsResource *q, 
    char *pmax,
						 	     NBTArguments  *nbtarg)
{
	NBTNsResourceNULL	*n;
	u_short bcount;

	if (q == NULL || (char *)(q + 1) > pmax)
		return(NULL);

	/* Forward to Resource NULL position */
	n = (NBTNsResourceNULL *)( (u_char *)q + sizeof(NBTNsResource) );

	/* Check out of length */
	bcount = ntohs(q->rdlen);

	/* Processing all in_addr array */
	while ( bcount != 0 )  {
		if ((char *)(n + 1) > pmax) {
			n = NULL;
			break;
		}
		n++;
		bcount -= sizeof(NBTNsResourceNULL);
	}
	if ((char *)(n + 1) > pmax)
		n = NULL;

	return ((u_char *)n);
}

static u_char *
AliasHandleResourceNS( 
    NBTNsResource *q,
    char *pmax,
						 	     NBTArguments  *nbtarg)
{
	NBTNsResourceNULL	*n;
	u_short bcount;

	if (q == NULL || (char *)(q + 1) > pmax)
		return(NULL);

	/* Forward to Resource NULL position */
	n = (NBTNsResourceNULL *)( (u_char *)q + sizeof(NBTNsResource) );

	/* Check out of length */
	bcount = ntohs(q->rdlen);

	/* Resource Record Name Filed */
	q = (NBTNsResource *)AliasHandleName( (u_char *)n, pmax ); /* XXX */

	if (q == NULL || (char *)((u_char *)n + bcount) > pmax)
		return(NULL);
	else
	return ((u_char *)n + bcount);
}

typedef struct {
	u_short	numnames;
} NBTNsResourceNBSTAT;

static u_char *
AliasHandleResourceNBSTAT(
    NBTNsResource *q,
    char *pmax,
						 	       NBTArguments  *nbtarg)
{
	NBTNsResourceNBSTAT	*n;
	u_short bcount;

	if (q == NULL || (char *)(q + 1) > pmax)
		return(NULL);

	/* Forward to Resource NBSTAT position */
	n = (NBTNsResourceNBSTAT *)( (u_char *)q + sizeof(NBTNsResource) );

	/* Check out of length */
	bcount = ntohs(q->rdlen);

	if (q == NULL || (char *)((u_char *)n + bcount) > pmax)
		return(NULL);
	else
	return ((u_char *)n + bcount);
}

static u_char *
AliasHandleResource(
    u_short count, 
							NBTNsResource *q,
    char *pmax,
    NBTArguments  
    *nbtarg)
{
	while ( count != 0 ) {
		/* Resource Record Name Filed */
		q = (NBTNsResource *)AliasHandleName( (u_char *)q, pmax );

		if (q == NULL || (char *)(q + 1) > pmax)
			break;
#ifdef DEBUG
		printf("type=%02x, count=%d\n", ntohs(q->type), count );
#endif

		/* Type and Class filed */
		switch ( ntohs(q->type) ) {
			case RR_TYPE_NB:
				q = (NBTNsResource *)AliasHandleResourceNB( 
				    q,
				    pmax,
				    nbtarg 
				);
				break;
			case RR_TYPE_A: 
				q = (NBTNsResource *)AliasHandleResourceA( 
				    q, 
				    pmax, 
				    nbtarg
				);
				break;
			case RR_TYPE_NS:
				q = (NBTNsResource *)AliasHandleResourceNS( 
				    q,
				    pmax, 
				    nbtarg 
				);
				break;
			case RR_TYPE_NULL:
				q = (NBTNsResource *)AliasHandleResourceNULL( 
				    q, 
				    pmax, 
				    nbtarg 
				);
				break;
			case RR_TYPE_NBSTAT:
				q = (NBTNsResource *)AliasHandleResourceNBSTAT(
				    q,
				    pmax, 
				    nbtarg
				);
				break;
			default: 
#ifdef DEBUG
				printf(
				    "\nUnknown Type of Resource %0x\n", 
				    ntohs(q->type) 
				);
#endif
				break;
		}
		count--;
	}
	fflush(stdout);
	return ((u_char *)q);
}

int AliasHandleUdpNbtNS(
	struct ip 		  	*pip,	 /* IP packet to examine/patch */
	struct alias_link 	*link,
	struct in_addr		*alias_address,
	u_short 			*alias_port,
	struct in_addr		*original_address,
	u_short 			*original_port )
{
    struct udphdr *	uh;
	NbtNSHeader	  * nsh;
	u_char		  * p;
	char		*pmax;
	NBTArguments    nbtarg;

	/* Set up Common Parameter */	
	nbtarg.oldaddr	=	*alias_address;
	nbtarg.oldport	=	*alias_port;
	nbtarg.newaddr	=	*original_address;
	nbtarg.newport	=	*original_port;

    /* Calculate data length of UDP packet */
    uh =  (struct udphdr *) ((char *) pip + (pip->ip_hl << 2));
	nbtarg.uh_sum	=	&(uh->uh_sum);
	nsh = (NbtNSHeader *)((char *)uh + (sizeof(struct udphdr)));
	p = (u_char *)(nsh + 1);
    pmax = (char *)uh + ntohs( uh->uh_ulen );

    if ((char *)(nsh + 1) > pmax)
	return(-1);

#ifdef DEBUG
    printf(" [%s] ID=%02x, op=%01x, flag=%02x, rcode=%01x, qd=%04x"
	   ", an=%04x, ns=%04x, ar=%04x, [%d]-->", 
		nsh->dir ? "Response": "Request",
		nsh->nametrid,
		nsh->opcode,
		nsh->nmflags,
		nsh->rcode,
		ntohs(nsh->qdcount),
		ntohs(nsh->ancount),
		ntohs(nsh->nscount),
		ntohs(nsh->arcount),
	(u_char *)p -(u_char *)nsh
    );
#endif

	/* Question Entries */
	if (ntohs(nsh->qdcount) !=0 ) {
	p = AliasHandleQuestion(
	    ntohs(nsh->qdcount),
	    (NBTNsQuestion *)p,
	    pmax, 
	    &nbtarg 
	);
	}

	/* Answer Resource Records */
	if (ntohs(nsh->ancount) !=0 ) {
	p = AliasHandleResource(
	    ntohs(nsh->ancount),
	    (NBTNsResource *)p,
	    pmax, 
	    &nbtarg 
	);
	}

	/* Authority Resource Recodrs */
	if (ntohs(nsh->nscount) !=0 ) {
	p = AliasHandleResource(
	    ntohs(nsh->nscount), 
	    (NBTNsResource *)p,
	    pmax, 
	    &nbtarg 
	);
	}

	/* Additional Resource Recodrs */
	if (ntohs(nsh->arcount) !=0 ) {
	p = AliasHandleResource(
	    ntohs(nsh->arcount),
	    (NBTNsResource *)p,
	    pmax, 
	    &nbtarg 
	);
	}

#ifdef DEBUG
	 	PrintRcode(nsh->rcode);
#endif
    return ((p == NULL) ? -1 : 0);
}
