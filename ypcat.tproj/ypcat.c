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
static char rcsid[] = "$Id: ypcat.c,v 1.1 1999/05/02 03:59:01 wsanchez Exp $";
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <ctype.h>

#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpcsvc/yp_prot.h>
#include <rpcsvc/ypclnt.h>

struct ypalias {
	char *alias, *name;
} ypaliases[] = {
	{ "passwd", "passwd.byname" },
	{ "group", "group.byname" },
	{ "networks", "networks.byaddr" },
	{ "hosts", "hosts.byaddr" },
	{ "protocols", "protocols.bynumber" },
	{ "services", "services.byname" },
	{ "aliases", "mail.aliases" },
	{ "ethers", "ethers.byname" },
};

int key;

usage()
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\typcat [-k] [-d domainname] [-t] mapname\n");
	fprintf(stderr, "\typcat -x\n");
	exit(1);
}

printit(instatus, inkey, inkeylen, inval, invallen, indata)
int instatus;
char *inkey;
int inkeylen;
char *inval;
int invallen;
char *indata;
{
	if(instatus != YP_TRUE)
		return instatus;
	if(key)
		printf("%*.*s ", inkeylen, inkeylen, inkey);
	printf("%*.*s\n", invallen, invallen, inval);
	return 0;
}

int
main(argc, argv)
char **argv;
{
	char *domainname;
	struct ypall_callback ypcb;
	char *inmap;
	extern char *optarg;
	extern int optind;
	int notrans;
	int c, r, i;

	notrans = key = 0;
	yp_get_default_domain(&domainname);

	while( (c=getopt(argc, argv, "xd:kt")) != -1)
		switch(c) {
		case 'x':
			for(i=0; i<sizeof ypaliases/sizeof ypaliases[0]; i++)
				printf("Use \"%s\" for \"%s\"\n",
					ypaliases[i].alias,
					ypaliases[i].name);
			exit(0);
		case 'd':
			domainname = optarg;
			break;
		case 't':
			notrans++;
			break;
		case 'k':
			key++;
			break;
		default:
			usage();
		}

	if(optind + 1 != argc )
		usage();

	inmap = argv[optind];
	for(i=0; (!notrans) && i<sizeof ypaliases/sizeof ypaliases[0]; i++)
		if( strcmp(inmap, ypaliases[i].alias) == 0)
			inmap = ypaliases[i].name;
	ypcb.foreach = printit;
	ypcb.data = NULL;

	r = yp_all(domainname, inmap, &ypcb);
	switch(r) {
	case 0:
		break;
	case YPERR_YPBIND:
		fprintf(stderr, "ypcat: not running ypbind\n");
		exit(1);
	default:
		fprintf(stderr, "No such map %s. Reason: %s\n",
			inmap, yperr_string(r));
		exit(1);
	}
	exit(0);
}
