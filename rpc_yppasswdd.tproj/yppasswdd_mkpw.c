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
/*	$OpenBSD: yppasswdd_mkpw.c,v 1.16 1997/11/17 23:56:20 gene Exp $	*/

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
static char rcsid[] = "$OpenBSD: yppasswdd_mkpw.c,v 1.16 1997/11/17 23:56:20 gene Exp $";
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <rpc/rpc.h>
#include <rpcsvc/yppasswd.h>
#include <db.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>
#include <util.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <err.h>

extern int noshell;
extern int nogecos;
extern int nopw;
extern int make;
extern char make_arg[];

static void _pw_copy(int, int, struct passwd *);

/* This is imported from OpenBSD's libutil because it's argument
 * incompatible with NetBSD's. However, the NetBSD libutil is
 * at least what the prototypes suggest is in System.framework,
 * even though I can't find the code. I assume it will be there
 * eventually. We need to use NetBSD's because it works with the
 * pwd_mkdb binary that's shipped with Rhapsody. This is an area
 * where OpenBSD diverges; however, we wanted to keep the OpenBSD
 * rpc.yppasswdd because the rest of our YP code is from OpenBSD.
 * What a mess.
 */
static void
_pw_copy(ffd, tfd, pw)
	int ffd, tfd;
	struct passwd *pw;
{
	FILE   *from, *to;
	int	done;
	char   *p, buf[8192];

	if (!(from = fdopen(ffd, "r")))
		pw_error(_PATH_MASTERPASSWD, 1, 1);
	if (!(to = fdopen(tfd, "w")))
		pw_error(_PATH_MASTERPASSWD_LOCK, 1, 1);

	for (done = 0; fgets(buf, sizeof(buf), from);) {
		if (!strchr(buf, '\n')) {
			warnx("%s: line too long", _PATH_MASTERPASSWD);
			pw_error(NULL, 0, 1);
		}
		if (done) {
			(void)fprintf(to, "%s", buf);
			if (ferror(to))
				goto err;
			continue;
		}
		if (!(p = strchr(buf, ':'))) {
			warnx("%s: corrupted entry", _PATH_MASTERPASSWD);
			pw_error(NULL, 0, 1);
		}
		*p = '\0';
		if (strcmp(buf, pw->pw_name)) {
			*p = ':';
			(void)fprintf(to, "%s", buf);
			if (ferror(to))
				goto err;
			continue;
		}
		(void)fprintf(to, "%s:%s:%d:%d:%s:%ld:%ld:%s:%s:%s\n",
		    pw->pw_name, pw->pw_passwd, pw->pw_uid, pw->pw_gid,
		    pw->pw_class, pw->pw_change, pw->pw_expire, pw->pw_gecos,
		    pw->pw_dir, pw->pw_shell);
		done = 1;
		if (ferror(to))
			goto err;
	}
	if (!done)
		(void)fprintf(to, "%s:%s:%d:%d:%s:%ld:%ld:%s:%s:%s\n",
		    pw->pw_name, pw->pw_passwd, pw->pw_uid, pw->pw_gid,
		    pw->pw_class, pw->pw_change, pw->pw_expire, pw->pw_gecos,
		    pw->pw_dir, pw->pw_shell);

	if (ferror(to))
err:
	pw_error(NULL, 0, 1);
	(void)fclose(to);
}


int
badchars(base)
	char *base;
{
	int ampr = 0;
	char *s;

	for (s = base; *s; s++) {
		if (*s == '&')
			ampr++;
		if (!isprint(*s))
			return 1;
		if (strchr(":\n\t\r", *s))
			return 1;
	}
	if (ampr > 10)
		return 1;
	return 0;
}

int
subst(s, from, to)
	char *s;
	char from, to;
{
	int	n = 0;

	while (*s) {
		if (*s == from) {
			*s = to;
			n++;
		}
		s++;
	}
	return (n);
}

int
make_passwd(argp)
	yppasswd *argp;
{
	struct passwd pw;
	int     pfd, tfd;
	char	buf[10], *bp = NULL, *p, *t;
	int	n;
	ssize_t cnt;
	size_t	resid;
	struct stat st;

	pw_init();
	pfd = open(_PATH_MASTERPASSWD, O_RDONLY);
	if (pfd < 0)
		goto fail;
	if (fstat(pfd, &st))
		goto fail;
	p = bp = malloc((resid = st.st_size) + 1);
	do {
		cnt = read(pfd, p, resid);
		if (cnt < 0)
			goto fail;
		p += cnt;
		resid -= cnt;
	} while (resid > 0);
	close(pfd);
	pfd = -1;
	*p = '\0';		/* Buf oflow prevention */

	p = bp;
	subst(p, '\n', '\0');
	for (n = 1; p < bp + st.st_size; n++, p = t) {
		t = strchr(p, '\0') + 1;
		/* Rhapsody allows the passwd file to have comments in it. */
		if (p[0] == '#') {
			continue;
		}
		cnt = subst(p, ':', '\0');
		if (cnt != 9) {
			syslog(LOG_WARNING, "bad entry at line %d of %s", n,
			    _PATH_MASTERPASSWD);
			continue;
		}

		if (strcmp(p, argp->newpw.pw_name) == 0)
			break;
	}
	if (p >= bp + st.st_size)
		goto fail;

#define	EXPAND(e)	e = p; while (*p++);
	EXPAND(pw.pw_name);
	EXPAND(pw.pw_passwd);
	pw.pw_uid = atoi(p); EXPAND(t);
	pw.pw_gid = atoi(p); EXPAND(t);
	EXPAND(pw.pw_class);
	pw.pw_change = (time_t)atol(p); EXPAND(t);
	pw.pw_expire = (time_t)atol(p); EXPAND(t);
	EXPAND(pw.pw_gecos);
	EXPAND(pw.pw_dir);
	EXPAND(pw.pw_shell);

	/* crypt() is broken under Rhapsody. It doesn't deal with
	 * empty keys or salts like other Unices.
	 */
	if (pw.pw_passwd[0] != '\0' && argp->oldpass != NULL && argp->oldpass[0] != '\0') {
		if (strcmp(crypt(argp->oldpass, pw.pw_passwd), pw.pw_passwd) != 0)
			goto fail;
	}
	
	if (!nopw && badchars(argp->newpw.pw_passwd))
		goto fail;
	if (!nogecos && badchars(argp->newpw.pw_gecos))
		goto fail;
	if (!nogecos && badchars(argp->newpw.pw_shell))
		goto fail;

	/*
	 * Get the new password.  Reset passwd change time to zero; when
	 * classes are implemented, go and get the "offset" value for this
	 * class and reset the timer.
	 */
	if (!nopw) {
		pw.pw_passwd = argp->newpw.pw_passwd;
		pw.pw_change = 0;
	}
	if (!nogecos)
		pw.pw_gecos = argp->newpw.pw_gecos;
	if (!noshell)
		pw.pw_shell = argp->newpw.pw_shell;

	for (n = 0, p = pw.pw_gecos; *p; p++)
		if (*p == '&')
			n = n + strlen(pw.pw_name) - 1;
	if (strlen(pw.pw_name) + 1 + strlen(pw.pw_passwd) + 1 +
	    strlen((sprintf(buf, "%d", pw.pw_uid), buf)) + 1 +
	    strlen((sprintf(buf, "%d", pw.pw_gid), buf)) + 1 +
	    strlen(pw.pw_gecos) + n + 1 + strlen(pw.pw_dir) + 1 +
	    strlen(pw.pw_shell) >= 1023)
		goto fail;

	pfd = open(_PATH_MASTERPASSWD, O_RDONLY, 0);
	if (pfd < 0) {
		syslog(LOG_ERR, "cannot open %s", _PATH_MASTERPASSWD);
		goto fail;
	}

	tfd = pw_lock(0);
	if (tfd < 0)
		goto fail;

	_pw_copy(pfd, tfd, &pw);
	pw_mkdb();
	free(bp);

	if (fork() == 0) {
		chdir("/var/yp");
		(void)umask(022);
		system(make_arg);
		exit(0);
	}
	return (0);

fail:
	if (bp)
		free(bp);
	if (pfd >= 0)
		close(pfd);
	return (1);
}
