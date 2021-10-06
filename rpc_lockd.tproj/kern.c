/*-
 * Copyright (c) 1997 Berkeley Software Design, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Berkeley Software Design Inc's name may not be used to endorse or
 *    promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY BERKELEY SOFTWARE DESIGN INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL BERKELEY SOFTWARE DESIGN INC BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      from BSDI kern.c,v 1.2 1998/11/25 22:38:27 don Exp
 * $FreeBSD: src/usr.sbin/rpc.lockd/kern.c,v 1.11 2002/08/15 21:52:21 alfred Exp $
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <netdb.h>

#include "rpcsvc/nlm_prot.h"
#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs_lock.h>
#include <nfs/nfs.h>

#include "lockd.h"
#include "lockd_lock.h"

#define nfslockdans(_v, _ansp)	\
	((_ansp)->la_version = (_v), \
	nfsclnt(NFSCLNT_LOCKDANS, (_ansp)))


/* Lock request owner. */
typedef struct __owner {
	pid_t	 pid;				/* Process ID. */
	time_t	 tod;				/* Time-of-day. */
} OWNER;
static OWNER owner;

static char hostname[MAXHOSTNAMELEN + 1];	/* Hostname. */

static void	client_cleanup(void);
static void	set_auth(CLIENT *cl, struct xucred *ucred);
int	lock_request(LOCKD_MSG *);
int	cancel_request(LOCKD_MSG *);
int	test_request(LOCKD_MSG *);
void	show(LOCKD_MSG *);
int	unlock_request(LOCKD_MSG *);

#define d_calls (debug_level > 1)
#define d_args (debug_level > 2)

static const char *
from_addr(saddr)
	struct sockaddr *saddr;
{
	static char inet_buf[INET6_ADDRSTRLEN];

	if (getnameinfo(saddr, saddr->sa_len, inet_buf, sizeof(inet_buf),
			NULL, 0, NI_NUMERICHOST) == 0)
		return inet_buf;
	return "???";
}

/*
 * client_kern_wait()
 *
 * wait for kernel to signal first lock request before starting
 */
void
client_kern_wait(void)
{
	if (nfsclnt(NFSCLNT_LOCKDWAIT, NULL))
		warn("nfsclnt_lockdwait");
}

void
client_cleanup(void)
{
	(void) nfsclnt(NFSCLNT_LOCKDFD, (struct lockd_ans *)-1);
	exit(-1);
}

/*
 * client_request --
 *	Loop around messages from the kernel, forwarding them off to
 *	NLM servers.
 */
pid_t
client_request(void)
{
	LOCKD_MSG msg;
	fd_set rdset;
	int fd, nr, ret;
	pid_t child;
	mode_t old_umask;

	/* Recreate the NLM fifo. */
	(void)unlink(_PATH_LCKFIFO);
	old_umask = umask(S_IXGRP|S_IXOTH);
	if (mkfifo(_PATH_LCKFIFO, S_IWUSR | S_IRUSR)) {
		syslog(LOG_ERR, "mkfifo: %s: %m", _PATH_LCKFIFO);
		exit (1);
	}
	umask(old_umask);

	/*
	 * Create a separate process, the client code is really a separate
	 * daemon that shares a lot of code.
	 */
	switch (child = fork()) {
	case -1:
		err(1, "fork");
	case 0:
		break;
	default:
		return (child);
	}

	signal(SIGHUP, (sig_t)client_cleanup);
	signal(SIGTERM, (sig_t)client_cleanup);

	/* Setup. */
	(void)time(&owner.tod);
	owner.pid = getpid();

	/* Open the fifo for reading. */
	if ((fd = open(_PATH_LCKFIFO, O_RDONLY | O_NONBLOCK)) == -1) {
		syslog(LOG_ERR, "open: %s: %m", _PATH_LCKFIFO);
		_exit (1);
	}
	(void)unlink(_PATH_LCKFIFO);
	if (nfsclnt(NFSCLNT_LOCKDFD, (struct lockd_ans *)fd)) {
		syslog(LOG_ERR, "nfsclnt_fd: %d: %m", fd);
		_exit (1);
	}

	for (;;) {
		/* Wait for contact... fifo's return EAGAIN when read with 
		 * no data
		 */
		/* Set up the select. */
		FD_ZERO(&rdset);
		FD_SET(fd, &rdset);
		(void)select(fd + 1, &rdset, NULL, NULL, NULL);

		/*
		 * Hold off getting hostname until first
		 * lock request. Otherwise we risk getting
		 * an initial ".local" name.
		 */
		if (hostname[0] == '\0')
			(void)gethostname(hostname, sizeof(hostname) - 1);

		/* Read the fixed length message. */
		if ((nr = read(fd, &msg, sizeof(msg))) == sizeof(msg)) {
			if (d_args)
				show(&msg);

			if (msg.lm_version != LOCKD_MSG_VERSION) {
				syslog(LOG_ERR,
				    "unknown msg type: %d", msg.lm_version);
			}
			/*
			 * Send it to the NLM server and don't grant the lock
			 * if we fail for any reason.
			 */
			switch (msg.lm_fl.l_type) {
			case F_RDLCK:
			case F_WRLCK:
				if (msg.lm_flags & LOCKD_MSG_TEST)
					ret = test_request(&msg);
				else if (msg.lm_flags & LOCKD_MSG_CANCEL)
					ret = cancel_request(&msg);
				else
					ret = lock_request(&msg);
				break;
			case F_UNLCK:
				ret = unlock_request(&msg);
				break;
			default:
				ret = 1;
				syslog(LOG_ERR,
				    "unknown lock type: %d", msg.lm_fl.l_type);
				break;
			}
			if (ret) {
				struct lockd_ans ans;

				ans.la_xid = msg.lm_xid;
				ans.la_errno = ENOTSUP;

				if (nfslockdans(LOCKD_ANS_VERSION, &ans)) {
					syslog(LOG_DEBUG, "process %lu: %m",
						(u_long)msg.lm_fl.l_pid);
				}
			}
		} else if (nr == -1) {
			if (errno != EAGAIN) {
				syslog(LOG_ERR, "read: %s: %m", _PATH_LCKFIFO);
				goto err;
			}
		} else if (nr != 0) {
			syslog(LOG_ERR,
			    "%s: discard %d bytes", _PATH_LCKFIFO, nr);
		}
	}

	/* Reached only on error. */
err:
	(void) nfsclnt(NFSCLNT_LOCKDFD, (struct lockd_ans *)-1);
	_exit (1);
	return 0;
}

void
set_auth(cl, xucred)
	CLIENT *cl;
	struct xucred *xucred;
{
        if (cl->cl_auth != NULL)
                cl->cl_auth->ah_ops->ah_destroy(cl->cl_auth);
        cl->cl_auth = authunix_create(hostname,
                        xucred->cr_uid,
                        xucred->cr_groups[0],
                        xucred->cr_ngroups - 1,
                        &xucred->cr_groups[1]);
}


/*
 * test_request --
 *	Convert a lock LOCKD_MSG into an NLM request, and send it off.
 */
int
test_request(LOCKD_MSG *msg)
{
	CLIENT *cli;
	struct timeval timeout = {0, 0};	/* No timeout, no response. */
	char dummy;

	if (d_calls)
		syslog(LOG_DEBUG, "test request: %s: %s to %s",
		    (msg->lm_flags & LOCKD_MSG_NFSV3) ? "V4" : "V1/3",
		    msg->lm_fl.l_type == F_WRLCK ? "write" : "read",
		    from_addr((struct sockaddr *)&msg->lm_addr));

	if (msg->lm_flags & LOCKD_MSG_NFSV3) {
		struct nlm4_testargs arg4;

		arg4.cookie.n_bytes = (char *)&msg->lm_xid;
		arg4.cookie.n_len = sizeof(msg->lm_xid);
		arg4.exclusive = msg->lm_fl.l_type == F_WRLCK ? 1 : 0;
		arg4.alock.caller_name = hostname;
		arg4.alock.fh.n_bytes = (char *)&msg->lm_fh;
		arg4.alock.fh.n_len = msg->lm_fh_len;
		arg4.alock.oh.n_bytes = (char *)&owner;
		arg4.alock.oh.n_len = sizeof(owner);
		arg4.alock.svid = msg->lm_fl.l_pid;
		arg4.alock.l_offset = msg->lm_fl.l_start;
		arg4.alock.l_len = msg->lm_fl.l_len;

		if ((cli = get_client(
		    (struct sockaddr *)&msg->lm_addr,
		    NLM_VERS4)) == NULL)
			return (1);

		set_auth(cli, &msg->lm_cred);
		(void)clnt_call(cli, NLM4_TEST_MSG,
		    xdr_nlm4_testargs, &arg4, xdr_void, &dummy, timeout);
	} else {
		struct nlm_testargs arg;

		arg.cookie.n_bytes = (char *)&msg->lm_xid;
		arg.cookie.n_len = sizeof(msg->lm_xid);
		arg.exclusive = msg->lm_fl.l_type == F_WRLCK ? 1 : 0;
		arg.alock.caller_name = hostname;
		arg.alock.fh.n_bytes = (char *)&msg->lm_fh;
		arg.alock.fh.n_len = msg->lm_fh_len;
		arg.alock.oh.n_bytes = (char *)&owner;
		arg.alock.oh.n_len = sizeof(owner);
		arg.alock.svid = msg->lm_fl.l_pid;
		arg.alock.l_offset = msg->lm_fl.l_start;
		arg.alock.l_len = msg->lm_fl.l_len;

		if ((cli = get_client(
		    (struct sockaddr *)&msg->lm_addr,
		    NLM_VERS)) == NULL)
			return (1);

		set_auth(cli, &msg->lm_cred);
		(void)clnt_call(cli, NLM_TEST_MSG,
		    xdr_nlm_testargs, &arg, xdr_void, &dummy, timeout);
	}
	return (0);
}

/*
 * lock_request --
 *	Convert a lock LOCKD_MSG into an NLM request, and send it off.
 */
int
lock_request(LOCKD_MSG *msg)
{
	CLIENT *cli;
	struct nlm4_lockargs arg4;
	struct nlm_lockargs arg;
	struct timeval timeout = {0, 0};	/* No timeout, no response. */
	char dummy;

	if (d_calls)
		syslog(LOG_DEBUG, "lock request: %s: %s to %s",
		    (msg->lm_flags & LOCKD_MSG_NFSV3) ? "V4" : "V1/3",
		    msg->lm_fl.l_type == F_WRLCK ? "write" : "read",
		    from_addr((struct sockaddr *)&msg->lm_addr));

	monitor_lock_host_by_addr((struct sockaddr *)&msg->lm_addr);

	if (msg->lm_flags & LOCKD_MSG_NFSV3) {
		arg4.cookie.n_bytes = (char *)&msg->lm_xid;
		arg4.cookie.n_len = sizeof(msg->lm_xid);
		arg4.block = (msg->lm_flags & LOCKD_MSG_BLOCK) ? 1 : 0;
		arg4.exclusive = msg->lm_fl.l_type == F_WRLCK ? 1 : 0;
		arg4.alock.caller_name = hostname;
		arg4.alock.fh.n_bytes = (char *)&msg->lm_fh;
		arg4.alock.fh.n_len = msg->lm_fh_len;
		arg4.alock.oh.n_bytes = (char *)&owner;
		arg4.alock.oh.n_len = sizeof(owner);
		arg4.alock.svid = msg->lm_fl.l_pid;
		arg4.alock.l_offset = msg->lm_fl.l_start;
		arg4.alock.l_len = msg->lm_fl.l_len;
		arg4.reclaim = 0;
		arg4.state = nsm_state;

		if ((cli = get_client(
		    (struct sockaddr *)&msg->lm_addr,
		    NLM_VERS4)) == NULL)
			return (1);

		set_auth(cli, &msg->lm_cred);
		(void)clnt_call(cli, NLM4_LOCK_MSG,
		    xdr_nlm4_lockargs, &arg4, xdr_void, &dummy, timeout);
	} else {
		arg.cookie.n_bytes = (char *)&msg->lm_xid;
		arg.cookie.n_len = sizeof(msg->lm_xid);
		arg.block = (msg->lm_flags & LOCKD_MSG_BLOCK) ? 1 : 0;
		arg.exclusive = msg->lm_fl.l_type == F_WRLCK ? 1 : 0;
		arg.alock.caller_name = hostname;
		arg.alock.fh.n_bytes = (char *)&msg->lm_fh;
		arg.alock.fh.n_len = msg->lm_fh_len;
		arg.alock.oh.n_bytes = (char *)&owner;
		arg.alock.oh.n_len = sizeof(owner);
		arg.alock.svid = msg->lm_fl.l_pid;
		arg.alock.l_offset = msg->lm_fl.l_start;
		arg.alock.l_len = msg->lm_fl.l_len;
		arg.reclaim = 0;
		arg.state = nsm_state;

		if ((cli = get_client(
		    (struct sockaddr *)&msg->lm_addr,
		    NLM_VERS)) == NULL)
			return (1);

		set_auth(cli, &msg->lm_cred);
		(void)clnt_call(cli, NLM_LOCK_MSG,
		    xdr_nlm_lockargs, &arg, xdr_void, &dummy, timeout);
	}
	return (0);
}

/*
 * cancel_request --
 *	Convert a lock LOCKD_MSG into an NLM request, and send it off.
 */
int
cancel_request(LOCKD_MSG *msg)
{
	CLIENT *cli;
	struct nlm4_cancargs arg4;
	struct nlm_cancargs arg;
	struct timeval timeout = {0, 0};	/* No timeout, no response. */
	char dummy;

	if (d_calls)
		syslog(LOG_DEBUG, "cancel request: %s: %s to %s",
		    (msg->lm_flags & LOCKD_MSG_NFSV3) ? "V4" : "V1/3",
		    msg->lm_fl.l_type == F_WRLCK ? "write" : "read",
		    from_addr((struct sockaddr *)&msg->lm_addr));

	if (msg->lm_flags & LOCKD_MSG_NFSV3) {
		arg4.cookie.n_bytes = (char *)&msg->lm_xid;
		arg4.cookie.n_len = sizeof(msg->lm_xid);
		arg4.block = (msg->lm_flags & LOCKD_MSG_BLOCK) ? 1 : 0;
		arg4.exclusive = msg->lm_fl.l_type == F_WRLCK ? 1 : 0;
		arg4.alock.caller_name = hostname;
		arg4.alock.fh.n_bytes = (char *)&msg->lm_fh;
		arg4.alock.fh.n_len = msg->lm_fh_len;
		arg4.alock.oh.n_bytes = (char *)&owner;
		arg4.alock.oh.n_len = sizeof(owner);
		arg4.alock.svid = msg->lm_fl.l_pid;
		arg4.alock.l_offset = msg->lm_fl.l_start;
		arg4.alock.l_len = msg->lm_fl.l_len;

		if ((cli = get_client(
		    (struct sockaddr *)&msg->lm_addr, NLM_VERS4)) == NULL)
			return (1);

		set_auth(cli, &msg->lm_cred);
		(void)clnt_call(cli, NLM4_CANCEL_MSG,
		    xdr_nlm4_cancargs, &arg4, xdr_void, &dummy, timeout);
	} else {
		arg.cookie.n_bytes = (char *)&msg->lm_xid;
		arg.cookie.n_len = sizeof(msg->lm_xid);
		arg.block = (msg->lm_flags & LOCKD_MSG_BLOCK) ? 1 : 0;
		arg.exclusive = msg->lm_fl.l_type == F_WRLCK ? 1 : 0;
		arg.alock.caller_name = hostname;
		arg.alock.fh.n_bytes = (char *)&msg->lm_fh;
		arg.alock.fh.n_len = msg->lm_fh_len;
		arg.alock.oh.n_bytes = (char *)&owner;
		arg.alock.oh.n_len = sizeof(owner);
		arg.alock.svid = msg->lm_fl.l_pid;
		arg.alock.l_offset = msg->lm_fl.l_start;
		arg.alock.l_len = msg->lm_fl.l_len;

		if ((cli = get_client(
		    (struct sockaddr *)&msg->lm_addr, NLM_VERS)) == NULL)
			return (1);

		set_auth(cli, &msg->lm_cred);
		(void)clnt_call(cli, NLM_CANCEL_MSG,
		    xdr_nlm_cancargs, &arg, xdr_void, &dummy, timeout);
	}
	return (0);
}

/*
 * unlock_request --
 *	Convert an unlock LOCKD_MSG into an NLM request, and send it off.
 */
int
unlock_request(LOCKD_MSG *msg)
{
	CLIENT *cli;
	struct nlm4_unlockargs arg4;
	struct nlm_unlockargs arg;
	struct timeval timeout = {0, 0};	/* No timeout, no response. */
	char dummy;

	if (d_calls)
		syslog(LOG_DEBUG, "unlock request: %s: to %s",
		    (msg->lm_flags & LOCKD_MSG_NFSV3) ? "V4" : "V1/3",
		    from_addr((struct sockaddr *)&msg->lm_addr));

	if (msg->lm_flags & LOCKD_MSG_NFSV3) {
		arg4.cookie.n_bytes = (char *)&msg->lm_xid;
		arg4.cookie.n_len = sizeof(msg->lm_xid);
		arg4.alock.caller_name = hostname;
		arg4.alock.fh.n_bytes = (char *)&msg->lm_fh;
		arg4.alock.fh.n_len = msg->lm_fh_len;
		arg4.alock.oh.n_bytes = (char *)&owner;
		arg4.alock.oh.n_len = sizeof(owner);
		arg4.alock.svid = msg->lm_fl.l_pid;
		arg4.alock.l_offset = msg->lm_fl.l_start;
		arg4.alock.l_len = msg->lm_fl.l_len;

		if ((cli = get_client(
		    (struct sockaddr *)&msg->lm_addr,
		    NLM_VERS4)) == NULL)
			return (1);

		set_auth(cli, &msg->lm_cred);
		(void)clnt_call(cli, NLM4_UNLOCK_MSG,
		    xdr_nlm4_unlockargs, &arg4, xdr_void, &dummy, timeout);
	} else {
		arg.cookie.n_bytes = (char *)&msg->lm_xid;
		arg.cookie.n_len = sizeof(msg->lm_xid);
		arg.alock.caller_name = hostname;
		arg.alock.fh.n_bytes = (char *)&msg->lm_fh;
		arg.alock.fh.n_len = msg->lm_fh_len;
		arg.alock.oh.n_bytes = (char *)&owner;
		arg.alock.oh.n_len = sizeof(owner);
		arg.alock.svid = msg->lm_fl.l_pid;
		arg.alock.l_offset = msg->lm_fl.l_start;
		arg.alock.l_len = msg->lm_fl.l_len;

		if ((cli = get_client(
		    (struct sockaddr *)&msg->lm_addr,
		    NLM_VERS)) == NULL)
			return (1);

		set_auth(cli, &msg->lm_cred);
		(void)clnt_call(cli, NLM_UNLOCK_MSG,
		    xdr_nlm_unlockargs, &arg, xdr_void, &dummy, timeout);
	}

	return (0);
}

int
lock_answer(int version, netobj *netcookie, nlm4_lock *lock, int flags, int result)
{
	struct lockd_ans ans;

	ans.la_flags = 0;
	if (flags & LOCK_ANSWER_GRANTED)
		ans.la_flags |= LOCKD_ANS_GRANTED;

	if (netcookie->n_len != sizeof(ans.la_xid)) {
		if (lock == NULL) {	/* we're screwed */
			syslog(LOG_ERR, "inedible nlm cookie");
			return -1;
		}
		/* no/bad cookie - need to copy lock info to identify request */
		ans.la_xid = 0;
		/* copy lock info */
		ans.la_fh_len = lock->fh.n_len;
		if (!lock->fh.n_len || (lock->fh.n_len > NFS_SMALLFH)) {
			syslog(LOG_ERR, "bogus filehandle size %d in answer", lock->fh.n_len);
			return -1;
		}
		memcpy(ans.la_fh, lock->fh.n_bytes, ans.la_fh_len);
		ans.la_pid = lock->svid;
		ans.la_start = lock->l_offset;
		ans.la_len = lock->l_len;
		ans.la_flags |= LOCKD_ANS_LOCK_INFO;
		if (flags & LOCK_ANSWER_LOCK_EXCL)
			ans.la_flags |= LOCKD_ANS_LOCK_EXCL;
	} else {
		memcpy(&ans.la_xid, netcookie->n_bytes, sizeof(ans.la_xid));
		ans.la_fh_len = 0;
	}

	if (d_calls)
		syslog(LOG_DEBUG, "lock answer: pid %lu: %s %d",
		    (unsigned long)ans.la_pid,
		    version == NLM_VERS4 ? "nlmv4" : "nlmv3",
		    result);

	if (version == NLM_VERS4)
		switch (result) {
		case nlm4_granted:
			ans.la_errno = 0;
			if ((flags & LOCK_ANSWER_GRANTED) && lock &&
			    !(ans.la_flags & LOCKD_ANS_LOCK_INFO)) {
				/* copy lock info */
				ans.la_fh_len = lock->fh.n_len;
				if (!lock->fh.n_len || (lock->fh.n_len > NFS_SMALLFH)) {
					syslog(LOG_ERR, "bogus filehandle size %d in answer", lock->fh.n_len);
					return -1;
				}
				memcpy(ans.la_fh, lock->fh.n_bytes, ans.la_fh_len);
				ans.la_pid = lock->svid;
				ans.la_start = lock->l_offset;
				ans.la_len = lock->l_len;
				ans.la_flags |= LOCKD_ANS_LOCK_INFO;
				if (flags & LOCK_ANSWER_LOCK_EXCL)
					ans.la_flags |= LOCKD_ANS_LOCK_EXCL;
			}
			break;
		default:
			ans.la_errno = EACCES;
			break;
		case nlm4_denied:
			if (lock == NULL)
				ans.la_errno = EACCES;
			else {
				/* this is an answer to a nlm_test msg */
				ans.la_pid = lock->svid;
				ans.la_start = lock->l_offset;
				ans.la_len = lock->l_len;
				ans.la_flags |= LOCKD_ANS_LOCK_INFO;
				if (flags & LOCK_ANSWER_LOCK_EXCL)
					ans.la_flags |= LOCKD_ANS_LOCK_EXCL;
				ans.la_errno = 0;
			}
			break;
		case nlm4_denied_nolocks:
			ans.la_errno = ENOLCK;
			break;
		case nlm4_blocked:
			ans.la_errno = EINPROGRESS;
			break;
		case nlm4_denied_grace_period:
			ans.la_errno = EAGAIN;
			break;
		case nlm4_deadlck:
			ans.la_errno = EDEADLK;
			break;
		case nlm4_rofs:
			ans.la_errno = EROFS;
			break;
		case nlm4_stale_fh:
			ans.la_errno = ESTALE;
			break;
		case nlm4_fbig:
			ans.la_errno = EFBIG;
			break;
		case nlm4_failed:
			ans.la_errno = EACCES;
			break;
		}
	else
		switch (result) {
		case nlm_granted:
			ans.la_errno = 0;
			if ((flags & LOCK_ANSWER_GRANTED) && lock &&
			    !(ans.la_flags & LOCKD_ANS_LOCK_INFO)) {
				/* copy lock info */
				ans.la_fh_len = lock->fh.n_len;
				if (!lock->fh.n_len || (lock->fh.n_len > NFS_SMALLFH)) {
					syslog(LOG_ERR, "bogus filehandle size %d in answer", lock->fh.n_len);
					return -1;
				}
				memcpy(ans.la_fh, lock->fh.n_bytes, ans.la_fh_len);
				ans.la_pid = lock->svid;
				ans.la_start = lock->l_offset;
				ans.la_len = lock->l_len;
				ans.la_flags |= LOCKD_ANS_LOCK_INFO;
				if (flags & LOCK_ANSWER_LOCK_EXCL)
					ans.la_flags |= LOCKD_ANS_LOCK_EXCL;
			}
			break;
		default:
			ans.la_errno = EACCES;
			break;
		case nlm_denied:
			if (lock == NULL)
				ans.la_errno = EACCES;
			else {
				/* this is an answer to a nlm_test msg */
				ans.la_pid = lock->svid;
				ans.la_start = lock->l_offset;
				ans.la_len = lock->l_len;
				ans.la_flags |= LOCKD_ANS_LOCK_INFO;
				if (flags & LOCK_ANSWER_LOCK_EXCL)
					ans.la_flags |= LOCKD_ANS_LOCK_EXCL;
				ans.la_errno = 0;
			}
			break;
		case nlm_denied_nolocks:
			ans.la_errno = ENOLCK;
			break;
		case nlm_blocked:
			ans.la_errno = EINPROGRESS;
			break;
		case nlm_denied_grace_period:
			ans.la_errno = EAGAIN;
			break;
		case nlm_deadlck:
			ans.la_errno = EDEADLK;
			break;
		}

	if (nfslockdans(LOCKD_ANS_VERSION, &ans)) {
		syslog(LOG_DEBUG, "lock_answer(%d): process %lu: %m",
			result, (u_long)ans.la_pid);
		return -1;
	}
	return 0;
}

/*
 * show --
 *	Display the contents of a kernel LOCKD_MSG structure.
 */
void
show(LOCKD_MSG *mp)
{
	static char hex[] = "0123456789abcdef";
	size_t len;
	u_int8_t *p, *t, buf[NFS_SMALLFH*3+1];

	syslog(LOG_DEBUG, "process ID: %lu\n", (long)mp->lm_fl.l_pid);

	for (t = buf, p = (u_int8_t *)mp->lm_fh,
	    len = mp->lm_fh_len;
	    len > 0; ++p, --len) {
		*t++ = '\\';
		*t++ = hex[(*p & 0xf0) >> 4];
		*t++ = hex[*p & 0x0f];
	}
	*t = '\0';

	syslog(LOG_DEBUG, "fh_len %d, fh %s\n", mp->lm_fh_len, buf);

	/* Show flock structure. */
	syslog(LOG_DEBUG, "start %qu; len %qu; pid %lu; type %d; whence %d\n",
	    mp->lm_fl.l_start, mp->lm_fl.l_len, (u_long)mp->lm_fl.l_pid,
	    mp->lm_fl.l_type, mp->lm_fl.l_whence);

	/* Show wait flag. */
	syslog(LOG_DEBUG, "wait was %s\n", (mp->lm_flags & LOCKD_MSG_BLOCK) ? "set" : "not set");
}
