/*	$NetBSD: lockd_lock.h,v 1.2 2000/06/09 14:00:54 fvdl Exp $	*/
/*	$FreeBSD: src/usr.sbin/rpc.lockd/lockd_lock.h,v 1.4 2002/03/21 22:52:45 alfred Exp $ */

/* Headers and function declarations for file-locking utilities */

#ifndef LOCKD_LOCK_H
#define LOCKD_LOCK_H
struct nlm4_holder * testlock(struct nlm4_lock *lock, bool_t exclusive, int flags);
enum nlm_stats getlock(nlm4_lockargs *lckarg, struct svc_req *rqstp, const int flags);
enum nlm_stats unlock(nlm4_lock *lock, const int flags);
enum nlm_stats cancellock(nlm4_cancargs *args, const int flags);
int lock_answer(int version, netobj *netcookie, nlm4_lock *lock, int flags, int result);
enum nlm_stats getshare(nlm_shareargs *shrarg, struct svc_req *rqstp, const int flags);
enum nlm_stats unshare(nlm_shareargs *shrarg, struct svc_req *rqstp);
void do_free_all(const char *hostname);
void granted_failed(nlm4_res *arg);

void notify(const char *hostname, const int state);

void monitor_lock_host_by_name(const char *hostname);
void monitor_lock_host_by_addr(const struct sockaddr *addr);
void unmonitor_lock_host(const char *hostname);

/* flags for testlock, getlock & unlock */
#define LOCK_ASYNC	0x01 /* async version (getlock only) */
#define LOCK_V4 	0x02 /* v4 version */
#define LOCK_MON 	0x04 /* monitored lock (getlock only) */

/* flags for lock_answer */
#define LOCK_ANSWER_GRANTED	0x0001	/* NLM_GRANTED request */
#define LOCK_ANSWER_LOCK_EXCL	0x0004	/* lock is exclusive */

/* callbacks from lock_proc.c */
int	transmit_result(int, nlm_res *, struct sockaddr *);
int	transmit4_result(int, nlm4_res *, struct sockaddr *);
CLIENT  *get_client(struct sockaddr *, rpcvers_t);
int	addrcmp(const struct sockaddr *, const struct sockaddr *);

extern time_t currsec;

#endif /* !LOCKD_LOCK_H */
