/*	$NetBSD: ktrace.h,v 1.66 2018/04/19 21:19:07 christos Exp $	*/

/*
 * Copyright (c) 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ktrace.h	8.2 (Berkeley) 2/19/95
 */

#ifndef _SYS_KTRACE_H_
#define _SYS_KTRACE_H_

#include <sys/mutex.h>
#include <sys/lwp.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/uio.h>

/*
 * operations to ktrace system call  (KTROP(op))
 */
#define KTROP_SET		0	/* set trace points */
#define KTROP_CLEAR		1	/* clear trace points */
#define KTROP_CLEARFILE		2	/* stop all tracing to file */
#define	KTROP_MASK		0x3
#define	KTROP(o)		((o)&KTROP_MASK) /* macro to extract operation */
/*
 * flags (ORed in with operation)
 */
#define KTRFLAG_DESCEND		4	/* perform op on all children too */

/*
 * ktrace record header
 */
struct ktr_header {
	union {
		struct { /* v0-v2 */
			int	_len;		/* length of record minus length of old header */
#if BYTE_ORDER == LITTLE_ENDIAN
			short	_type;		/* trace record type */
			short	_version;	/* trace record version */
#else
			short	_version;	/* trace record version */
			short	_type;		/* trace record type */
#endif
			pid_t	_pid;		/* process id */
			char	_comm[MAXCOMLEN+1];	/* command name */
			union {
				struct { /* v0 */
					struct {
						int32_t tv_sec;
						long tv_usec;
					} _tv;
					const void *_buf;
				} _v0;
				struct { /* v1 */
					struct {
						int32_t tv_sec;
						long tv_nsec;
					} _ts;
					lwpid_t _lid;
				} _v1;
				struct { /* v2 */
					struct timespec _ts;
					lwpid_t _lid;
				} _v2;
			} _v;
		} _v012;
		struct { /* v3 */
			int32_t	_len;
			int16_t _version;
			int16_t	_type;
			char	_comm[MAXCOMLEN];
			int64_t	_ts_tv_sec;
			int32_t	_ts_tv_nsec;
			int32_t	_pid;
			int32_t	_lid;
			int32_t _unused;
		} _v3;
	};
};

#define	ktr_olen	_v012._len		/* was ktr_len */
#define	ktr_oversion	_v012._version		/* was ktr_version */
#define	ktr_otype	_v012._type		/* was ktr_type */
#define ktr_opid	_v012._pid		/* was ktr_pid */
#define ktr_ocomm	_v012._comm		/* was ktr_comm */
#define ktr_olid	_v012._v._v2._lid	/* was ktr_lid */
#define ktr_oolid	_v012._v._v1._lid	/* was ktr_olid */
#define ktr_otime	_v012._v._v2._ts	/* was ktr_time */
#define ktr_ootv	_v012._v._v0._tv	/* was ktr_otv */
#define ktr_oots	_v012._v._v1._ts	/* was ktr_ots */
#define ktr_ots		_v012._v._v2._ts	/* was ktr_ts */
#define ktr_ounused	_v012._v._v0._buf	/* was ktr_unused */

/* XXXXXX remove all member "x" prefixes once coverted */
#define	ktr_xlen	_v3._len
#define	ktr_xversion	_v3._version
#define	ktr_xtype	_v3._type
#define	ktr_xcomm	_v3._comm
#define	ktr_xpid	_v3._pid
#define	ktr_xlid	_v3._lid
#define	ktr_xts_sec	_v3._ts_tv_sec
#define	ktr_xts_nsec	_v3._ts_tv_nsec
#define	ktr_xunused	_v3._unused;

#define	KTR_SHIMLEN	offsetof(struct ktr_header, ktr_pid)

#define	KTR_SET_LEN(ktr, len)	(ktr)->ktr_xlen = htobe32(len)
#define	KTR_SET_VERS(ktr, ver)	(ktr)->ktr_xversion = htobe16(ver)
#define	KTR_SET_TYPE(ktr, type)	(ktr)->ktr_xtype = htobe16(type)
#define	KTR_SET_COMM(ktr, comm)	memcpy(kth->ktr_xcomm, (comm), MAXCOMLEN)
#define	KTR_SET_PID(ktr, pid)	(ktr)->ktr_xpid = htobe32(pid)
#define	KTR_SET_LID(ktr, lid)	(ktr)->ktr_xlid = htobe32(lid)
#define	KTR_SET_TIME(ktr, ts)	do {							\
					(ktr)->ktr_xts_sec = htobe64((ts)->tv_sec);	\
					(ktr)->ktr_xts_nsec = htobe32((ts)->tv_nsec);	\
				} while (0)

#define	KTR_GET_LEN(ktr)	be32toh((ktr)->ktr_xlen)
#define	KTR_GET_VERS(ktr)	be16toh((ktr)->ktr_xversion)
#define	KTR_GET_TYPE(ktr)	be16toh((ktr)->ktr_xtype)
#define	KTR_GET_COMM(ktr)	((ktr)->ktr_xcomm)
#define	KTR_GET_PID(ktr)	be32toh((ktr)->ktr_xpid)
#define	KTR_GET_LID(ktr)	be32toh((ktr)->ktr_xlid)
#define	KTR_GET_TIME(ktr, ts)	do {							\
					(ts)->tv_sec = be64toh((ktr)->ktr_xts_sec);	\
					(ts)->tv_nsec = be32toh((ktr)->ktr_xts_nsec);	\
				} while (0)

/*
 * Test for kernel trace point
 */
#define KTRPOINT(p, type)	\
	(((p)->p_traceflag & (1<<(type))) != 0)

/*
 * ktrace record types
 */

/*
 * KTR_SYSCALL - system call record
 */
#define KTR_SYSCALL	1
struct ktr_osyscall {
	int	ktr_code;		/* syscall number */
	int	ktr_argsize;		/* size of arguments */
	/*
	 * followed by ktr_argsize/sizeof(register_t) "register_t"s
	 */
};
struct ktr_syscall {
	int32_t	xktr_code;		/* syscall number */
	int32_t	xktr_argsize;		/* size of arguments */
	/*
	 * followed by ktr_argsize/sizeof(int64_t) "register_t"s
	 */
	int64_t xktr_args[0];
};
#define	KTR_SYSCALL_SET_CODE(ktr, code)		(ktr)->xktr_code = htobe32(code)
#define	KTR_SYSCALL_SET_ARGSIZE(ktr, size)	(ktr)->xktr_argsize = htobe32(size)
#define	KTR_SYSCALL_SET_ARG(ktr, n, arg)	(ktr)->xktr_args[n] = htobe64(arg)

#define	KTR_SYSCALL_GET_CODE(ktr)		be32toh((ktr)->xktr_code)
#define	KTR_SYSCALL_GET_ARGSIZE(ktr)		be32toh((ktr)->xktr_argsize)
#define	KTR_SYSCALL_GET_ARG(ktr, n)		be64toh((ktr)->xktr_args[n])

/*
 * KTR_SYSRET - return from system call record
 */
#define KTR_SYSRET	2
struct ktr_osysret {
	short	ktr_code;
	short	ktr_eosys;		/* XXX unused */
	int	ktr_error;
	__register_t ktr_retval;
	__register_t ktr_retval_1;
};
struct ktr_sysret {
	int16_t	xktr_code;
	int32_t	xktr_error;
	int64_t xktr_retval;
	int64_t xktr_retval_1;
};
#define	KTR_SYSRET_SET_CODE(ktr, code)		(ktr)->xktr_code = htobe16(code)
#define	KTR_SYSRET_SET_ERROR(ktr, error)	(ktr)->xktr_error = htobe32(error)
#define	KTR_SYSRET_SET_RETVAL(ktr, ret)		(ktr)->xktr_retval = htobe64(ret)
#define	KTR_SYSRET_SET_RETVAL1(ktr, ret)	(ktr)->xktr_retval_1 = htobe64(ret)

#define	KTR_SYSRET_GET_CODE(ktr)		htobe16((ktr)->xktr_code)
#define	KTR_SYSRET_GET_ERROR(ktr)		htobe32((ktr)->xktr_error)
#define	KTR_SYSRET_GET_RETVAL(ktr)		htobe64((ktr)->xktr_retval)
#define	KTR_SYSRET_GET_RETVAL1(ktr)		htobe64((ktr)->xktr_retval_1)

#define	KTR_SYSRET_OFFSET_RETVAL1	(offsetof(struct ktr_sysret, xktr_retval_1))

/*
 * KTR_NAMEI - namei record
 */
#define KTR_NAMEI	3
	/* record contains pathname */

/*
 * KTR_GENIO - trace generic process i/o
 */
#define KTR_GENIO	4
struct ktr_ogenio {
	int	ktr_fd;
	enum	uio_rw ktr_rw;
	/*
	 * followed by data successfully read/written
	 */
};
struct ktr_genio {
	int32_t	xktr_fd;
	int32_t	xktr_rw;
	/*
	 * followed by data successfully read/written
	 */
};
#define	KTR_GENIO_SET_FD(genio, fd)	(genio)->xktr_fd = htobe32(fd)
#define	KTR_GENIO_SET_RW(genio, rw)	(genio)->xktr_rw = htobe32(rw)

#define	KTR_GENIO_GET_FD(genio)		be32toh((genio)->xktr_fd)
#define	KTR_GENIO_GET_RW(genio)		be32toh((genio)->xktr_rw)

/*
 * KTR_PSIG - trace processed signal
 */
#define	KTR_PSIG	5
struct ktr_opsig {
	int	signo;
	sig_t	action;
	sigset_t mask;
	int	code;
	/*
	 * followed by optional siginfo_t
	 */
};
struct ktr_psig {
	int32_t	xsigno;
	int32_t	xcode;
	int64_t	xaction;
	struct {
		uint32_t	__bits[4];
	} xmask;
	/*
	 * followed by optional ktr_siginfo_t	XXXXXX ugh
	 */
};
#define	KTR_PSIG_SET_SIG(psig, sig)	(psig)->xsigno = htobe32(sig)
#define	KTR_PSIG_SET_CODE(psig, code)	(psig)->xcode = htobe32(code)
#define	KTR_PSIG_SET_ACTION(psig, act)	(psig)->xaction = htobe64((intptr_t)(act))
#define	KTR_PSIG_SET_MASK(psig, mask)					\
	do {								\
		/* XXX magic "4" */					\
		(psig)->xmask.__bits[0] = htobe32(mask->__bits[0]);	\
		(psig)->xmask.__bits[1] = htobe32(mask->__bits[1]);	\
		(psig)->xmask.__bits[2] = htobe32(mask->__bits[2]);	\
		(psig)->xmask.__bits[3] = htobe32(mask->__bits[3]);	\
	} while (0)
#define	KTR_PSIG_GET_SIG(psig)		be32toh((psig)->xsigno)
#define	KTR_PSIG_GET_CODE(psig)		be32toh((psig)->xcode)
#define	KTR_PSIG_GET_ACTION(psig)	be64toh((psig)->xaction)

/* The following track <sys/sigtypes) __sigmask/__sigword/__sigismember */
#define	__KTR_PSIG_SIGMASK(n)		(1U << (((unsigned int)be32toh(n) - 1) & 31))
#define	__KTR_PSIG_SIGWORD(n)		(((unsigned int)(n) - 1) >> 5)
#define	KTR_PSIG_SIGISMEMBER(psig, n)	\
	(((psig)->xmask.__bits[__KTR_PSIG_SIGWORD(n)] & __KTR_PSIG_SIGMASK(n)) != 0)

#define	KTR_SIG_DFL			((intptr_t)SIG_DFL)

/*
 * KTR_CSW - trace context switches
 */
#define KTR_CSW		6
struct ktr_ocsw {
	int	out;	/* 1 if switch out, 0 if switch in */
	int	user;	/* 1 if usermode (ivcsw), 0 if kernel (vcsw) */
};
struct ktr_csw {
	int32_t	out;	/* 1 if switch out, 0 if switch in */
	int32_t	user;	/* 1 if usermode (ivcsw), 0 if kernel (vcsw) */
};

/*
 * KTR_EMUL - emulation change
 */
#define KTR_EMUL	7
	/* record contains emulation name */

/*
 * KTR_USER - user record
 */
#define	KTR_USER	8
#define KTR_USER_MAXIDLEN	20
#define KTR_USER_MAXLEN		2048	/* maximum length of passed data */
struct ktr_user {
	char 	ktr_id[KTR_USER_MAXIDLEN];	/* string id of caller */
	/*
	 * Followed by ktr_len - sizeof(struct ktr_user) of user data.
	 */
};

/*
 * KTR_EXEC_ARG, KTR_EXEC_ENV - Arguments and environment from exec
 */
#define KTR_EXEC_ARG		10
#define KTR_EXEC_ENV		11
	/* record contains arg/env string */

/*
 * KTR_SAUPCALL - scheduler activated upcall.
 *
 * The structure is no longer used, but retained for compatibility.
 */
#define	KTR_SAUPCALL	13
struct ktr_osaupcall {
	int ktr_sutype;		/* was ktr_type */
	int ktr_nevent;
	int ktr_nint;
	void *ktr_sas;
	void *ktr_ap;
	/*
	 * followed by nevent sa_t's from sas[]
	 */
};
struct ktr_saupcall {
	int32_t	xktr_sutype;		/* was ktr_type */
	int32_t	xktr_nevent;
	int32_t	xktr_nint;
	int32_t	_fill;
	int64_t	xktr_sas;
	int64_t	xktr_ap;
	/*
	 * followed by nevent sa_t's from sas[]		XXXXXX what are these??
	 */
};

/*
 * KTR_MIB - MIB name and data
 */
#define KTR_MIB		14
	/* Record contains MIB name */

/*
 * KTR_EXEC_FD - Opened file descriptor from exec
 */
#define KTR_EXEC_FD		15
struct ktr_execfd {
	int   ktr_fd;
	u_int ktr_dtype; /* one of DTYPE_* constants */
};
struct ktr_oexecfd {
	int32_t	xktr_fd;
	uint32_t xktr_dtype; /* one of DTYPE_* constants */
};

/*
 * kernel trace points (in p_traceflag)
 */
#define KTRFAC_MASK	0x00ffffff
#define KTRFAC_SYSCALL	(1<<KTR_SYSCALL)
#define KTRFAC_SYSRET	(1<<KTR_SYSRET)
#define KTRFAC_NAMEI	(1<<KTR_NAMEI)
#define KTRFAC_GENIO	(1<<KTR_GENIO)
#define	KTRFAC_PSIG	(1<<KTR_PSIG)
#define KTRFAC_CSW	(1<<KTR_CSW)
#define KTRFAC_EMUL	(1<<KTR_EMUL)
#define	KTRFAC_USER	(1<<KTR_USER)
#define KTRFAC_EXEC_ARG	(1<<KTR_EXEC_ARG)
#define KTRFAC_EXEC_ENV	(1<<KTR_EXEC_ENV)
#define	KTRFAC_MIB	(1<<KTR_MIB)
#define	KTRFAC_EXEC_FD	(1<<KTR_EXEC_FD)
/*
 * trace flags (also in p_traceflags)
 */
#define KTRFAC_PERSISTENT	0x80000000	/* persistent trace across sugid
						   exec (exclusive) */
#define KTRFAC_INHERIT	0x40000000	/* pass trace flags to children */
#define KTRFAC_TRC_EMUL	0x10000000	/* ktrace KTR_EMUL before next trace */
#define	KTRFAC_VER_MASK	0x0f000000	/* record version mask */
#define	KTRFAC_VER_SHIFT	24	/* record version shift */

#define	KTRFAC_VERSION(tf)	(((tf) & KTRFAC_VER_MASK) >> KTRFAC_VER_SHIFT)

#define	KTRFACv0	(0 << KTRFAC_VER_SHIFT)
#define	KTRFACv1	(1 << KTRFAC_VER_SHIFT)
#define	KTRFACv2	(2 << KTRFAC_VER_SHIFT)
#define	KTRFACv3	(3 << KTRFAC_VER_SHIFT)

#ifndef	_KERNEL

#include <sys/cdefs.h>

__BEGIN_DECLS
int	ktrace(const char *, int, int, pid_t);
int	fktrace(int, int, int, pid_t);
int	utrace(const char *, void *, size_t);
__END_DECLS

#else

void ktrinit(void);
void ktrderef(struct proc *);
void ktradref(struct proc *);

extern kmutex_t ktrace_lock;
extern int ktrace_on;

int ktruser(const char *, void *, size_t, int);
bool ktr_point(int);

void ktr_csw(int, int);
void ktr_emul(void);
void ktr_geniov(int, enum uio_rw, struct iovec *, size_t, int);
void ktr_genio(int, enum uio_rw, const void *, size_t, int);
void ktr_mibio(int, enum uio_rw, const void *, size_t, int);
void ktr_namei(const char *, size_t);
void ktr_namei2(const char *, size_t, const char *, size_t);
void ktr_psig(int, sig_t, const sigset_t *, const ksiginfo_t *);
void ktr_syscall(register_t, const register_t [], int);
void ktr_sysret(register_t, int, register_t *);
void ktr_kuser(const char *, const void *, size_t);
void ktr_mib(const int *a , u_int b);
void ktr_execarg(const void *, size_t);
void ktr_execenv(const void *, size_t);
void ktr_execfd(int, u_int);

int  ktrace_common(lwp_t *, int, int, int, file_t **);

static __inline int
ktrenter(lwp_t *l)
{

	if ((l->l_pflag & LP_KTRACTIVE) != 0)
		return 1;
	l->l_pflag |= LP_KTRACTIVE;
	return 0;
}

static __inline void
ktrexit(lwp_t *l)
{

	l->l_pflag &= ~LP_KTRACTIVE;
}

static __inline bool
ktrpoint(int fac)
{
    return __predict_false(ktrace_on) && __predict_false(ktr_point(1 << fac));
}

static __inline void
ktrcsw(int a, int b)
{
	if (__predict_false(ktrace_on))
		ktr_csw(a, b);
}

static __inline void
ktremul(void)
{
	if (__predict_false(ktrace_on))
		ktr_emul();
}

static __inline void
ktrgenio(int a, enum uio_rw b, const void *c, size_t d, int e)
{
	if (__predict_false(ktrace_on))
		ktr_genio(a, b, c, d, e);
}

static __inline void
ktrgeniov(int a, enum uio_rw b, struct iovec *c, int d, int e)
{
	if (__predict_false(ktrace_on))
		ktr_geniov(a, b, c, d, e);
}

static __inline void
ktrmibio(int a, enum uio_rw b, const void *c, size_t d, int e)
{
	if (__predict_false(ktrace_on))
		ktr_mibio(a, b, c, d, e);
}

static __inline void
ktrnamei(const char *a, size_t b)
{
	if (__predict_false(ktrace_on))
		ktr_namei(a, b);
}

static __inline void
ktrnamei2(const char *a, size_t b, const char *c, size_t d)
{
	if (__predict_false(ktrace_on))
		ktr_namei2(a, b, c, d);
}

static __inline void
ktrpsig(int a, sig_t b, const sigset_t *c, const ksiginfo_t * d)
{
	if (__predict_false(ktrace_on))
		ktr_psig(a, b, c, d);
}

static __inline void
ktrsyscall(register_t code, const register_t args[], int narg)
{
	if (__predict_false(ktrace_on))
		ktr_syscall(code, args, narg);
}

static __inline void
ktrsysret(register_t a, int b, register_t *c)
{
	if (__predict_false(ktrace_on))
		ktr_sysret(a, b, c);
}

static __inline void
ktrkuser(const char *a, const void *b, size_t c)
{
	if (__predict_false(ktrace_on))
		ktr_kuser(a, b, c);
}

static __inline void
ktrmib(const int *a , u_int b)
{
	if (__predict_false(ktrace_on))
		ktr_mib(a, b);
}

static __inline void
ktrexecarg(const void *a, size_t b)
{
	if (__predict_false(ktrace_on))
		ktr_execarg(a, b);
}

static __inline void
ktrexecenv(const void *a, size_t b)
{
	if (__predict_false(ktrace_on))
		ktr_execenv(a, b);
}

static __inline void
ktrexecfd(int fd, u_int dtype)
{
	if (__predict_false(ktrace_on))
		ktr_execfd(fd, dtype);
}

struct ktrace_entry;
int	ktealloc(struct ktrace_entry **, void **, lwp_t *, int, size_t);
void	ktraddentry(lwp_t *, struct ktrace_entry *, int);
/* Flags for ktraddentry (3rd arg) */
#define	KTA_NOWAIT		0x0000
#define	KTA_WAITOK		0x0001
#define	KTA_LARGE		0x0002

#endif	/* !_KERNEL */

#endif /* _SYS_KTRACE_H_ */
