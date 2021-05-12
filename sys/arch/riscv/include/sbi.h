/*	$NetBSD$	*/

/*-
 * Copyright (c) 2021 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Nick Hudson
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RISCV_SBI_H_
#define _RISCV_SBI_H_

#define SBI_V0P1_SET_TIMER              0
#define SBI_V0P1_CONSOLE_PUTCHAR        1
#define SBI_V0P1_CONSOLE_GETCHAR        2
#define SBI_V0P1_CLEAR_IPI              3
#define SBI_V0P1_SEND_IPI               4
#define SBI_V0P1_REMOTE_FENCE_I         5
#define SBI_V0P1_REMOTE_SFENCE_VMA      6
#define SBI_V0P1_REMOTE_SFENCE_VMA_ASID 7
#define SBI_V0P1_SHUTDOWN               8

#include <sys/types.h>

static __inline register_t
sbi_call0(register_t eid) {
	register register_t a7 __asm ("a7") = eid;
	register register_t a0 __asm ("a0");

	__asm __volatile (
	    "ecall"
		: "=r" (a0)
		: "r" (a7)
		: "memory");
	return a0;
}

static __inline register_t
sbi_call1(register_t eid, register_t arg0) {
	register register_t a7 __asm ("a7") = eid;

	register register_t a0 __asm ("a0") = arg0;

	__asm __volatile (
	    "ecall"
		: "+r" (a0)
		: "r" (a7)
		: "memory");
	return a0;
}

static __inline register_t
sbi_call2(register_t eid, register_t arg0, register_t arg1) {
	register register_t a7 __asm ("a7") = eid;

	register register_t a0 __asm ("a0") = arg0;
	register register_t a1 __asm ("a1") = arg1;

	__asm __volatile (
	    "ecall"
		: "+r" (a0)
		: "r" (a1), "r" (a7)
		: "memory");
	return a0;
}

static __inline register_t
sbi_call3(register_t eid, register_t arg0, register_t arg1, register_t arg2) {
	register register_t a7 __asm ("a7") = eid;

	register register_t a0 __asm ("a0") = arg0;
	register register_t a1 __asm ("a1") = arg1;
	register register_t a2 __asm ("a2") = arg2;

	__asm __volatile (
		"ecall"
		: "+r" (a0)
		: "r" (a1), "r" (a2), "r" (a7)
		: "memory");
	return a0;
}

static __inline register_t
sbi_call4(register_t eid, register_t arg0, register_t arg1, register_t arg2,
    register_t arg3) {
	register register_t a7 __asm ("a7") = eid;

	register register_t a0 __asm ("a0") = arg0;
	register register_t a1 __asm ("a1") = arg1;
	register register_t a2 __asm ("a2") = arg2;
	register register_t a3 __asm ("a3") = arg3;

	__asm __volatile (
		"ecall"
		: "+r" (a0)
		: "r" (a1), "r" (a2), "r" (a3), "r" (a7)
		: "memory");
	return a0;
}

struct sbiret {
	long error;
	long value;
};

#define	SBI_SUCCESS			0
#define	SBI_ERR_FAILED			-1
#define	SBI_ERR_NOT_SUPPORTED		-2
#define	SBI_ERR_INVALID_PARAM		-3
#define	SBI_ERR_DENIED			-4
#define	SBI_ERR_INVALID_ADDRESS		-5
#define	SBI_ERR_ALREADY_AVAILABLE	-6


static __inline struct sbiret
sbi_ecall(int eid, int fid,
    unsigned long arg0, unsigned long arg1, unsigned long arg2,
    unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	struct sbiret ret;

	register register_t _a7 __asm ("a7") = eid;
	register register_t _a6 __asm ("a6") = fid;

	register register_t _a0 __asm ("a0") = arg0;
	register register_t _a1 __asm ("a1") = arg1;
	register register_t _a2 __asm ("a2") = arg2;
	register register_t _a3 __asm ("a3") = arg3;
	register register_t _a4 __asm ("a4") = arg4;
	register register_t _a5 __asm ("a5") = arg5;

	__asm __volatile (
		"ecall"
		: "+r" (_a0), "+r" (_a1)
		: "r" (_a2), "r" (_a3), "r" (_a4), "r" (_a5), "r" (_a6), "r" (_a7)
		: "memory");
	ret.error = _a0;
	ret.value = _a1;

	return ret;
}


/*
 * void sbi_set_timer(uint64_t stime_value)
 */

static __inline void
sbi_set_timer(uint64_t stime_value)
{
#ifdef _LP64
	sbi_ecall(SBI_V0P1_SET_TIMER, 0, stime_value, 0, 0, 0, 0, 0);
#else
	sbi_ecall(SBI_V0P1_SET_TIMER, 0, stime_value, stime_value >> 32, 0, 0,
	    0, 0);
#endif
}

/*
 * void sbi_console_putchar(int ch)
 */

static __inline void
sbi_console_putchar(char c) {
	sbi_ecall(SBI_V0P1_CONSOLE_PUTCHAR, 0, c, 0, 0, 0, 0, 0);
}

/*
 * int sbi_console_getchar(void)
 */
static __inline char
sbi_console_getchar(void) {
	struct sbiret ret = sbi_ecall(SBI_V0P1_CONSOLE_GETCHAR, 0, 0, 0, 0, 0,
	    0, 0);

	return ret.error;
}

/*
 * void sbi_clear_ipi(void)
 */
static __inline void
sbi_clear_ipi(void) {
	sbi_call0(SBI_V0P1_CLEAR_IPI);
}


/*
 * hart_mask is a virtual address that points to a bit-vector of harts. The
 * bit vector is represented as a sequence of unsigned longs whose length
 * equals the number of harts in the system divided by the number of bits
 * in an unsigned long, rounded up to the next integer.
*/

/*
 * void sbi_send_ipi(const unsigned long *hart_mask)
 */
static __inline void
sbi_send_ipi(const unsigned long *hart_mask) {
	sbi_call1(SBI_V0P1_SEND_IPI, (register_t)hart_mask);
}

/*
 * void sbi_remote_fence_i(const unsigned long *hart_mask)
 */
static __inline void
sbi_remote_fence_i(const unsigned long *hart_mask) {
	sbi_call1(SBI_V0P1_REMOTE_FENCE_I, (register_t)hart_mask);
}

/*
 * void sbi_remote_sfence_vma(const unsigned long *hart_mask,
 *                            unsigned long start,
 *                            unsigned long size)
 */
static __inline void
sbi_remote_sfence_vma(const unsigned long *hart_mask,
    unsigned long start, unsigned long size)
{
	sbi_call3(SBI_V0P1_REMOTE_SFENCE_VMA, (register_t)hart_mask,
	    start, size);
}

/*
 * void sbi_remote_sfence_vma_asid(const unsigned long *hart_mask,
 *                                 unsigned long start,
 *                                 unsigned long size,
 *                                 unsigned long asid)
 */
static __inline void
sbi_remote_sfence_vma_asid(const unsigned long *hart_mask,
    unsigned long start, unsigned long size, unsigned long asid)
{
	sbi_call4(SBI_V0P1_REMOTE_SFENCE_VMA_ASID, (register_t)hart_mask,
	    start, size, asid);
}

/*
 * void sbi_shutdown(void)
 */
static __inline void
sbi_shutdown(void) {
	sbi_call0(SBI_V0P1_SHUTDOWN);
}





/*
| Function Name            | SBI Version | FID | EID
| sbi_get_sbi_spec_version | 0.2         |   0 | 0x10
| sbi_get_sbi_impl_id      | 0.2         |   1 | 0x10
| sbi_get_sbi_impl_version | 0.2         |   2 | 0x10
| sbi_probe_extension      | 0.2         |   3 | 0x10
| sbi_get_mvendorid        | 0.2         |   4 | 0x10
| sbi_get_marchid          | 0.2         |   5 | 0x10
| sbi_get_mimpid           | 0.2         |   6 | 0x10
*/


struct sbiret sbi_get_spec_version(void);

struct sbiret sbi_get_impl_id(void);

struct sbiret sbi_get_impl_version(void);

struct sbiret sbi_probe_extension(long extension_id);

struct sbiret sbi_get_mvendorid(void);

struct sbiret sbi_get_marchid(void);

struct sbiret sbi_get_mimpid(void);

/*
| Implementation ID | Name
| 0                 | Berkeley Boot Loader (BBL)
| 1                 | OpenSBI
| 2                 | Xvisor
| 3                 | KVM
| 4                 | RustSBI
| 5                 | Diosix
*/

#define	SBI_IMPLID_BERKELEY	0
#define	SBI_IMPLID_OPENSBI	1
#define	SBI_IMPLID_XVISOR	2
#define	SBI_IMPLID_KVM		3
#define	SBI_IMPLID_RUSTSBI	4
#define	SBI_IMPLID_DIOSIX	5

/*
.Legacy Function List
[cols="4,2,1,2,3", width=100%, align="center", options="header"]
|===
| Function Name             | SBI Version | FID | EID       | Replacement EID
| sbi_set_timer             | 0.1         |   0 | 0x00      | 0x54494D45
| sbi_console_putchar       | 0.1         |   0 | 0x01      | N/A
| sbi_console_getchar       | 0.1         |   0 | 0x02      | N/A
| sbi_clear_ipi             | 0.1         |   0 | 0x03      | N/A
| sbi_send_ipi              | 0.1         |   0 | 0x04      | 0x735049
| sbi_remote_fence_i        | 0.1         |   0 | 0x05      | 0x52464E43
| sbi_remote_sfence_vma     | 0.1         |   0 | 0x06      | 0x52464E43
| sbi_remote_sfence_vma_asid| 0.1         |   0 | 0x07      | 0x52464E43
| sbi_shutdown              | 0.1         |   0 | 0x08      | 0x53525354
| *RESERVED*                |             |     | 0x09-0x0F |
*/



#endif /* _RISCV_SBI_H_ */
