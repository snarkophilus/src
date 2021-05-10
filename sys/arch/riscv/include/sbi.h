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

#define SBI_SET_TIMER              0
#define SBI_CONSOLE_PUTCHAR        1
#define SBI_CONSOLE_GETCHAR        2
#define SBI_CLEAR_IPI              3
#define SBI_SEND_IPI               4
#define SBI_REMOTE_FENCE_I         5
#define SBI_REMOTE_SFENCE_VMA      6
#define SBI_REMOTE_SFENCE_VMA_ASID 7
#define SBI_SHUTDOWN               8

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


/*
 * void sbi_set_timer(uint64_t stime_value)
 */

static __inline void
sbi_set_timer(uint64_t stime_value)
{
#ifdef _LP64
	sbi_call1(SBI_SET_TIMER, stime_value);
#else
	sbi_call2(SBI_SET_TIMER, stime_value, stime_value >> 32);
#endif
}

/*
 * void sbi_console_putchar(int ch)
 */

static __inline void
sbi_console_putchar(char c) {
	sbi_call1(SBI_CONSOLE_PUTCHAR, c);
}

/*
 * int sbi_console_getchar(void)
 */
static __inline char
sbi_console_getchar(void) {
	return sbi_call0(SBI_CONSOLE_GETCHAR);
}

/*
 * void sbi_clear_ipi(void)
 */
static __inline void
sbi_clear_ipi(void) {
	sbi_call0(SBI_CLEAR_IPI);
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
	sbi_call1(SBI_SEND_IPI, (register_t)hart_mask);
}

/*
 * void sbi_remote_fence_i(const unsigned long *hart_mask)
 */
static __inline void
sbi_remote_fence_i(const unsigned long *hart_mask) {
	sbi_call1(SBI_REMOTE_FENCE_I, (register_t)hart_mask);
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
	sbi_call3(SBI_REMOTE_SFENCE_VMA, (register_t)hart_mask,
	    start, )size);
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
	sbi_call4(SBI_REMOTE_SFENCE_VMA_ASID, (register_t)hart_mask,
	    start, size, asid);
}

/*
 * void sbi_shutdown(void)
 */
static __inline void
sbi_shutdown(void) {
	sbi_call0(SBI_SHUTDOWN);
}

#endif /* _RISCV_SBI_H_ */
