/*	$NetBSD$	*/

/*-
 * Copyright (c) 2020 The NetBSD Foundation, Inc.
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


#include <riscv/asm.h>
#include "assym.h"

RCSID("$NetBSD$")


ENTRY_NP(generic_bs_r_1)
	PTR_L	a5, BS_STRIDE(a0)	/* stride */
	PTR_SLL	a2, a2, a5		/* offset <<= stride */
	PTR_ADD	a2, a2, a1		/* add to address */
	lbu	a0, 0(a2)		/* load 8-bit */
	ret
END(generic_bs_r_1)


ENTRY_NP(generic_bs_r_2)
	PTR_L	a5, BS_STRIDE(a0)	/* stride */
	PTR_SLL	a2, a2, a5		/* offset <<= stride */
	PTR_ADD	a2, a2, a1		/* add to address */
	lhu	a0, 0(a2)		/* load 16-bit */
	ret
END(generic_bs_r_2)

ENTRY_NP(generic_bs_r_4)
	PTR_L	a5, BS_STRIDE(a0)	/* stride */
	PTR_SLL	a2, a2, a5		/* offset <<= stride */
	PTR_ADD	a2, a2, a1		/* add to address */
	lw	a0, 0(a2)		/* load 32-bit */
	ret
END(generic_bs_r_4)

#ifdef _LP64
ENTRY_NP(generic_bs_r_8)
	PTR_L	a5, BS_STRIDE(a0)	/* stride */
	PTR_SLL	a2, a2, a5		/* offset <<= stride */
	PTR_ADD	a2, a2, a1		/* add to address */
	ld	a0, 0(a2)		/* load 64-bit */
	ret
END(generic_bs_r_4)
#endif

ENTRY_NP(generic_bs_rm_1)
	PTR_L	a5, BS_STRIDE(a0)	/* stride */
	PTR_SLL	a2, a2, a5		/* offset <<= stride */
	PTR_ADD	a2, a2, a1		/* add to address */
1:
	lbu	a0, 0(a2)		/* load 8-bit */
	sb	a0, 0(a3)
	add 	a3, a3, 1
	add	a4, a4, -1		/* count-- */
	bnez	a4, 1b
	ret
END(generic_bs_rm_1)



ENTRY_NP(generic_bs_rm_2)
	PTR_L	a5, BS_STRIDE(a0)	/* stride */
	PTR_SLL	a2, a2, a5		/* offset <<= stride */
	PTR_ADD	a2, a2, a1		/* add to address */
1:
	lhu	a0, 0(a2)		/* load 16-bit */
	sh	a0, 0(a3)		/* store 16-bit */
	add 	a3, a3, 2
	add	a4, a4, -1		/* count-- */
	bnez	a4, 1b
	ret
END(generic_bs_rm_2)


ENTRY_NP(generic_bs_rm_4)
	PTR_L	a5, BS_STRIDE(a0)	/* stride */
	PTR_SLL	a2, a2, a5		/* offset <<= stride */
	PTR_ADD	a2, a2, a1		/* add to address */
1:
	lw	a0, 0(a2)		/* load 32-bit */
	sw	a0, 0(a3)		/* store 32-bit */
	add 	a3, a3, 4
	add	a4, a4, -1		/* count-- */
	bnez	a4, 1b
	ret
END(generic_bs_rm_4)

#ifdef _LP64
ENTRY_NP(generic_bs_rm_8)
	PTR_L	a5, BS_STRIDE(a0)	/* stride */
	PTR_SLL	a2, a2, a5		/* offset <<= stride */
	PTR_ADD	a2, a2, a1		/* add to address */
1:
	ld	a0, 0(a2)		/* load 64-bit */
	sd	a0, 0(a3)		/* store 64-bit */
	add 	a3, a3, 8
	add	a4, a4, -1		/* count-- */
	bnez	a4, 1b
	ret
END(generic_bs_rm_4)
#endif




ENTRY_NP(generic_bs_rr_1)
	PTR_L	a5, BS_STRIDE(a0)	/* stride */
	li	t0, 1
	srl	t0, t0, a5		/* delta = 1 << stride */
	PTR_SLL	a2, a2, a5		/* offset <<= stride */
	PTR_ADD	a2, a2, a1		/* add to address */
1:
	lbu	a0, 0(a2)		/* load 8-bit */
	sb	a0, 0(a3)		/* *dst = value */
	add	a2, a2, t0		/* src += delta */
	add 	a3, a3, 1		/* dst++ */
	add	a4, a4, -1		/* count-- */
	bnez	a4, 1b
	ret
END(generic_bs_rr_1)




ENTRY_NP(generic_bs_w_1)
	PTR_L	a5, BS_STRIDE(a0)	/* stride */
	PTR_SLL	a2, a2, a5		/* offset <<= stride */
	PTR_ADD	a2, a2, a1		/* add to address */
	sb	a0, 0(a2)		/* store 8-bit */
	ret
END(generic_bs_w_1)


ENTRY_NP(generic_bs_w_2)
	PTR_L	a5, BS_STRIDE(a0)	/* stride */
	PTR_SLL	a2, a2, a5		/* offset <<= stride */
	PTR_ADD	a2, a2, a1		/* add to address */
	sh	a0 ,0(a2)		/* store 16-bit */
	ret
END(generic_bs_w_2)

ENTRY_NP(generic_bs_w_4)
	PTR_L	a5, BS_STRIDE(a0)	/* stride */
	PTR_SLL	a2, a2, a5		/* offset <<= stride */
	PTR_ADD	a2, a2, a1		/* add to address */
	sw	a0, 0(a2)		/* store 32-bit */
	ret
END(generic_bs_w_4)

#ifdef _LP64
ENTRY_NP(generic_bs_w_8)
	PTR_L	a5, BS_STRIDE(a0)	/* stride */
	PTR_SLL	a2, a2, a5		/* offset <<= stride */
	PTR_ADD	a2, a2, a1		/* add to address */
	sd	a0, 0(a2)		/* store 64-bit */
	ret
END(generic_bs_w_8)
#endif





