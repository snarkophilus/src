/*-
 * Copyright (c) 2019 The NetBSD Foundation, Inc.
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

#include "opt_cputypes.h"
#include "opt_multiprocessor.h"

#include <sys/cdefs.h>
__KERNEL_RCSID(1, "$NetBSD$");

#include <sys/param.h>
#include <sys/types.h>

#include <uvm/uvm.h>

#include <arm/cpufunc.h>

#include <aarch64/armreg.h>

tlb_asid_t
tlb_get_asid(void)
{

	return __SHIFTOUT(reg_ttbr0_el1_read(), TTBR_ASID);
}

void
tlb_set_asid(tlb_asid_t asid)
{

	uint64_t ttbr = reg_ttbr0_el1_read();

	ttbr &= ~TTBR_ASID;
	ttbr |= __SHIFTIN(asid, TTBR_ASID);

	cpu_set_ttbr0(ttbr);

	//XXXNH clear TCR_EPD0?
}

void
tlb_invalidate_all(void)
{

	aarch64_tlbi_all();
}

void
tlb_invalidate_globals(void)
{
	tlb_invalidate_all();
}

void
tlb_invalidate_asids(tlb_asid_t lo, tlb_asid_t hi)
{
	for (; lo <= hi; lo++) {
		aarch64_tlbi_by_asid(lo);
	}
}

void
tlb_invalidate_addr(vaddr_t va, tlb_asid_t asid)
{

	aarch64_tlbi_by_asid_va(asid, va);
}

bool
tlb_update_addr(vaddr_t va, tlb_asid_t asid, pt_entry_t pte, bool insert_p)
{

	tlb_invalidate_addr(va, asid);

	return true;
}

u_int
tlb_record_asids(u_long *mapp, tlb_asid_t asid_max)
{
#ifdef DIAGNOSTIC
	mapp[0] = 0xfffffffe;
	mapp[1] = 0xffffffff;
	mapp[2] = 0xffffffff;
	mapp[3] = 0xffffffff;
	mapp[4] = 0xffffffff;
	mapp[5] = 0xffffffff;
	mapp[6] = 0xffffffff;
	mapp[7] = 0xffffffff;
#endif
	// XXXNH
	return 255;
}

void
tlb_walk(void *ctx, bool (*func)(void *, vaddr_t, tlb_asid_t, pt_entry_t))
{

	/* no way to view the TLB */
}
