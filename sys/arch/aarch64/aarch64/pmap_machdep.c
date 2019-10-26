/*	$NetBSD$	*/

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

#include "opt_arm_debug.h"
#include "opt_multiprocessor.h"
#include "opt_uvmhist.h"

#define __PMAP_PRIVATE

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/types.h>
#include <sys/cpu.h>
#include <sys/kernel.h>

#include <uvm/uvm.h>
#include <uvm/pmap/pmap_pvt.h>

#include <aarch64/cpufunc.h>

#include <arm/locore.h>

__KERNEL_RCSID(0, "$NetBSD$");

#ifdef VERBOSE_INIT_ARM
#define VPRINTF(...)	printf(__VA_ARGS__)
#else
#define VPRINTF(...)	__nothing
#endif

//static void	pmap_md_vca_page_wbinv(struct vm_page *, bool);

/*
 * Misc variables
 */
vaddr_t virtual_avail;
vaddr_t virtual_end;
vaddr_t pmap_curmaxkvaddr;

bool pmap_devmap_bootstrap_done = false;

/*
 * Virtual end of direct-mapped memory
 */
vaddr_t pmap_directlimit;

paddr_t
vtophys(vaddr_t va)
{
	paddr_t pa;

	if (pmap_extract(pmap_kernel(), va, &pa) == false)
		return 0;
	return pa;
}

bool
pmap_extract_coherency(pmap_t pm, vaddr_t va, paddr_t *pap, bool *coherentp)
{
	paddr_t pa;

	// XXXNH copy of ryopmap behaviour.
	*coherentp = false;

	if (pm == pmap_kernel()) {
		if (pmap_md_direct_mapped_vaddr_p(va)) {
			pa = pmap_md_direct_mapped_vaddr_to_paddr(va);
//			*coherentp = true;
			goto done;
		}
		if (pmap_md_io_vaddr_p(va))
			panic("pmap_extract: io address %#"PRIxVADDR"", va);

		if (va >= pmap_limits.virtual_end)
			panic("%s: illegal kernel mapped address %#"PRIxVADDR,
			    __func__, va);
	}

	kpreempt_disable();
	const pt_entry_t * const ptep = pmap_pte_lookup(pm, va);
	if (ptep == NULL || !pte_valid_p(*ptep)) {
		kpreempt_enable();
		return false;
	}

	pa = pte_to_paddr(*ptep) | (va & PGOFSET);
	kpreempt_enable();
done:
	if (pap != NULL) {
		*pap = pa;
	}
	return true;
}


bool
pmap_fault_fixup(pmap_t pm, vaddr_t va, vm_prot_t ftype, bool user)
{
	UVMHIST_FUNC(__func__); UVMHIST_CALLED(maphist);

	KASSERT(!user || (pm != pmap_kernel()));

	UVMHIST_LOG(maphist, " (pm=%#jx, va=%#jx, ftype=%#jx, user=%jd)",
	    (uintptr_t)pm, va, ftype, user);
	UVMHIST_LOG(maphist, " ti=%#jx pai=%#jx asid=%#jx",
	    (uintptr_t)cpu_tlb_info(curcpu()),
	    (uintptr_t)PMAP_PAI(pm, cpu_tlb_info(curcpu())),
	    (uintptr_t)PMAP_PAI(pm, cpu_tlb_info(curcpu()))->pai_asid, 0);

	kpreempt_disable();

	bool fixed = false;
	pt_entry_t * const ptep = pmap_pte_lookup(pm, va);
	if (ptep == NULL) {
		UVMHIST_LOG(pmaphist, "... no ptep", 0, 0, 0, 0);
		goto done;
	}

	pt_entry_t pte = *ptep;

	if (!l3pte_valid(pte)) {
		UVMHIST_LOG(pmaphist, "invalid pte: %016llx: va=%016lx",
		    pte, va, 0, 0);
		goto done;
	}

	pt_entry_t opte = *ptep;
	paddr_t pa = l3pte_pa(opte);

	struct vm_page * const pg = PHYS_TO_VM_PAGE(pa);
	if (pg == NULL) {
		UVMHIST_LOG(pmaphist, "pg not found: va=%016lx", va, 0, 0, 0);
		goto done;
	}

	struct vm_page_md * const mdpg = VM_PAGE_TO_MD(pg);

	if ((ftype & VM_PROT_WRITE) && (pte & LX_BLKPAG_AP) == LX_BLKPAG_AP_RW) {
		/*
		 * This looks like a good candidate for "page modified"
		 * emulation...
		 */

		pmap_page_set_attributes(mdpg, VM_PAGEMD_MODIFIED|VM_PAGEMD_REFERENCED);

		/*
		 * Enable write permissions for the page by setting the Access Flag.
		 */
		const pt_entry_t npte = opte | LX_BLKPAG_AF | LX_BLKPAG_OS_0;
		atomic_swap_64(ptep, npte);

		fixed = true;
		UVMHIST_LOG(maphist, " <-- done (mod emul: changed pte "
		    "from %#jx to %#jx)", opte, npte, 0, 0);
	} else if ((ftype & VM_PROT_READ) && (pte & LX_BLKPAG_AP) == LX_BLKPAG_AP_RO) {
		/*
		 * This looks like a good candidate for "page referenced"
		 * emulation.
		 */

		pmap_page_set_attributes(mdpg, VM_PAGEMD_REFERENCED);

		/*
		 * Enable write permissions for the page by setting the Access Flag.
		 */
		const pt_entry_t npte = opte | LX_BLKPAG_AF;

		atomic_swap_64(ptep, npte);

		//PMAPCOUNT(fixup_mod);
		fixed = true;
		UVMHIST_LOG(maphist, " <-- done (ref emul: changed pte "
		    "from %#jx to %#jx)", opte, npte, 0, 0);
	}

done:
	kpreempt_enable();

	return fixed;
}



#if 0
#ifdef __HAVE_MM_MD_DIRECT_MAPPED_PHYS
vaddr_t
pmap_direct_mapped_phys(paddr_t pa, bool *ok_p, vaddr_t va)
{
	bool ok = false;
	if (physical_start <= pa && pa < physical_end) {
		const vaddr_t newva = pa - physical_start + KERNEL_DIRECTMAP_BASE;
		if (newva >= KERNEL_DIRECTMAP_BASE && newva < pmap_directlimit) {
			va = newva;
			ok = true;
		}
	}
	KASSERT(ok_p);
	*ok_p = ok;
	return va;
}
#endif
#endif


struct vm_page *
pmap_md_alloc_poolpage(int flags)
{

	/*
	 * Any managed page works for us.
	 */
	return uvm_pagealloc(NULL, 0, NULL, flags);
}

vaddr_t
pmap_md_map_poolpage(paddr_t pa, size_t len)
{

	struct vm_page * const pg = PHYS_TO_VM_PAGE(pa);
	vaddr_t va = pmap_md_pool_phystov(pa);
	KASSERT(cold || pg != NULL);
	if (pg != NULL) {
		struct vm_page_md * const mdpg = VM_PAGE_TO_MD(pg);
		pv_entry_t pv = &mdpg->mdpg_first;
		vaddr_t last_va = trunc_page(pv->pv_va);

		KASSERT(len == PAGE_SIZE || last_va == pa);
		KASSERT(pv->pv_pmap == NULL);
		KASSERT(pv->pv_next == NULL);
		KASSERT(!VM_PAGEMD_EXECPAGE_P(mdpg));

#ifdef PMAP_VIRTUAL_CACHE_ALIASES
		/*
		 * If this page was last mapped with an address that
		 * might cause aliases, flush the page from the cache.
		 */
		if (AARCH64_CACHE_VIRTUAL_ALIAS
		    && aarch64_cache_badalias(last_va, va)) {
			pmap_md_vca_page_wbinv(pg, false);
		}
#endif

		pv->pv_va = va;
	}

	return va;
}

paddr_t
pmap_md_unmap_poolpage(vaddr_t va, size_t len)
{
	KASSERT(len == PAGE_SIZE);
	KASSERT(pmap_md_direct_mapped_vaddr_p(va));

	const paddr_t pa = pmap_md_direct_mapped_vaddr_to_paddr(va);
	struct vm_page * const pg = PHYS_TO_VM_PAGE(pa);

	KASSERT(pg);
	struct vm_page_md * const mdpg = VM_PAGE_TO_MD(pg);

#ifdef PMAP_VIRTUAL_CACHE_ALIASES
	KASSERT(VM_PAGEMD_CACHED_P(mdpg));
#endif
	KASSERT(!VM_PAGEMD_EXECPAGE_P(mdpg));

	pv_entry_t pv = &mdpg->mdpg_first;

	/* Note last mapped address for future color check */
	pv->pv_va = va;

	KASSERT(pv->pv_pmap == NULL);
	KASSERT(pv->pv_next == NULL);

	return pa;
}


bool
pmap_md_kernel_vaddr_p(vaddr_t va)
{

	extern char __kernel_text[];
	extern char _end[];
	extern long kernend_extra;

	vaddr_t kernstart = trunc_page((vaddr_t)__kernel_text);
	vaddr_t kernend = round_page((vaddr_t)_end);

	vaddr_t fva = L2_TRUNC_BLOCK(kernstart);
	vaddr_t lva = L2_ROUND_BLOCK(kernend + kernend_extra);

	if (va >= fva && va < lva) {
		return true;
	}

	return false;
}

paddr_t
pmap_md_kernel_vaddr_to_paddr(vaddr_t va)
{

	if (pmap_md_kernel_vaddr_p(va)) {
		return KERN_VTOPHYS(va);
	}
	panic("%s: va %#" PRIxVADDR " not direct mapped!", __func__, va);
}


bool
pmap_md_direct_mapped_vaddr_p(vaddr_t va)
{
	if (!AARCH64_KVA_P(va))
		return false;

	paddr_t pa = AARCH64_KVA_TO_PA(va);
	if (physical_start <= pa && pa < physical_end)
		return true;

	return false;
}

paddr_t
pmap_md_direct_mapped_vaddr_to_paddr(vaddr_t va)
{

	return AARCH64_KVA_TO_PA(va);
}


bool
pmap_md_io_vaddr_p(vaddr_t va)
{

	if (pmap_devmap_find_va(va, PAGE_SIZE)) {
		return true;
	}
	return false;
}


paddr_t
pmap_md_pool_vtophys(vaddr_t va)
{

	KASSERT(AARCH64_KVA_P(va));
	//XXXNH Check actual RAM size

	return AARCH64_KVA_TO_PA(va);
}

vaddr_t
pmap_md_pool_phystov(paddr_t pa)
{

	return AARCH64_PA_TO_KVA(pa);
}

struct vm_page *pmap_md_alloc_poolpage(int);

void
pmap_bootstrap(vaddr_t vstart, vaddr_t vend)
{
	UVMHIST_FUNC(__func__); UVMHIST_CALLED(maphist);

	pmap_t pm = pmap_kernel();

	/*
	 * Initialise the kernel pmap object
	 */
	curcpu()->ci_pmap_cur = pm;
#if 0
	/* uvmexp.ncolors = icachesize / icacheways / PAGE_SIZE; */
	uvmexp.ncolors = aarch64_cache_vindexsize / PAGE_SIZE;

	/* devmap already uses last of va? */
	if ((virtual_devmap_addr != 0) && (virtual_devmap_addr < vend))
		vend = virtual_devmap_addr;

#endif

	virtual_avail = vstart;
	virtual_end = vend;

	aarch64_tlbi_all();

	pm->pm_l0_pa = __SHIFTOUT(reg_ttbr1_el1_read(), TTBR_BADDR);
	pm->pm_pdetab = (pmap_pdetab_t *)AARCH64_PA_TO_KVA(pm->pm_l0_pa);
	pm->pm_l0 = (pd_entry_t *)pm->pm_pdetab;

	VPRINTF("locks ");
	mutex_init(&pm->pm_obj_lock, MUTEX_DEFAULT, IPL_VM);
	uvm_obj_init(&pm->pm_uobject, NULL, false, 1);
	uvm_obj_setlock(&pm->pm_uobject, &pm->pm_obj_lock);

//	TAILQ_INIT(&pmap->pm_pvp_list);
	TAILQ_INIT(&pm->pm_ptp_list);

#if defined(PMAP_HWPAGEWALKER)
	TAILQ_INIT(&pm->pm_pdetab_list);
#endif
#if !defined(PMAP_HWPAGEWALKER) || !defined(PMAP_MAP_POOLPAGE)
	TAILQ_INIT(&pm->pm_segtab_list);
#endif

	VPRINTF("tlb0 ");
	pmap_tlb_info_init(&pmap_tlb0_info);

#ifdef MULTIPROCESSOR
	VPRINTF("kcpusets ");

	kcpuset_create(&pm->pm_onproc, true);
	kcpuset_create(&pm->pm_active, true);
	KASSERT(pm->pm_onproc != NULL);
	KASSERT(pm->pm_active != NULL);
	kcpuset_set(pm->pm_onproc, cpu_number());
	kcpuset_set(pm->pm_active, cpu_number());
#endif

	VPRINTF("specials ");

	/*
	 * does VIPT exist for aarch64?
	 */
	//nptes = 1

#if 0
	pmap_alloc_specials(&virtual_avail, nptes, &csrcp, &csrc_pte);
	pmap_set_pt_cache_mode(l1pt, (vaddr_t)csrc_pte, nptes);
	pmap_alloc_specials(&virtual_avail, nptes, &cdstp, &cdst_pte);
	pmap_set_pt_cache_mode(l1pt, (vaddr_t)cdst_pte, nptes);
	pmap_alloc_specials(&virtual_avail, nptes, &memhook, NULL);
	if (msgbufaddr == NULL) {
		pmap_alloc_specials(&virtual_avail,
		    round_page(MSGBUFSIZE) / PAGE_SIZE,
		    (void *)&msgbufaddr, NULL);
	}
#endif


	/*
	 * Initialize `FYI' variables.	Note we're relying on
	 * the fact that BSEARCH sorts the vm_physmem[] array
	 * for us.  Must do this before uvm_pageboot_alloc()
	 * can be called.
	 */
	pmap_limits.avail_start = ptoa(uvm_physseg_get_start(uvm_physseg_get_first()));
	pmap_limits.avail_end = ptoa(uvm_physseg_get_end(uvm_physseg_get_last()));


        pmap_limits.virtual_start = virtual_avail;
        pmap_limits.virtual_end = virtual_end;

	pool_init(&pmap_pmap_pool, PMAP_SIZE, 0, 0, 0, "pmappl",
	    &pool_allocator_nointr, IPL_NONE);
	pool_init(&pmap_pv_pool, sizeof(struct pv_entry), 0, 0, 0, "pvpl",
	    &pmap_pv_page_allocator, IPL_NONE);

	pmap_pvlist_lock_init(/*arm_dcache_align*/ 128);
}



void
pmap_md_init(void)
{

	//XXXNH implement this.
//	pmap_md_alloc_ephemeral_address_space(curcpu());
}

void
pmap_md_pdetab_activate(pmap_t pm, struct lwp *l)
{
	UVMHIST_FUNC(__func__); UVMHIST_CALLED(maphist);

	/*
	 * Assume that TTBR1 has only global mappings and TTBR0 only
	 * has non-global mappings.  To prevent speculation from doing
	 * evil things we disable translation table walks using TTBR0
	 * before setting the CONTEXTIDR (ASID) or new TTBR0 value.
	 * Once both are set, table walks are reenabled.
	 */

//XXXNH check this against the ARM ARMv8

	const uint64_t old_tcrel1 = reg_tcr_el1_read();
	reg_tcr_el1_write(old_tcrel1 | TCR_EPD0);
	arm_isb();

	struct cpu_info * const ci = curcpu();
	struct pmap_asid_info * const pai = PMAP_PAI(pm, cpu_tlb_info(ci));

	uint64_t ttbr =
	    __SHIFTIN(pai->pai_asid, TTBR_ASID) |
	    __SHIFTIN(pm->pm_l0_pa, TTBR_BADDR);

	cpu_set_ttbr0(ttbr);

	if (pm != pmap_kernel()) {
		reg_tcr_el1_write(old_tcrel1 & ~TCR_EPD0);
	}

	UVMHIST_LOG(maphist, " pm %#jx pm->pm_l1 %016jx pm->pm_l0_pa %016jx asid %ju... done",
	    (uintptr_t)pm, (uintptr_t)pm->pm_l0, (uintptr_t)pm->pm_l0_pa,
	    (uintptr_t)pai->pai_asid);

	KASSERTMSG(ci->ci_pmap_asid_cur == pai->pai_asid, "%u vs %u",
	    ci->ci_pmap_asid_cur, pai->pai_asid);
	ci->ci_pmap_cur = pm;
}

void
pmap_md_pdetab_deactivate(pmap_t pm)
{
	UVMHIST_FUNC(__func__); UVMHIST_CALLED(maphist);

	kpreempt_disable();
	struct cpu_info * const ci = curcpu();
	/*
	 * Disable translation table walks from TTBR0 while no pmap has been
	 * activated.
	 */
	const uint64_t old_tcrel1 = reg_tcr_el1_read();
	reg_tcr_el1_write(old_tcrel1 | TCR_EPD0);
	arm_isb();

	//XXXNH needed cf TCR_EPD0
	cpu_set_ttbr0(0);

	ci->ci_pmap_cur = pmap_kernel();
	KASSERTMSG(ci->ci_pmap_asid_cur == KERNEL_PID, "ci_pmap_asid_cur %u",
	    ci->ci_pmap_asid_cur);
	kpreempt_enable();
}

void
pmap_md_pdetab_init(struct pmap *pm)
{

	KASSERT(pm != NULL);

	pm->pm_l0 = (pd_entry_t *)pm->pm_pdetab;
	pmap_extract(pmap_kernel(), (vaddr_t)pm->pm_l0, &pm->pm_l0_pa);
}

void
pmap_md_pdetab_destroy(struct pmap *pm)
{

	KASSERT(pm != NULL);
}

vaddr_t
pmap_md_direct_map_paddr(paddr_t pa)
{

	return AARCH64_PA_TO_KVA(pa);
}


#if 0

//XXXNH see "common" comment above
u_int
arm32_mmap_flags(paddr_t pa)
{
	/*
	 * the upper 8 bits in pmap_enter()'s flags are reserved for MD stuff
	 * and we're using the upper bits in page numbers to pass flags around
	 * so we might as well use the same bits
	 */
	return (u_int)pa & PMAP_MD_MASK;
}
#endif


#ifdef PMAP_VIRTUAL_CACHE_ALIASES

static void
pmap_md_vca_page_wbinv(struct vm_page *pg, bool locked_p)
{
	UVMHIST_FUNC(__func__); UVMHIST_CALLED(pmaphist);
#ifdef needtowrite
	pt_entry_t pte;

	const register_t va = pmap_md_map_ephemeral_page(pg, locked_p,
	    VM_PROT_READ, &pte);

	mips_dcache_wbinv_range(va, PAGE_SIZE);

	pmap_md_unmap_ephemeral_page(pg, locked_p, va, pte);
#endif
}
#endif


void
pmap_md_page_syncicache(struct vm_page *pg, const kcpuset_t *onproc)
{
	UVMHIST_FUNC(__func__); UVMHIST_CALLED(pmaphist);
#ifdef needtowrite
	struct mips_options * const opts = &mips_options;
	if (opts->mips_cpu_flags & CPU_MIPS_I_D_CACHE_COHERENT)
		return;

	struct vm_page_md * const mdpg = VM_PAGE_TO_MD(pg);

	/*
	 * If onproc is empty, we could do a
	 * pmap_page_protect(pg, VM_PROT_NONE) and remove all
	 * mappings of the page and clear its execness.  Then
	 * the next time page is faulted, it will get icache
	 * synched.  But this is easier. :)
	 */
	if (MIPS_HAS_R4K_MMU) {
		if (VM_PAGEMD_CACHED_P(mdpg)) {
			/* This was probably mapped cached by UBC so flush it */
			pt_entry_t pte;
			const register_t tva = pmap_md_map_ephemeral_page(pg, false,
			    VM_PROT_READ, &pte);

			UVMHIST_LOG(pmaphist, "  va %#"PRIxVADDR, tva, 0, 0, 0);
			mips_dcache_wbinv_range(tva, PAGE_SIZE);
			mips_icache_sync_range(tva, PAGE_SIZE);

			pmap_md_unmap_ephemeral_page(pg, false, tva, pte);
		}
	} else {
		mips_icache_sync_range(MIPS_PHYS_TO_KSEG0(VM_PAGE_TO_PHYS(pg)),
		    PAGE_SIZE);
	}
#ifdef MULTIPROCESSOR
	pv_entry_t pv = &mdpg->mdpg_first;
	const register_t va = (intptr_t)trunc_page(pv->pv_va);
	pmap_tlb_syncicache(va, onproc);
#endif
#endif
}


bool
pmap_md_ok_to_steal_p(const uvm_physseg_t bank, size_t npgs)
{
#ifdef needtowrite
	if (uvm_physseg_get_avail_start(bank) + npgs >= atop(MIPS_PHYS_MASK + 1)) {
		aprint_debug("%s: seg not enough in KSEG0 for %zu pages\n",
		    __func__, npgs);
		return false;
	}
#endif

	if (uvm_physseg_get_avail_start(bank) + npgs >= atop(physical_start + 1 * 1024 * 1024 * 1024)) {
		aprint_debug("%s: not enough space in direct map for %zu pages (%lx - %lx)\n",
		    __func__, npgs, uvm_physseg_get_avail_start(bank), uvm_physseg_get_avail_end(bank));
		return false;
	}

	return true;
}

#ifdef PMAP_VIRTUAL_CACHE_ALIASES

bool
pmap_md_vca_add(struct vm_page *pg, vaddr_t va, pt_entry_t *ptep)
{
	UVMHIST_FUNC(__func__); UVMHIST_CALLED(pmaphist);
#ifdef needtowrite
	struct vm_page_md * const mdpg = VM_PAGE_TO_MD(pg);
	if (!MIPS_HAS_R4K_MMU || !MIPS_CACHE_VIRTUAL_ALIAS)
		return false;

	/*
	 * There is at least one other VA mapping this page.
	 * Check if they are cache index compatible.
	 */

	KASSERT(VM_PAGEMD_PVLIST_LOCKED_P(mdpg));
	pv_entry_t pv = &mdpg->mdpg_first;
#if defined(PMAP_NO_PV_UNCACHED)
	/*
	 * Instead of mapping uncached, which some platforms
	 * cannot support, remove incompatible mappings from others pmaps.
	 * When this address is touched again, the uvm will
	 * fault it in.  Because of this, each page will only
	 * be mapped with one index at any given time.
	 *
	 * We need to deal with all entries on the list - if the first is
	 * incompatible with the new mapping then they all will be.
	 */
	if (__predict_true(!mips_cache_badalias(pv->pv_va, va))) {
		return false;
	}
	KASSERT(pv->pv_pmap != NULL);
	bool ret = false;
	for (pv_entry_t npv = pv; npv && npv->pv_pmap;) {
		if (npv->pv_va & PV_KENTER) {
			npv = npv->pv_next;
			continue;
		}
		ret = true;
		vaddr_t nva = trunc_page(npv->pv_va);
		pmap_t npm = npv->pv_pmap;
		VM_PAGEMD_PVLIST_UNLOCK(mdpg);
		pmap_remove(npm, nva, nva + PAGE_SIZE);

		/*
		 * pmap_update is not required here as we're the pmap
		 * and we know that the invalidation happened or the
		 * asid has been released (and activation is deferred)
		 *
		 * A deferred activation should NOT occur here.
		 */
		(void)VM_PAGEMD_PVLIST_LOCK(mdpg);

		npv = pv;
	}
	KASSERT(ret == true);

	return ret;
#else	/* !PMAP_NO_PV_UNCACHED */
	if (VM_PAGEMD_CACHED_P(mdpg)) {
		/*
		 * If this page is cached, then all mappings
		 * have the same cache alias so we only need
		 * to check the first page to see if it's
		 * incompatible with the new mapping.
		 *
		 * If the mappings are incompatible, map this
		 * page as uncached and re-map all the current
		 * mapping as uncached until all pages can
		 * share the same cache index again.
		 */
		if (mips_cache_badalias(pv->pv_va, va)) {
			pmap_page_cache(pg, false);
			pmap_md_vca_page_wbinv(pg, true);
			*ptep = pte_cached_change(*ptep, false);
			PMAP_COUNT(page_cache_evictions);
		}
	} else {
		*ptep = pte_cached_change(*ptep, false);
		PMAP_COUNT(page_cache_evictions);
	}
	return false;
#endif	/* !PMAP_NO_PV_UNCACHED */
#endif


	return false;
}

void
pmap_md_vca_clean(struct vm_page *pg, int op)
{
	UVMHIST_FUNC(__func__); UVMHIST_CALLED(pmaphist);
#ifdef needtowrite
	if (!MIPS_HAS_R4K_MMU || !MIPS_CACHE_VIRTUAL_ALIAS)
		return;

	UVMHIST_LOG(pmaphist, "(pg=%p, op=%d)", pg, op, 0, 0);
	KASSERT(VM_PAGEMD_PVLIST_LOCKED_P(VM_PAGE_TO_MD(pg)));

	if (op == PMAP_WB || op == PMAP_WBINV) {
		pmap_md_vca_page_wbinv(pg, true);
	} else if (op == PMAP_INV) {
		KASSERT(op == PMAP_INV && false);
		//mips_dcache_inv_range_index(va, PAGE_SIZE);
	}
#endif
}

/*
 * In the PMAP_NO_PV_CACHED case, all conflicts are resolved at mapping
 * so nothing needs to be done in removal.
 */
void
pmap_md_vca_remove(struct vm_page *pg, vaddr_t va, bool dirty, bool last)
{
#ifdef needtowrite
#if !defined(PMAP_NO_PV_UNCACHED)
	struct vm_page_md * const mdpg = VM_PAGE_TO_MD(pg);
	if (!MIPS_HAS_R4K_MMU
	    || !MIPS_CACHE_VIRTUAL_ALIAS
	    || !VM_PAGEMD_UNCACHED_P(mdpg))
		return;

	KASSERT(kpreempt_disabled());
	KASSERT((va & PAGE_MASK) == 0);

	/*
	 * Page is currently uncached, check if alias mapping has been
	 * removed.  If it was, then reenable caching.
	 */
	(void)VM_PAGEMD_PVLIST_READLOCK(mdpg);
	pv_entry_t pv = &mdpg->mdpg_first;
	pv_entry_t pv0 = pv->pv_next;

	for (; pv0; pv0 = pv0->pv_next) {
		if (mips_cache_badalias(pv->pv_va, pv0->pv_va))
			break;
	}
	if (pv0 == NULL)
		pmap_page_cache(pg, true);
	VM_PAGEMD_PVLIST_UNLOCK(mdpg);
#endif
#endif
}

#endif

pd_entry_t *
pmap_l0table(struct pmap *pm)
{

	return pm->pm_l0;
}


static const struct pmap_devmap *pmap_devmap_table;
vaddr_t virtual_devmap_addr;

#define	L1_BLK_MAPPABLE_P(va, pa, size)					\
    ((((va) | (pa)) & L1_OFFSET) == 0 && (size) >= L1_SIZE)

#define	L2_BLK_MAPPABLE_P(va, pa, size)					\
    ((((va) | (pa)) & L2_OFFSET) == 0 && (size) >= L2_SIZE)

static vsize_t
pmap_map_chunk(vaddr_t va, paddr_t pa, vsize_t size,
    vm_prot_t prot, u_int flags)
{
	pt_entry_t attr;
	psize_t blocksize;
	int rc;

	vsize_t resid = round_page(size);
	vsize_t mapped = 0;

	while (resid > 0) {
		if (L1_BLK_MAPPABLE_P(va, pa, resid)) {
			blocksize = L1_SIZE;
			attr = L1_BLOCK;
		} else if (L2_BLK_MAPPABLE_P(va, pa, resid)) {
			blocksize = L2_SIZE;
			attr = L2_BLOCK;
		} else {
			blocksize = L3_SIZE;
			attr = L3_PAGE;
		}

		pt_entry_t pte = pte_make_kenter_pa(pa, NULL, prot, flags);
		pte &= ~LX_TYPE;
		attr |= pte;

		rc = pmapboot_enter(va, pa, blocksize, blocksize, attr, NULL);
		if (rc != 0)
			panic("%s: pmapboot_enter failed. %lx is already mapped?\n",
			    __func__, va);

		va += blocksize;
		pa += blocksize;
		resid -= blocksize;
		mapped += blocksize;

		aarch64_tlbi_by_va(va);
	}

	return mapped;
}



void
pmap_devmap_register(const struct pmap_devmap *table)
{
	pmap_devmap_table = table;
}

void
pmap_devmap_bootstrap(vaddr_t l0pt, const struct pmap_devmap *table)
{
	vaddr_t va;
	int i;

	pmap_devmap_register(table);

	VPRINTF("%s:\n", __func__);
	for (i = 0; table[i].pd_size != 0; i++) {
		VPRINTF(" devmap: pa %08lx-%08lx = va %016lx\n",
		    table[i].pd_pa,
		    table[i].pd_pa + table[i].pd_size - 1,
		    table[i].pd_va);
		va = table[i].pd_va;

		KASSERT((VM_KERNEL_IO_ADDRESS <= va) &&
		    (va < (VM_KERNEL_IO_ADDRESS + VM_KERNEL_IO_SIZE)));

		/* update and check virtual_devmap_addr */
		if ((virtual_devmap_addr == 0) ||
		    (virtual_devmap_addr > va)) {
			virtual_devmap_addr = va;
		}

		pmap_map_chunk(
		    table[i].pd_va,
		    table[i].pd_pa,
		    table[i].pd_size,
		    table[i].pd_prot,
		    table[i].pd_flags);
	}

	pmap_devmap_bootstrap_done = true;
}

const struct pmap_devmap *
pmap_devmap_find_va(vaddr_t va, vsize_t size)
{
	paddr_t endva;
	int i;

	if (pmap_devmap_table == NULL)
		return NULL;

	endva = va + size;
	for (i = 0; pmap_devmap_table[i].pd_size != 0; i++) {
		if ((va >= pmap_devmap_table[i].pd_va) &&
		    (endva <= pmap_devmap_table[i].pd_va +
		              pmap_devmap_table[i].pd_size)) {
			return &pmap_devmap_table[i];
		}
	}
	return NULL;
}

const struct pmap_devmap *
pmap_devmap_find_pa(paddr_t pa, psize_t size)
{
	paddr_t endpa;
	int i;

	if (pmap_devmap_table == NULL)
		return NULL;

	endpa = pa + size;
	for (i = 0; pmap_devmap_table[i].pd_size != 0; i++) {
		if (pa >= pmap_devmap_table[i].pd_pa &&
		    (endpa <= pmap_devmap_table[i].pd_pa +
		              pmap_devmap_table[i].pd_size))
			return (&pmap_devmap_table[i]);
	}
	return NULL;
}


#ifdef MULTIPROCESSOR
void
pmap_md_tlb_info_attach(struct pmap_tlb_info *ti, struct cpu_info *ci)
{
	/* nothing */
}
#endif /* MULTIPROCESSOR */
