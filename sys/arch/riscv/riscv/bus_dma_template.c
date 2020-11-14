/*	$NetBSD: bus_dma.c,v 1.124 2020/10/24 14:51:59 skrll Exp $	*/

/*-
 * Copyright (c) 1996, 1997, 1998, 2020 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
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

#define _RISCV_BUS_DMA_PRIVATE

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>

#include <sys/bus.h>
#include <sys/cpu.h>
#include <sys/kmem.h>
#include <sys/mbuf.h>

#include <uvm/uvm.h>


/*
 * Common function for DMA map creation.  May be called by bus-specific
 * DMA map creation functions.
 */
int
_bus_dmamap_create(bus_dma_tag_t t, bus_size_t size, int nsegments,
    bus_size_t maxsegsz, bus_size_t boundary, int flags, bus_dmamap_t *dmamp)
{

	return 0;
}

/*
 * Common function for DMA map destruction.  May be called by bus-specific
 * DMA map destruction functions.
 */
void
_bus_dmamap_destroy(bus_dma_tag_t t, bus_dmamap_t map)
{
}

/*
 * Common function for loading a DMA map with a linear buffer.  May
 * be called by bus-specific DMA map load functions.
 */
int
_bus_dmamap_load(bus_dma_tag_t t, bus_dmamap_t map, void *buf,
    bus_size_t buflen, struct proc *p, int flags)
{
	return 0;
}

/*
 * Like _bus_dmamap_load(), but for mbufs.
 */
int
_bus_dmamap_load_mbuf(bus_dma_tag_t t, bus_dmamap_t map, struct mbuf *m0,
    int flags)
{
	return 0;
}

/*
 * Like _bus_dmamap_load(), but for uios.
 */
int
_bus_dmamap_load_uio(bus_dma_tag_t t, bus_dmamap_t map, struct uio *uio,
    int flags)
{
	return 0;
}

/*
 * Like _bus_dmamap_load(), but for raw memory allocated with
 * bus_dmamem_alloc().
 */
int
_bus_dmamap_load_raw(bus_dma_tag_t t, bus_dmamap_t map,
    bus_dma_segment_t *segs, int nsegs, bus_size_t size0, int flags)
{
	return 0;
}

/*
 * Common function for unloading a DMA map.  May be called by
 * bus-specific DMA map unload functions.
 */
void
_bus_dmamap_unload(bus_dma_tag_t t, bus_dmamap_t map)
{
}

#if 0
static void
_bus_dmamap_sync_segment(vaddr_t va, paddr_t pa, vsize_t len, int ops,
    bool readonly_p)
{

#if defined(ARM_MMU_EXTENDED)
	/*
	 * No optimisations are available for readonly mbufs on armv6+, so
	 * assume it's not readonly from here on.
	 *
 	 * See the comment in _bus_dmamap_sync_mbuf
	 */
	readonly_p = false;
#endif

	KASSERTMSG((va & PAGE_MASK) == (pa & PAGE_MASK),
	    "va %#lx pa %#lx", va, pa);
#if 0
	printf("sync_segment: va=%#lx pa=%#lx len=%#lx ops=%#x ro=%d\n",
	    va, pa, len, ops, readonly_p);
#endif

	switch (ops) {
	case BUS_DMASYNC_PREREAD|BUS_DMASYNC_PREWRITE:
		if (!readonly_p) {
			STAT_INCR(sync_prereadwrite);
			cpu_dcache_wbinv_range(va, len);
			cpu_sdcache_wbinv_range(va, pa, len);
			break;
		}
		/* FALLTHROUGH */

	case BUS_DMASYNC_PREREAD: {
		const size_t line_size = arm_dcache_align;
		const size_t line_mask = arm_dcache_align_mask;
		vsize_t misalignment = va & line_mask;
		if (misalignment) {
			va -= misalignment;
			pa -= misalignment;
			len += misalignment;
			STAT_INCR(sync_preread_begin);
			cpu_dcache_wbinv_range(va, line_size);
			cpu_sdcache_wbinv_range(va, pa, line_size);
			if (len <= line_size)
				break;
			va += line_size;
			pa += line_size;
			len -= line_size;
		}
		misalignment = len & line_mask;
		len -= misalignment;
		if (len > 0) {
			STAT_INCR(sync_preread);
			cpu_dcache_inv_range(va, len);
			cpu_sdcache_inv_range(va, pa, len);
		}
		if (misalignment) {
			va += len;
			pa += len;
			STAT_INCR(sync_preread_tail);
			cpu_dcache_wbinv_range(va, line_size);
			cpu_sdcache_wbinv_range(va, pa, line_size);
		}
		break;
	}

	case BUS_DMASYNC_PREWRITE:
		STAT_INCR(sync_prewrite);
		cpu_dcache_wb_range(va, len);
		cpu_sdcache_wb_range(va, pa, len);
		break;

#if defined(CPU_CORTEX) || defined(CPU_ARMV8)

	/*
	 * Cortex CPUs can do speculative loads so we need to clean the cache
	 * after a DMA read to deal with any speculatively loaded cache lines.
	 * Since these can't be dirty, we can just invalidate them and don't
	 * have to worry about having to write back their contents.
	 */
	case BUS_DMASYNC_POSTREAD|BUS_DMASYNC_POSTWRITE:
		STAT_INCR(sync_postreadwrite);
		cpu_dcache_inv_range(va, len);
		cpu_sdcache_inv_range(va, pa, len);
		break;
	case BUS_DMASYNC_POSTREAD:
		STAT_INCR(sync_postread);
		cpu_dcache_inv_range(va, len);
		cpu_sdcache_inv_range(va, pa, len);
		break;
#endif
	}
}

static inline void
_bus_dmamap_sync_linear(bus_dma_tag_t t, bus_dmamap_t map, bus_addr_t offset,
    bus_size_t len, int ops)
{
	bus_dma_segment_t *ds = map->dm_segs;
	vaddr_t va = (vaddr_t) map->_dm_origbuf;
#ifdef _RISCV_NEED_BUS_DMA_BOUNCE
	if (map->_dm_flags & _BUS_DMAMAP_IS_BOUNCING) {
		struct arm32_bus_dma_cookie * const cookie = map->_dm_cookie;
		va = (vaddr_t) cookie->id_bouncebuf;
	}
#endif

	while (len > 0) {
		while (offset >= ds->ds_len) {
			offset -= ds->ds_len;
			va += ds->ds_len;
			ds++;
		}

		paddr_t pa = _bus_dma_busaddr_to_paddr(t, ds->ds_addr + offset);
		size_t seglen = uimin(len, ds->ds_len - offset);

		if ((ds->_ds_flags & _BUS_DMAMAP_COHERENT) == 0)
			_bus_dmamap_sync_segment(va + offset, pa, seglen, ops,
			    false);

		offset += seglen;
		len -= seglen;
	}
}

static inline void
_bus_dmamap_sync_mbuf(bus_dma_tag_t t, bus_dmamap_t map, bus_size_t offset,
    bus_size_t len, int ops)
{
	bus_dma_segment_t *ds = map->dm_segs;
	struct mbuf *m = map->_dm_origbuf;
	bus_size_t voff = offset;
	bus_size_t ds_off = offset;

	while (len > 0) {
		/* Find the current dma segment */
		while (ds_off >= ds->ds_len) {
			ds_off -= ds->ds_len;
			ds++;
		}
		/* Find the current mbuf. */
		while (voff >= m->m_len) {
			voff -= m->m_len;
			m = m->m_next;
		}

		/*
		 * Now at the first mbuf to sync; nail each one until
		 * we have exhausted the length.
		 */
		vsize_t seglen = uimin(len, uimin(m->m_len - voff, ds->ds_len - ds_off));
		vaddr_t va = mtod(m, vaddr_t) + voff;
		paddr_t pa = _bus_dma_busaddr_to_paddr(t, ds->ds_addr + ds_off);

		/*
		 * We can save a lot of work here if we know the mapping
		 * is read-only at the MMU and we aren't using the armv6+
		 * MMU:
		 *
		 * If a mapping is read-only, no dirty cache blocks will
		 * exist for it.  If a writable mapping was made read-only,
		 * we know any dirty cache lines for the range will have
		 * been cleaned for us already.  Therefore, if the upper
		 * layer can tell us we have a read-only mapping, we can
		 * skip all cache cleaning.
		 *
		 * NOTE: This only works if we know the pmap cleans pages
		 * before making a read-write -> read-only transition.  If
		 * this ever becomes non-true (e.g. Physically Indexed
		 * cache), this will have to be revisited.
		 */

		if ((ds->_ds_flags & _BUS_DMAMAP_COHERENT) == 0) {
			/*
			 * If we are doing preread (DMAing into the mbuf),
			 * this mbuf better not be readonly,
			 */
			KASSERT(!(ops & BUS_DMASYNC_PREREAD) || !M_ROMAP(m));
			_bus_dmamap_sync_segment(va, pa, seglen, ops,
			    M_ROMAP(m));
		}
		voff += seglen;
		ds_off += seglen;
		len -= seglen;
	}
}

static inline void
_bus_dmamap_sync_uio(bus_dma_tag_t t, bus_dmamap_t map, bus_addr_t offset,
    bus_size_t len, int ops)
{
	bus_dma_segment_t *ds = map->dm_segs;
	struct uio *uio = map->_dm_origbuf;
	struct iovec *iov = uio->uio_iov;
	bus_size_t voff = offset;
	bus_size_t ds_off = offset;

	while (len > 0) {
		/* Find the current dma segment */
		while (ds_off >= ds->ds_len) {
			ds_off -= ds->ds_len;
			ds++;
		}

		/* Find the current iovec. */
		while (voff >= iov->iov_len) {
			voff -= iov->iov_len;
			iov++;
		}

		/*
		 * Now at the first iovec to sync; nail each one until
		 * we have exhausted the length.
		 */
		vsize_t seglen = uimin(len, uimin(iov->iov_len - voff, ds->ds_len - ds_off));
		vaddr_t va = (vaddr_t) iov->iov_base + voff;
		paddr_t pa = _bus_dma_busaddr_to_paddr(t, ds->ds_addr + ds_off);

		if ((ds->_ds_flags & _BUS_DMAMAP_COHERENT) == 0)
			_bus_dmamap_sync_segment(va, pa, seglen, ops, false);

		voff += seglen;
		ds_off += seglen;
		len -= seglen;
	}
}
#endif

/*
 * Common function for DMA map synchronization.  May be called
 * by bus-specific DMA map synchronization functions.
 *
 * XXX Should have separate versions for write-through vs.
 * XXX write-back caches.  We currently assume write-back
 * XXX here, which is not as efficient as it could be for
 * XXX the write-through case.
 */
void
_bus_dmamap_sync(bus_dma_tag_t t, bus_dmamap_t map, bus_addr_t offset,
    bus_size_t len, int ops)
{
}

/*
 * Common function for DMA-safe memory allocation.  May be called
 * by bus-specific DMA memory allocation functions.
 */

extern paddr_t physical_start;
extern paddr_t physical_end;

int
_bus_dmamem_alloc(bus_dma_tag_t t, bus_size_t size, bus_size_t alignment,
    bus_size_t boundary, bus_dma_segment_t *segs, int nsegs, int *rsegs,
    int flags)
{
	return 0;
}

/*
 * Common function for freeing DMA-safe memory.  May be called by
 * bus-specific DMA memory free functions.
 */
void
_bus_dmamem_free(bus_dma_tag_t t, bus_dma_segment_t *segs, int nsegs)
{
}

/*
 * Common function for mapping DMA-safe memory.  May be called by
 * bus-specific DMA memory map functions.
 */
int
_bus_dmamem_map(bus_dma_tag_t t, bus_dma_segment_t *segs, int nsegs,
    size_t size, void **kvap, int flags)
{
	return 0;
}

/*
 * Common function for unmapping DMA-safe memory.  May be called by
 * bus-specific DMA memory unmapping functions.
 */
void
_bus_dmamem_unmap(bus_dma_tag_t t, void *kva, size_t size)
{
}

/*
 * Common functin for mmap(2)'ing DMA-safe memory.  May be called by
 * bus-specific DMA mmap(2)'ing functions.
 */
paddr_t
_bus_dmamem_mmap(bus_dma_tag_t t, bus_dma_segment_t *segs, int nsegs,
    off_t off, int prot, int flags)
{
	return 0;
}

int
_bus_dmatag_subregion(bus_dma_tag_t tag, bus_addr_t min_addr,
    bus_addr_t max_addr, bus_dma_tag_t *newtag, int flags)
{
	if (min_addr >= max_addr)
		return EOPNOTSUPP;

	return 0;
}

void
_bus_dmatag_destroy(bus_dma_tag_t tag)
{
}
