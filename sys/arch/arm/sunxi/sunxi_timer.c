/* $NetBSD: sunxi_timer.c,v 1.9 2021/01/27 03:10:20 thorpej Exp $ */

/*-
 * Copyright (c) 2017 Jared McNeill <jmcneill@invisible.ca>
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: sunxi_timer.c,v 1.9 2021/01/27 03:10:20 thorpej Exp $");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/intr.h>
#include <sys/systm.h>
#include <sys/timetc.h>

#include <arm/locore.h>

#include <dev/fdt/fdtvar.h>

#include <arm/fdt/arm_fdtvar.h>

/* Timer 0 registers */
#define	TMR_IRQ_EN_REG		0x00
#define	 TMR_IRQ_EN(n)		__BIT(n)
#define	TMR_IRQ_STAS_REG	0x04
#define	 TMR_IRQ_STAS_PEND(n)	__BIT(n)
#define	TMR0_CTRL_REG		0x10
#define	 TMR0_CTRL_MODE		__BIT(7)
#define	 TMR0_CTRL_CLK_PRESCALE	__BITS(6,4)
#define	 TMR0_CTRL_CLK_SRC	__BITS(3,2)
#define	  TMR0_CTRL_CLK_SRC_OSC24M	1
#define	  TMR0_CTRL_CLK_SRC_PLL6_6	2
#define	 TMR0_CTRL_RELOAD	__BIT(1)
#define	 TMR0_CTRL_EN		__BIT(0)
#define	TMR0_INTV_VALUE_REG	0x14
#define	TMR0_CURNT_VALUE_REG	0x18

/* Timer 1 is used for delay() */

/* Timer 2 registers */
#define	TMR2_CTRL_REG		0x30
#define	 TMR2_CTRL_MODE		__BIT(7)
#define	 TMR2_CTRL_CLK_SRC	__BITS(3,2)
#define	  TMR2_CTRL_CLK_SRC_OSC24M	1
#define	 TMR2_CTRL_RELOAD	__BIT(1)
#define	 TMR2_CTRL_EN		__BIT(0)
#define	TMR2_INTV_VALUE_REG	0x34
#define	TMR2_CURNT_VALUE_REG	0x38

/* Timer 4 registers */
#define	TMR4_CTRL_REG		0x50
#define	 TMR4_CTRL_RELOAD	__BIT(1)
#define	 TMR4_CTRL_EN		__BIT(0)
#define	TMR4_INTV_VALUE_REG	0x54
#define	TMR4_CURNT_VALUE_REG	0x58

/* Control registers */
#define	AVS_CNT_CTL_REG		0x80
#define	AVS_CNT0_REG		0x84
#define	AVS_CNT1_REG		0x88
#define	AVS_CNT_DIV_REG		0x8c
#define	WDOG_CTRL_REG		0x90
#define	WDOG_MODE_REG		0x94
#define	LOSC_CTRL_REG		0x100
#define	 LOSC_CTRL_KEY_FIELD	__BITS(31,16)
#define	 LOSC_CTRL_KEY_FIELD_V	0x16aa
#define  LOSC_CTRL_OSC32K_AUTO_SWT_EN	__BIT(14)
#define	 LOSC_CTRL_OSC32K_SEL	__BIT(0)

static const struct device_compatible_entry compat_data[] = {
	{ .compat = "allwinner,sun4i-a10-timer" },
	DEVICE_COMPAT_EOL
};

struct sunxi_timer_softc {
	device_t sc_dev;
	bus_space_tag_t sc_bst;
	bus_space_handle_t sc_bsh;
	int sc_phandle;
	struct clk *sc_clk;

	struct timecounter sc_tc;
	struct timecounter sc_tc_losc;
};

#define TIMER_READ(sc, reg) \
    bus_space_read_4((sc)->sc_bst, (sc)->sc_bsh, (reg))
#define TIMER_WRITE(sc, reg, val) \
    bus_space_write_4((sc)->sc_bst, (sc)->sc_bsh, (reg), (val))

static struct sunxi_timer_softc *timer_softc;

static int
sunxi_timer_intr(void *arg)
{
	struct sunxi_timer_softc * const sc = timer_softc;
	struct clockframe *frame = arg;
	uint32_t stas;

	stas = TIMER_READ(sc, TMR_IRQ_STAS_REG);
	if (stas == 0)
		return 0;
	TIMER_WRITE(sc, TMR_IRQ_STAS_REG, stas);

	if ((stas & TMR_IRQ_STAS_PEND(0)) != 0)
		hardclock(frame);

	return 1;
}

static void
sunxi_timer_cpu_initclocks(void)
{
	struct sunxi_timer_softc * const sc = timer_softc;
	char intrstr[128];
	void *ih;

	KASSERT(sc != NULL);

	if (!fdtbus_intr_str(sc->sc_phandle, 0, intrstr, sizeof(intrstr)))
		panic("%s: failed to decode interrupt", __func__);

	ih = fdtbus_intr_establish_xname(sc->sc_phandle, 0, IPL_CLOCK,
	    FDT_INTR_MPSAFE, sunxi_timer_intr, NULL, device_xname(sc->sc_dev));
	if (ih == NULL)
		panic("%s: failed to establish timer interrupt", __func__);

	aprint_normal_dev(sc->sc_dev, "interrupting on %s\n", intrstr);

	/* Enable Timer 0 IRQ */
	const uint32_t irq_en = TIMER_READ(sc, TMR_IRQ_EN_REG);
	TIMER_WRITE(sc, TMR_IRQ_EN_REG, irq_en | TMR_IRQ_EN(0));
}

static u_int
sunxi_timer_get_timecount(struct timecounter *tc)
{
	struct sunxi_timer_softc * const sc = tc->tc_priv;

	/* Timer current value is a 32-bit down counter. */
	return ~TIMER_READ(sc, TMR2_CURNT_VALUE_REG);
}

static u_int
sunxi_timer_get_timecount_losc(struct timecounter *tc)
{
	struct sunxi_timer_softc * const sc = tc->tc_priv;

	return ~TIMER_READ(sc, TMR4_CURNT_VALUE_REG);
}

static int
sunxi_timer_match(device_t parent, cfdata_t cf, void *aux)
{
	struct fdt_attach_args * const faa = aux;

	return of_compatible_match(faa->faa_phandle, compat_data);
}

static void
sunxi_timer_attach(device_t parent, device_t self, void *aux)
{
	struct sunxi_timer_softc * const sc = device_private(self);
	struct fdt_attach_args * const faa = aux;
	struct timecounter *tc = &sc->sc_tc;
	struct timecounter *tc_losc = &sc->sc_tc_losc;
	const int phandle = faa->faa_phandle;
	bus_addr_t addr;
	bus_size_t size;
	u_int ticks;
	u_int reg;

	if (fdtbus_get_reg(phandle, 0, &addr, &size) != 0) {
		aprint_error(": couldn't get registers\n");
		return;
	}

	if ((sc->sc_clk = fdtbus_clock_get_index(phandle, 0)) == NULL) {
		aprint_error(": couldn't get clock\n");
		return;
	}

	sc->sc_dev = self;
	sc->sc_phandle = phandle;
	sc->sc_bst = faa->faa_bst;
	if (bus_space_map(sc->sc_bst, addr, size, 0, &sc->sc_bsh) != 0) {
		aprint_error(": couldn't map registers\n");
		return;
	}

	aprint_naive("\n");
	aprint_normal(": Timer\n");

	const u_int rate = clk_get_rate(sc->sc_clk);

	/* Disable IRQs and all timers */
	TIMER_WRITE(sc, TMR_IRQ_EN_REG, 0);
	TIMER_WRITE(sc, TMR_IRQ_STAS_REG, TIMER_READ(sc, TMR_IRQ_STAS_REG));
	/* Enable Timer 0 (hardclock) */
	TIMER_WRITE(sc, TMR0_INTV_VALUE_REG, rate / hz);
	TIMER_WRITE(sc, TMR0_CTRL_REG,
	    __SHIFTIN(TMR0_CTRL_CLK_SRC_OSC24M, TMR0_CTRL_CLK_SRC) |
	    TMR0_CTRL_RELOAD | TMR0_CTRL_EN);
	/* Enable Timer 2 (timecounter) */
	TIMER_WRITE(sc, TMR2_INTV_VALUE_REG, ~0u);
	TIMER_WRITE(sc, TMR2_CTRL_REG,
	    __SHIFTIN(TMR2_CTRL_CLK_SRC_OSC24M, TMR2_CTRL_CLK_SRC) |
	    TMR2_CTRL_RELOAD | TMR2_CTRL_EN);
	/* Enable Timer 4 (timecounter for LOSC) */
	TIMER_WRITE(sc, TMR4_INTV_VALUE_REG, ~0u);
	TIMER_WRITE(sc, TMR4_CTRL_REG, TMR4_CTRL_RELOAD | TMR4_CTRL_EN);

	/* Timecounter setup */
	tc->tc_get_timecount = sunxi_timer_get_timecount;
	tc->tc_counter_mask = ~0u;
	tc->tc_frequency = rate;
	tc->tc_name = "Timer 2";
	tc->tc_quality = 200;
	tc->tc_priv = sc;
	tc_init(tc);
	tc_losc->tc_get_timecount = sunxi_timer_get_timecount_losc;
	tc_losc->tc_counter_mask = ~0u;
	tc_losc->tc_frequency = 32768;
	tc_losc->tc_name = "LOSC";
	tc_losc->tc_quality = 150;
	tc_losc->tc_priv = sc;
	/*
	 * LOSC is optional to implement in hardware.
	 * Make sure it ticks before registering it.
	 */
	reg = __SHIFTIN(LOSC_CTRL_KEY_FIELD_V, LOSC_CTRL_KEY_FIELD) |
	    LOSC_CTRL_OSC32K_AUTO_SWT_EN |
	    LOSC_CTRL_OSC32K_SEL;
	TIMER_WRITE(sc, LOSC_CTRL_REG, reg);
	ticks = sunxi_timer_get_timecount_losc(tc_losc);
	delay(100);
	if (ticks != sunxi_timer_get_timecount_losc(tc_losc))
		tc_init(tc_losc);
	else
		TIMER_WRITE(sc, LOSC_CTRL_REG, reg & ~LOSC_CTRL_OSC32K_SEL);

	/* Use this as the OS timer in UP configurations */
	if (!arm_has_mpext_p) {
		timer_softc = sc;
		arm_fdt_timer_register(sunxi_timer_cpu_initclocks);
	}
}

CFATTACH_DECL_NEW(sunxi_timer, sizeof(struct sunxi_timer_softc),
	sunxi_timer_match, sunxi_timer_attach, NULL, NULL);
