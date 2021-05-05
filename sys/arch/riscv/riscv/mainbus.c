/*	$NetBSD: mainbus.c,v 1.3 2021/04/24 23:36:47 thorpej Exp $	*/

/*-
 * Copyright (c) 2014 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Matt Thomas of 3am Software Foundry.
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

#include "locators.h"
#include "opt_console.h"

#include <sys/cdefs.h>

__RCSID("$NetBSD: mainbus.c,v 1.3 2021/04/24 23:36:47 thorpej Exp $");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/systm.h>

#include <dev/fdt/fdtvar.h>

static int mainbus_match(device_t, cfdata_t, void *);
static void mainbus_attach(device_t, device_t, void *);

CFATTACH_DECL_NEW(mainbus, 0,
    mainbus_match, mainbus_attach, NULL, NULL);

#if 0

struct mainbus_attach_args {
	const char *maa_name;
	u_int maa_instance;
};


static int
mainbus_print(void *aux, const char *name)
{
	struct mainbus_attach_args * const maa = aux;

	if (maa->maa_instance != MAINBUSCF_INSTANCE_DEFAULT)
		printf(" instance %d", maa->maa_instance);

	return QUIET;
}
#endif

int
mainbus_match(device_t parent, cfdata_t cf, void *aux)
{
	//
	static int once = 0;

	if (once != 0)
		return 0;
	once = 1;

	return 1;
}

void
mainbus_attach(device_t parent, device_t self, void *aux)
{
	const struct fdt_console *cons = fdtbus_get_console();
//	struct mainbus_attach_args maa;
	struct fdt_attach_args faa;
//	u_int uart_freq;
#if 0
	aa.aa_name = "cpunode";
	config_found_sm_loc(self, "mainbus", NULL, &aa, mainbus_print,
	    mainbus_submatch);

	aa.aa_name = "iobus";
	config_found_sm_loc(self, "mainbus", NULL, &aa, mainbus_print,
	    mainbus_submatch);

	simplebus_bus_io_init(&simplebus_bus_tag, NULL);
#endif

#if 0
	faa.faa_bst = &simplebus_bus_tag;
	faa.faa_dmat = &simplebus_dma_tag;
	faa.faa_name = "";
#endif
	if (cons != NULL) {
		faa.faa_phandle = fdtbus_get_stdout_phandle();

#if 0
		if (of_getprop_uint32(faa.faa_phandle, "clock-frequency",
		    &uart_freq) != 0) {
			uart_freq = octeon_ioclock_speed();
		}

		if (uart_freq > 0)
			delay(640000000 / uart_freq);

		cons->consinit(&faa, uart_freq);
#endif
	}

	faa.faa_phandle = OF_peer(0);
	config_found(self, &faa, NULL, CFARG_EOL);
}



#define PBASE CONSADDR
#define VBASE (VM_KERNEL_VM_BASE + VM_KERNEL_VM_SIZE)

#include <dev/ic/ns16550reg.h>
#include <dev/ic/comreg.h>
#include <riscv/sysreg.h>


static inline bool
cpu_earlydevice_va_p(void)
{

	return __SHIFTOUT(riscvreg_satp_read(), SATP_MODE);
}


void com_platform_early_putchar(char);

void __noasan
com_platform_early_putchar(char c)
{
#ifdef CONSADDR
#define CONSADDR_VA	(CONSADDR - PBASE + VBASE)

	volatile uint8_t *uartaddr = cpu_earlydevice_va_p() ?
	    (volatile uint8_t *)CONSADDR_VA :
	    (volatile uint8_t *)CONSADDR;

	while ((uartaddr[com_lsr] & LSR_TXRDY) == 0)
		;

	uartaddr[com_data] = c;
#endif
}
