/* $NetBSD: asm.h,v 1.3 2018/07/17 18:08:37 christos Exp $ */

#ifndef _AARCH64_ASM_H_
#define _AARCH64_ASM_H_

#include <arm/asm.h>

#ifdef _LOCORE
.macro	adrl 	reg, addr
	adrp	\reg, \addr
	add	\reg, \reg, #:lo12:\addr
.endm
#endif

#define	fp	x29
#define	lr	x30

#endif /* !_AARCH64_ASM_H_ */
