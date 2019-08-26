#ifndef KVM_UNIFDEF_H
#define KVM_UNIFDEF_H

#ifdef __i386__
#ifndef CONFIG_X86_32
#define CONFIG_X86_32 1
#endif
#endif

#ifdef __x86_64__
#ifndef CONFIG_X86_64
#define CONFIG_X86_64 1
#endif
#endif

#if defined(__i386__) || defined (__x86_64__)
#ifndef CONFIG_X86
#define CONFIG_X86 1
#endif
#endif

#ifdef __PPC__
#ifndef CONFIG_PPC
#define CONFIG_PPC 1
#endif
#endif

#ifdef __s390__
#ifndef CONFIG_S390
#define CONFIG_S390 1
#endif
#endif

#endif
/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KVM_CLOCK_H
#define _ASM_X86_KVM_CLOCK_H

extern struct clocksource kvm_clock;

#endif /* _ASM_X86_KVM_CLOCK_H */
