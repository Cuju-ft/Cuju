// Cuju Add file
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
/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * timer support
 *
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/hrtimer.h>
#include <linux/atomic.h>
#include "kvm_timer.h"

enum hrtimer_restart kvm_timer_fn(struct hrtimer *data)
{
	struct kvm_timer *ktimer = container_of(data, struct kvm_timer, timer);
	struct kvm_vcpu *vcpu = ktimer->vcpu;
	//wait_queue_head_t *q = &vcpu->wq;	// Cuju
	struct swait_queue_head *q = &vcpu->wq;	// Cuju

	/*
	 * There is a race window between reading and incrementing, but we do
	 * not care about potentially losing timer events in the !reinject
	 * case anyway. Note: KVM_REQ_PENDING_TIMER is implicitly checked
	 * in vcpu_enter_guest.
	 */
	if (ktimer->reinject || !atomic_read(&ktimer->pending)) {
		atomic_inc(&ktimer->pending);
		/* FIXME: this code should not know anything about vcpus */
		kvm_make_request(KVM_REQ_PENDING_TIMER, vcpu);
	}

	// Cuju Begin
	//if (waitqueue_active(q))
	//	wake_up_interruptible(q);
	/*
	 * For x86, the atomic_inc() is serialized, thus
	 * using swait_active() is safe.
	 */
	if (swait_active(q))
		swake_up(q);
	// Cuju End

	if (ktimer->t_ops->is_periodic(ktimer)) {
		//kvm_hrtimer_add_expires_ns(&ktimer->timer, ktimer->period);	// Cuju
		hrtimer_add_expires_ns(&ktimer->timer, ktimer->period);	// Cuju
		return HRTIMER_RESTART;
	} else
		return HRTIMER_NORESTART;
}
