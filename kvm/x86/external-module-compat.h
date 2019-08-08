
/*
 * Compatibility header for building as an external module.
 */

#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/kconfig.h>

#include <linux/types.h>

#include <asm/cpufeature.h>

#include "../external-module-compat-comm.h"

#include <asm/msr.h>
#include <asm/asm.h>
#include <asm/desc.h>

#ifndef CONFIG_HAVE_KVM_EVENTFD
#define CONFIG_HAVE_KVM_EVENTFD 1
#endif

// Cuju Begin
/*
#ifndef CONFIG_KVM_GENERIC_DIRTYLOG_READ_PROTECT
#define CONFIG_KVM_GENERIC_DIRTYLOG_READ_PROTECT 1
#endif
*/
// Cuju End

#ifndef CONFIG_KVM_APIC_ARCHITECTURE
#define CONFIG_KVM_APIC_ARCHITECTURE
#endif

#ifndef CONFIG_KVM_MMIO
#define CONFIG_KVM_MMIO
#endif

#ifndef CONFIG_KVM_ASYNC_PF
#define CONFIG_KVM_ASYNC_PF 1
#endif

#ifndef CONFIG_HAVE_KVM_MSI
#define CONFIG_HAVE_KVM_MSI 1
#endif

#ifndef CONFIG_HAVE_KVM_IRQCHIP
#define CONFIG_HAVE_KVM_IRQCHIP 1
#endif

#ifndef CONFIG_HAVE_KVM_IRQ_ROUTING
#define CONFIG_HAVE_KVM_IRQ_ROUTING 1
#endif

#ifndef CONFIG_HAVE_KVM_IRQFD
#define CONFIG_HAVE_KVM_IRQFD 1
#endif

#ifndef CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT
#define CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT 1
#endif

#include <linux/smp.h>