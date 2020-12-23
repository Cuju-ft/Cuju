
/*
 * Compatibility header for building as an external module.
 */

/*
 * Avoid picking up the kernel's kvm.h in case we have a newer one.
 */

#include <linux/compiler.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/kvm.h>
#include <linux/kvm_para.h>
#include <linux/kconfig.h>
#include <linux/cpu.h>
//#include <linux/pci.h>    // Cuju
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/kernel.h>
#include <linux/swait.h>
#include <linux/compat.h>
#include <asm/processor.h>
#include <linux/hrtimer.h>
#include <asm/bitops.h>
#include <linux/kconfig.h>

#include "kvm-kmod-config.h"


