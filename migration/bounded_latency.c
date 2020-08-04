#include "qemu/osdep.h"
#include "migration/migration.h"
#include "migration/cuju-kvm-share-mem.h"
#include "sysemu/kvm.h"
#include <linux/kvm.h>
#include "qmp-commands.h"

void bd_set_timer_fire(void)
{
	int bd_time_slot_us = 1000;

	Error *err = NULL;
	qmp_cuju_adjust_epoch((unsigned int)bd_time_slot_us, &err);
	if (err) {
		error_report_err(err);
		return;
	}

}

int kvmft_bd_update_latency(MigrationState *s)
{
/*    struct kvmft_update_latency update;

    update.dirty_page = dirty_page;
    update.runtime_us = runtime_us;
    update.trans_us = trans_us;
    update.latency_us = latency_us;

    update.last_trans_rate = mybdupdate.last_trans_rate;

    return kvm_vm_ioctl(kvm_state, KVMFT_BD_UPDATE_LATENCY, &update);
	*/
//	int runtime_us = (int)((s->snapshot_start_time - s->run_real_start_time) * 1000000);
//	printf("runtime = %d\n", runtime_us);
	return 0;
}
