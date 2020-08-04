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

    int runtime_us = (int)((s->snapshot_start_time - s->run_real_start_time) * 1000000);
    int latency_us = (int)((s->recv_ack1_time - s->run_real_start_time) * 1000000);
    int trans_us = (int)((s->recv_ack1_time - s->snapshot_start_time) * 1000000);
	int dirty_len = s->ram_len;

	static unsigned long long total = 0;
	static unsigned long long totalruntime = 0;
	static unsigned long long totallatency = 0;
	static unsigned long long totaltrans = 0;
	static unsigned long long totaldirty = 0;
	static unsigned long long exceed = 0;
	static unsigned long long less = 0;
	static unsigned long long ok = 0;

	totalruntime += runtime_us;
	totallatency += latency_us;
	totaltrans   += trans_us;
	totaldirty   += dirty_len;

	total++;



	if(latency_us <= EPOCH_TIME_IN_MS*1000 + 1000 && latency_us >= EPOCH_TIME_IN_MS*1000 - 1000) {
		ok++;
	} else if (latency_us > EPOCH_TIME_IN_MS*1000+1000) {
		exceed++;
	} else {
		less++;
	}






	double exceed_per, less_per, ok_per;

	if(total % 500 == 0) {
		exceed_per = (double)exceed*100/total;
		less_per = (double)less*100/total;
		ok_per = (double)ok*100/total;


		printf("exceed = %lf\n", exceed_per);
		printf("less = %lf\n", less_per);
		printf("ok = %lf\n", ok_per);

		printf("ave runtime = %lld\n", totalruntime/total);
		printf("ave trans = %lld\n", totaltrans/total);
		printf("ave latency = %lld\n", totallatency/total);
		printf("ave dirty = %lld\n", totaldirty/total);

	}

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
