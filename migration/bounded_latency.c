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

    struct kvmft_update_latency update;
	update.dirty_pfns_len = s->dirty_pfns_len;
	update.dirty_len      = dirty_len;
	update.runtime_us     = runtime_us;
	update.trans_us       = trans_us;
	update.latency_us     = latency_us;
	update.cur_index      = s->cur_off;

    int r = kvm_vm_ioctl(kvm_state, KVMFT_BD_UPDATE_LATENCY, &update);



	static unsigned long long total = 0;
	static unsigned long long totalruntime = 0;
	static unsigned long long totallatency = 0;
	static unsigned long long totaltrans = 0;
	static unsigned long long totaldirty = 0;
	static unsigned long long exceed = 0;
	static unsigned long long less = 0;
	static unsigned long long ok = 0;
	static unsigned long long runtime_err = 0;
	static unsigned long long last_transfer_impact_error = 0;
	static unsigned long long total_uncompress_dirty = 0;
	static unsigned long long total_fix_latency_ok = 0;
	static unsigned long long total_is_right_but_too_late = 0;
	static unsigned long long total_trans_r = 0;

	static long subcount = 0;


	//static unsigned long long page_zero_ok;
	static unsigned long long page_zero_less;
	static unsigned long long page_zero_exceed;

	static double total_dis_f = 0;
	static unsigned long long total_dis_c = 0;
	static double dirty_diff_f_total = 0;

	static int last_trans_time;

	int e_runtime = update.e_runtime;
	//int e_latency = update.e_runtime+update.e_trans;
	int e_trans = update.e_trans;

	totalruntime += runtime_us;
	totallatency += latency_us;
	totaltrans   += trans_us;
	totaldirty   += dirty_len;
	total_uncompress_dirty += s->dirty_pfns_len*4096;

	total++;


	if(update.e_dirty_len && update.kdis_value) {
		total_dis_f += (double)(update.kdis_value)/update.e_dirty_len;
		total_dis_c++;

		if(update.e_dirty_len > dirty_len) {
			dirty_diff_f_total += (double)(update.e_dirty_len - dirty_len) / update.e_dirty_len;
		} else {
			dirty_diff_f_total += (double)(dirty_len - update.e_dirty_len) / update.e_dirty_len;
		}
	}



	static unsigned long long last_ok = 0;
	static unsigned long long last_exceed = 0;
	static unsigned long long last_less = 0;

	static unsigned long long latency_fix_ok = 0;
	static unsigned long long latency_fix_err = 0;


	int target_latency = EPOCH_TIME_IN_MS*1000;


	total_trans_r+=update.alpha;

//		int fix_b_ok = 0;

		int m1 = update.x2;
		int m2 = update.x3;
		int trans = 0;
		//if(m1) {
		if(m1 && dirty_len < 500000) {
			trans += dirty_len/m1;
		} else if (dirty_len >= 500000) {
			trans += dirty_len/1000;
		}
		if(m2) {
			trans += (s->dirty_pfns_len*4096+dirty_len)/m2;
		}

		trans += (dirty_len/6745);

		if(trans == 0) trans = e_trans;
		int fixlatency = trans+runtime_us;
		//int fixlatency = trans+update.e_runtime;
//		if( fixlatency <= target_latency + target_latency/10 && fixlatency >= target_latency - target_latency/10) {
		if( fixlatency <= latency_us + target_latency/10 && fixlatency >= latency_us - target_latency/10) {
			//printf("fix latency = %d\n", fixlatency);
			latency_fix_ok++;
//			fix_b_ok = 1;
		} else {
			latency_fix_err++;
		}



		FILE *pFile;
   		char pbuf[200];
		//if(latency_us <= target_latency + target_latency/10 && latency_us >= target_latency - target_latency/10) {
//		if(fix_b_ok) {
			sprintf(pbuf, "runtime_latency_trans_rate_hit.txt");
//		} else {
//			sprintf(pbuf, "runtime_latency_trans_rate_miss.txt");
//		}
    	pFile = fopen(pbuf, "a");

		if(pFile != NULL){
            //    sprintf(pbuf, "%d %d\n", dirty_len, trans_us);
				//if(update.x0 != 0 && update.x1 !=0)
                //sprintf(pbuf, "%d %d %d %d %d %d\n", s->dirty_pfns_len, update.x0, s->dirty_pfns_len/update.x0, dirty_len, update.x1, dirty_len/update.x1);
                //sprintf(pbuf, "%d %d\n", update.x0, update.x1);
                //sprintf(pbuf, "%d %d\n", update.e_dirty_len, dirty_len);
			//	if(update.x3 > 1000) {
             //   sprintf(pbuf, "%d %d %d %d\n", update.x2, dirty_len+s->dirty_pfns_len*4096, update.x3, dirty_len);
        	  //  fputs(pbuf, pFile);
                sprintf(pbuf, "%d %d %d %d %d %d %d %d %d %d %d %d\n", update.x0, update.x1, update.x2, update.x3, update.x4, update.x5, dirty_len+s->dirty_pfns_len*4096,  dirty_len, e_runtime, runtime_us, trans_us, latency_us);
        	    fputs(pbuf, pFile);
			//}
		}
    	else
        	printf("no profile\n");

		fclose(pFile);



	//if(latency_us <= target_latency + 1000 && latency_us >= target_latency - 1000) {
	if(latency_us <= target_latency + target_latency/10 && latency_us >= target_latency - target_latency/10) {
		ok++;
		last_ok++;
	} else if (latency_us > target_latency+target_latency/10) {
		exceed++;
		last_exceed++;

		if(e_trans < trans_us + target_latency/10 && e_trans > trans_us - target_latency/10) {
			total_is_right_but_too_late++;
		}


		if(s->dirty_pfns_len == 0) {
			page_zero_exceed++;
		}
		latency_us-=runtime_us;
		latency_us+=e_runtime;
		if(latency_us <= target_latency + target_latency/10 && latency_us >= target_latency - target_latency/10) {
			runtime_err++;
		} else if (last_trans_time > runtime_us) {
			last_transfer_impact_error++;
		}

	} else {
		less++;
		last_less++;
		if(s->dirty_pfns_len == 0) {
			page_zero_less++;
		}
	}

	if(update.fix_latency <= target_latency + target_latency/10 && update.fix_latency >= target_latency - target_latency/10) {
		total_fix_latency_ok++;
	}



	last_trans_time = trans_us;


	double exceed_per, less_per, ok_per, runtime_err_per, last_transfer_impact_error_per;
	double fixok;

	if(total % 500 == 0) {
		exceed_per = (double)exceed*100/total;
		less_per = (double)less*100/total;
		ok_per = (double)ok*100/total;
//		runtime_err_per = (double)runtime_err*100/total;
//		last_transfer_impact_error_per = (double)last_transfer_impact_error*100/total;

//		fixok = (double)total_fix_latency_ok*100/total;

		printf("exceed = %lf\n", exceed_per);
		printf("less = %lf\n", less_per);
		printf("ok = %lf\n", ok_per);
	/*	printf("runtime_err = %lf\n", runtime_err_per);
		printf("last trans impact err = %lf\n", last_transfer_impact_error_per);
		printf("transfer rate predic err = %lf\n", exceed_per+less_per-runtime_err_per-last_transfer_impact_error_per);
		printf("too late err = %lf\n", (double)total_is_right_but_too_late*100/total);*/
		//printf("fixok = %lf\n", fixok);


		/*printf("ave runtime = %lld\n", totalruntime/total);
		printf("ave trans = %lld\n", totaltrans/total);
		printf("ave latency = %lld\n", totallatency/total);
		printf("ave dirty = %lld\n", totaldirty/total);
		printf("ave uncompress = %lld\n", total_uncompress_dirty/total);

		printf("zero exceed = %lf\n", (double)page_zero_exceed*100/total);
		printf("zero less = %lf\n", (double)page_zero_less*100/total);
*/
	//	if(total_dis_c) {
	//		printf("dis_f = %lf\n", total_dis_f/total_dis_c);
	//		printf("ave dirty factor (real_dirty/e_dirty) = %lf\n", dirty_diff_f_total/total_dis_c);
	//	}

	}

	subcount++;
	//if(total % 1000 == 0) {
	if(subcount == 1000) {
		printf("exceed = %lf\n", (double)last_exceed*100/1000);
		printf("less = %lf\n", (double)last_less*100/1000);
		printf("ok = %lf\n", (double)last_ok*100/1000);
		last_exceed = last_less = last_ok = 0;


		printf("ave runtime = %lld\n", totalruntime/1000);
		printf("ave trans = %lld\n", totaltrans/1000);
		printf("ave latency = %lld\n", totallatency/1000);
		printf("ave dirty = %lld\n", totaldirty/1000);
		printf("ave uncompress = %lld\n", total_uncompress_dirty/1000);

		printf("zero exceed = %lf\n", (double)page_zero_exceed*100/1000);
		printf("zero less = %lf\n", (double)page_zero_less*100/1000);

		if(total_dis_c) {
			printf("dis_f = %lf\n", total_dis_f/total_dis_c);
			printf("ave dirty factor (real_dirty/e_dirty) = %lf\n", dirty_diff_f_total/total_dis_c);
		}
		fixok = (double)total_fix_latency_ok*100/1000;
		printf("fixok = %lf\n", fixok);

		runtime_err_per = (double)runtime_err*100/1000;
		last_transfer_impact_error_per = (double)last_transfer_impact_error*100/1000;

		printf("runtime_err = %lf\n", runtime_err_per);
		printf("last trans impact err = %lf\n", last_transfer_impact_error_per);
//		printf("transfer rate predic err = %lf\n", exceed_per+less_per-runtime_err_per-last_transfer_impact_error_per);
		printf("too late err = %lf\n", (double)total_is_right_but_too_late*100/1000);

		printf("ave trans_r = %lf\n", (double)total_trans_r/1000);


		printf("fix_latency_err = %lf\n", (double)latency_fix_err*100/1000);
		printf("fix_latency_ok = %lf\n", (double)latency_fix_ok*100/1000);

		latency_fix_ok = latency_fix_err = 0;

		total_dis_c = 0;
		total_dis_f = 0;
		totalruntime = totaltrans = totallatency = totaldirty = total_uncompress_dirty = 0;
		total_fix_latency_ok = 0;
		runtime_err = last_transfer_impact_error = 0;
		page_zero_exceed = page_zero_less = 0;
		total_is_right_but_too_late = 0;
		dirty_diff_f_total = 0;
		subcount = 0;

		total_trans_r = 0;
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
	return r;
}
