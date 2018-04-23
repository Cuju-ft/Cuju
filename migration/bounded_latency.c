#include "qemu/osdep.h"
#include "migration/migration.h"
#include "migration/cuju-kvm-share-mem.h"
#include "sysemu/kvm.h"
#include <linux/kvm.h>
#include "qmp-commands.h"


static int bd_target = EPOCH_TIME_IN_MS * 1000;                                                                                                                                                                     
static int bd_alpha = 1000; // initial alpha is 1 ms

int kvmft_bd_set_alpha(int alpha); 


int kvmft_bd_set_alpha(int alpha)
{
    return kvm_vm_ioctl(kvm_state, KVMFT_BD_SET_ALPHA, &alpha);
}                                                                                                                                                                                                                   


//static FILE *bdofile = NULL; 
static FILE *ofile = NULL;

void bd_update_stat(int dirty_num, 
                    double tran_time_s, 
                    double delay_time_s, 
                    double run_time_s, 
                    double invoke_commit1_s, 
                    double recv_ack1_s, 
                    int ram_len, 
                    int average_predict)
{

    if (delay_time_s * 1000 * 1000 > bd_target * 110 / 100) {
        bd_alpha += 200;
        kvmft_bd_set_alpha(bd_alpha);
    } else if (delay_time_s * 1000 * 1000 > bd_target * 102 / 100) {                                                                                                                                                
        bd_alpha += 50; 
        kvmft_bd_set_alpha(bd_alpha);
    } else if (delay_time_s * 1000 * 1000 >= bd_target * 98 / 100) {
        // [98%, 102%]
        // slowly back off
        bd_alpha += 10; 
        kvmft_bd_set_alpha(bd_alpha);
    } else {
        bd_alpha -= 25; 
        kvmft_bd_set_alpha(bd_alpha);
    }   

    if (ofile == NULL) {
        ofile = fopen("/tmp/bd_delay", "w");
        assert(ofile);
    }   

    //if (dirty_num < 500)
    //    return;

    fprintf(ofile, "%.4lf\t%.4lf\t%.4lf\t%.4lf\t%.4lf\t%d\t%d\t%d\t%d\t%d\n", delay_time_s * 1000,
        tran_time_s * 1000,
        run_time_s * 1000,
        invoke_commit1_s * 1000,
        recv_ack1_s * 1000,
        dirty_num,
        (int)(ram_len / (tran_time_s * 1000)),
        ram_len / (dirty_num?dirty_num:1),
        average_predict,
        bd_alpha);

}


int kvmft_bd_update_latency(int dirty_page, int runtime_us, int trans_us, int latency_us)
{
    struct kvmft_update_latency update;

    update.dirty_page = dirty_page;
    update.runtime_us = runtime_us;
    update.trans_us = trans_us;
    update.latency_us = latency_us;

    return kvm_vm_ioctl(kvm_state, KVMFT_BD_UPDATE_LATENCY, &update);
}

void bd_reset_epoch_timer(void)
{
    //float nvalue = BD_TIMER_RATIO * EPOCH_TIME_IN_MS * 1000;
    float nvalue = 1000;
    if (EPOCH_TIME_IN_MS < 10)                                                                                                                                                                                      
        nvalue = EPOCH_TIME_IN_MS*1000/10;

    Error *err = NULL;
    qmp_cuju_adjust_epoch((unsigned int)nvalue, &err);                                                                                                                                                                             
    if (err) {
        error_report_err(err);
        return;
    }    

}

bool bd_timer_func(void)
{
/*
    static int count = 0;
    int dirty_bytes;
    MigrationState *s = migrate_get_current();

    static int last_dirty_bytes = 0;

    ++count;
                                                                                                                                                                                                                    
    if (ofile == NULL) {
        ofile = fopen("/tmp/bd_delay", "w");
        assert(ofile);
    }

    if (EPOCH_TIME_IN_MS >= 10) {
        if (count < EPOCH_TIME_IN_MS/2) {
            kvm_shmem_start_timer();
            return true;
        }

        if (count == EPOCH_TIME_IN_MS/2) {
            s->average_dirty_bytes = bd_calc_dirty_bytes();
        }

        if (count > EPOCH_TIME_IN_MS/2) {
            //s->average_dirty_bytes = bd_calc_dirty_bytes();
        }

        if (bd_is_last_count(count) || kvmft_bd_check_dirty_page_number()) {
            count = 0;
            last_dirty_bytes = 0;
            return false;
        }

    }
*/


    return 0;
}


