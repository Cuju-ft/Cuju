#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "migration/migration.h"
#include "migration/cuju-ft-trans-file.h"
#include "monitor/monitor.h"
#include "io/channel-util.h"
#include "trace.h"
#include "hmp.h"
#include "migration/ft_watchdog.h"
#include "qmp-commands.h"

/* using ms */
#define FT_WTDG_UNIT        (1000*1000)

/* FT_WTDG_TIME_SEC and FT_WTDG_TIME_MS_PREFIX is timer interval */
#define FT_WTDG_TIME_SEC     0
#define FT_WTDG_TIME_MS_PREFIX  900

#define FT_WTDG_TIME_MS      FT_WTDG_TIME_MS_PREFIX*FT_WTDG_UNIT
#define FT_WTDG_TIMER_MAX   5
#define REMOTE_3RDIP "8.8.8.8"
#define CUJU_HOST_PRIMARY_IP "192.168.126.19"
#define CUJU_HOST_BACKUP_IP "192.168.128.31"

timer_t timer;

unsigned int ft_timer_count = 0;

unsigned int ft_timer_count_max = FT_WTDG_TIMER_MAX;

int system_ping(const char* ip_string);

int system_ping(const char* ip_string) 
{
    int ret;
    char* op_string = NULL; 
    int size_op_string = sizeof("ping -c1 -w1  > /dev/null 2>&1");
    int total_size = size_op_string + sizeof(ip_string);

    //printf("String: %d Total:%d\n", size_op_string,  total_size);

    op_string = malloc(total_size);

    sprintf(op_string, "ping -c1 -w1 %s > /dev/null 2>&1", ip_string);

    //ret = system("ping -c1 -w1 8.8.8.8 > /dev/null 2>&1");
    printf("op_string: [%s]\n", op_string);
    ret = system(op_string);

    if(ret == 0) {
        printf("Success\n");
    } else {
        printf("Failed\n");
    }

    free(op_string);

    return ret;
}

static void SignHandler(int iSignNo){
    if(iSignNo == SIGUSR1){
        printf("Capture sign no : SIGUSR1\n"); 
    }else if(SIGALRM == iSignNo){
        //printf("Capture sign no : SIGALRM\n"); 
        ft_timer_count++;

        if (ft_timer_count > ft_timer_count_max) {
            printf("Timer wake up\n");

            if (cuju_ft_mode == CUJU_FT_TRANSACTION_RECV) {
                /* Backup */
                if (!system_ping(REMOTE_3RDIP)) {
                    /* call failover */
                     printf("ping 3rd IP pass\n");
                    if (!system_ping(CUJU_HOST_PRIMARY_IP)) {
                        printf("ping Primary IP pass\n");
                        printf("Cancel Backup Guest\n");
                        aio_ft_pause(0);
                        qmp_quit(NULL);
                    }
                    else {
                        printf("ping Primary IP failed\n");
                                           
                        hmp_cuju_failover(NULL, NULL);
                    }
                }
            } 
            else if (cuju_ft_mode >= CUJU_FT_TRANSACTION_FLUSH_OUTPUT) {
                /* Primary */
                if (!system_ping(REMOTE_3RDIP)) {
                    /* back to noft */
                    printf("ping 3rd IP pass\n");
                    printf("Primary back to NoFT\n");
                    qmp_cuju_migrate_cancel(NULL);
                }    
                #if 0
                if (!system_ping(CUJU_HOST_BACKUP_IP)) {
                    printf("ping Backup IP pass\n");
                }
                else {
                    printf("ping Backup IP failed\n");
                }
                #endif
            }
            else {
                /* unknown */
                printf("unknown Cuju_ft_mod:(%d)\n", cuju_ft_mode);
                printf("We will close primary timer\n");
                printf("Ping phase: unknown (mode:%d) \n", cuju_ft_mode);
                delete_ft_timer();
            }           
        }
    }
    else{
        printf("Capture sign no:%d\n", iSignNo); 
    }
}

void start_ft_timer (void)
{
    struct sigevent evp;  
    struct itimerspec ts;  
    int ret;  
    
    evp.sigev_value.sival_ptr = &timer;  
    evp.sigev_notify = SIGEV_SIGNAL;  
    evp.sigev_signo = SIGALRM;
    signal(evp.sigev_signo, SignHandler); 
    
    ret = timer_create(CLOCK_REALTIME, &evp, &timer);  
    if(ret) {
        perror("timer_create");
    }     
    
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;  
    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = 0;  
    
    printf("Start Timer\n");
    ret = timer_settime(timer, 0, &ts, NULL);  
    if(ret) {
        perror("timer_settime"); 
    } 
}

void re_set_ft_timer (void)
{
    struct itimerspec ts;  
    int ret;  

    if (FT_WTDG_TIME_MS_PREFIX >= 1000)
        printf("warning timer interval ms unit more than 1 sec\n");

    ts.it_interval.tv_sec = FT_WTDG_TIME_SEC;
    ts.it_interval.tv_nsec = FT_WTDG_TIME_MS;  
    ts.it_value.tv_sec = FT_WTDG_TIME_SEC;
    ts.it_value.tv_nsec = FT_WTDG_TIME_MS;  
    
    printf("RE-SET Timer\n");
    ret = timer_settime(timer, 0, &ts, NULL);  
    if(ret) {
        perror("timer_settime"); 
    } 
}


void delete_ft_timer (void)
{
    struct itimerspec ts;  
    int ret;  

    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;  
    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = 0;  
    
    printf("Cancel Timer\n");
    ret = timer_settime(timer, 0, &ts, NULL);  
    if(ret) {
        perror("timer_settime"); 
    } 
}

void reset_ft_timer_count (void)
{
    ft_timer_count = 0;
}

void wdgt_snapshot (void)
{
    MigrationState *mig_st = migrate_get_current();

    cuju_ft_trans_send_header(mig_st->file->opaque, CUJU_QEMU_VM_TRANSACTION_CHECK_WDGT, 0); 
    ////cuju_ft_trans_send_header(mig_st->fd, CUJU_QEMU_VM_TRANSACTION_CHECK_WDGT, 0); 
}