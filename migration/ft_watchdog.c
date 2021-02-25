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

#define DEBUG_FT_WDT
#ifdef DEBUG_FT_WDT
#define WDT_PRINTF(fmt, ...) \
    do { printf("Cuju WDT: " fmt, ## __VA_ARGS__); } while (0)
#else
#define WDT_PRINTF(fmt, ...) \
    do { } while (0)
#endif

/* using ms */
#define FT_WTDG_UNIT        (1000*1000)

/* FT_WTDG_TIME_SEC and FT_WTDG_TIME_MS_PREFIX is timer interval */
#define FT_WTDG_TIME_SEC     0
#define FT_WTDG_TIME_MS_PREFIX  900

#define FT_WTDG_TIME_MS      FT_WTDG_TIME_MS_PREFIX*FT_WTDG_UNIT
#define FT_WTDG_TIMER_MAX   5

#define ENABLE_DEFAULT_FIX  1

#define REMOTE_3RDIP "8.8.8.8"
#define CUJU_HOST_PRIMARY_IP "192.168.126.19"
#define CUJU_HOST_BACKUP_IP "192.168.128.31"

uint8_t* remote_host = NULL;
uint8_t* local_host = NULL;
uint8_t* third_party = NULL;

uint32_t timer_second = FT_WTDG_TIME_SEC;
uint16_t timer_milisec = FT_WTDG_TIME_MS_PREFIX;

timer_t timer;

static bool capa_cuju_enable = 0;

unsigned int ft_timer_count = 0;

unsigned int ft_timer_count_max = FT_WTDG_TIMER_MAX;

int system_ping(const uint8_t* ip_string);

int system_ping(const uint8_t* ip_string) 
{
    int ret;
    char* op_string = NULL; 
    int size_op_string = strlen("ping -c1 -w1  > /dev/null 2>&1");
    int total_size = size_op_string + strlen((char *)ip_string);

    WDT_PRINTF("String: %d Total:%d\n", size_op_string,  total_size);

    op_string = malloc(total_size);

    sprintf(op_string, "ping -c1 -w1 %s > /dev/null 2>&1", ip_string);

    //ret = system("ping -c1 -w1 8.8.8.8 > /dev/null 2>&1");
    WDT_PRINTF("op_string: [%s]\n", op_string);
    ret = system(op_string);

    if(ret == 0) {
        WDT_PRINTF("Success\n");
    } else {
        WDT_PRINTF("Failed\n");
    }

    free(op_string);

    return ret;
}

static void SignHandler(int iSignNo){
    if (iSignNo == SIGUSR1) {
        WDT_PRINTF("Capture sign no : SIGUSR1\n"); 
    } else if (SIGALRM == iSignNo) {
        //WDT_PRINTF("Capture sign no : SIGALRM\n"); 
        ft_timer_count++;

        if (ft_timer_count > ft_timer_count_max) {
            WDT_PRINTF("Timer wake up\n");

            if (cuju_ft_mode == CUJU_FT_TRANSACTION_RECV) {
                /* Backup */
                printf("[Backup] Start ping test\n");
                if (!system_ping(third_party)) {
                    /* call failover */
                     printf("ping 3rd IP pass\n");
                    if (!system_ping(remote_host)) {
                        printf("ping remote IP pass\n");
                        printf("Cancel Backup Guest\n");
                        aio_ft_pause(0);
                        qmp_quit(NULL);
                    }
                    else {
                        printf("ping Primary IP failed\n");
                                           
                        hmp_cuju_failover(NULL, NULL);
                    }
                }
                else {
                    printf("ping 3rd IP failed\n");
                    printf("ready for close\n");
                    aio_ft_pause(0);
                    qmp_quit(NULL);
                }                   
            } 
            else if (cuju_ft_mode >= CUJU_FT_TRANSACTION_FLUSH_OUTPUT) {
                /* Primary */
                printf("[Primary] Start ping test\n");
                if (!system_ping(third_party)) {
                    /* back to noft */
                    printf("ping 3rd IP pass\n");
                    printf("Primary back to NoFT\n");
                    qmp_cuju_migrate_cancel_fast(NULL);
                    delete_ft_timer();
                }
                else {
                    printf("ping 3rd IP failed\n");
                    printf("ready for close\n");
                    aio_ft_pause(0);
                    qmp_quit(NULL);
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

#if ENABLE_DEFAULT_FIX
    reset_ip_string((char **)&remote_host, CUJU_HOST_PRIMARY_IP);
    reset_ip_string((char **)&local_host, CUJU_HOST_BACKUP_IP);
    reset_ip_string((char **)&third_party, REMOTE_3RDIP);
#endif

    ret = timer_create(CLOCK_REALTIME, &evp, &timer);  
    if(ret) {
        perror("timer_create");
    }     

    WDT_PRINTF("Set Timer varible\n");
    
#if 0    
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;  
    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = 0;    
#else
    ts.it_interval.tv_sec = timer_second;
    ts.it_interval.tv_nsec = timer_milisec*FT_WTDG_UNIT;  
    ts.it_value.tv_sec = timer_second;
    ts.it_value.tv_nsec = timer_milisec*FT_WTDG_UNIT;  
#endif 
    /* default start function */
    if (capa_cuju_enable) {
        WDT_PRINTF("Start Timer\n");
        ret = timer_settime(timer, 0, &ts, NULL);  
        if(ret) {
            perror("timer_settime"); 
        } 
    }
}

void re_set_ft_timer (void)
{
    struct itimerspec ts;  
    int ret;  
#if 0
    if (FT_WTDG_TIME_MS_PREFIX >= 1000)
        printf("warning timer interval ms unit more than 1 sec\n");

    ts.it_interval.tv_sec = FT_WTDG_TIME_SEC;
    ts.it_interval.tv_nsec = FT_WTDG_TIME_MS;  
    ts.it_value.tv_sec = FT_WTDG_TIME_SEC;
    ts.it_value.tv_nsec = FT_WTDG_TIME_MS;  
#else
    if (timer_milisec >= 1000)
        printf("warning timer interval ms unit more than 1 sec\n");

    ts.it_interval.tv_sec = timer_second;
    ts.it_interval.tv_nsec = timer_milisec*FT_WTDG_UNIT;  
    ts.it_value.tv_sec = timer_second;
    ts.it_value.tv_nsec = timer_milisec*FT_WTDG_UNIT;  
#endif 

    if (capa_cuju_enable) {
        /* 1. if re-set before enter FT, we only set the timer and not start it. */
        /* 2. if re-set and already in FT, we set the timer and start it. */
        if ((cuju_ft_mode == CUJU_FT_TRANSACTION_RECV) || 
            (cuju_ft_mode >= CUJU_FT_TRANSACTION_FLUSH_OUTPUT)) {
            WDT_PRINTF("RE-SET Timer\n");
            ret = timer_settime(timer, 0, &ts, NULL);  
            if(ret) {
                perror("timer_settime"); 
            }
        } 
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
    
    WDT_PRINTF("Cancel Timer\n");
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

void reset_ip_string (char ** target, const char* string)
{
    //printf("*target: %s\n", *target);
    //printf("*string: %s\n", string);
    //printf("string size: %lu\n", strlen(string));
    //printf("**target: %p\n", **target);

    if (*target) {
        free(*target);
        *target = NULL;
    }

    //printf("target1: %s\n", *target);
    *target = malloc(strlen(string));
    strncpy(*target, string, strlen(string));
    //printf("target2: %s\n", *target);

    return;
}

void cuju_wdt_remote (const char * string)
{
    printf("[%s] %s\n", __func__, string);  
    reset_ip_string((char **)&remote_host, string);
}

void cuju_wdt_local (const char * string)
{
    printf("[%s] %s\n", __func__, string);   
    reset_ip_string((char **)&local_host, string);
}

void cuju_wdt_third (const char * string)
{
    printf("[%s] %s\n", __func__, string);  
    reset_ip_string((char **)&third_party, string);
}

void cuju_wdt_set_timer_sec (uint32_t sec)
{
    timer_second = sec;

    printf("[%s] timer_second:%u\n", __func__, timer_second);  
}

void cuju_wdt_set_timer_milisec (uint16_t mili)
{ 

    timer_milisec = mili;

    printf("[%s] timer_milisec:%u\n", __func__, timer_milisec);  
}

void cuju_wdt_on_off(bool state)
{
    capa_cuju_enable = state;
}