#ifndef QEMU_FT_WATCHDOG_H
#define QEMU_FT_WATCHDOG_H

void start_ft_timer(void);
void delete_ft_timer(void);
void re_set_ft_timer(void);
void reset_ft_timer_count(void);
void reset_ft_timer_out_count(void);
uint8_t get_fail_idx_once (void);
uint8_t get_fail_idx_once_backup (void);

void wdgt_snapshot(void);

void cuju_wdt_remote (const char * string);
void cuju_wdt_local (const char * string);
void cuju_wdt_third (const char * string);
void reset_ip_string (char ** target, const char* string);

void cuju_wdt_set_timer_sec (uint32_t sec);
void cuju_wdt_set_timer_milisec (uint16_t mili);

void cuju_wdt_on_off(bool state);
void backup_test_outside (void);
uint8_t primary_test_outside (void);

void start_out_timer (void);
void re_set_out_ft_timer (void);
void delete_out_ft_timer(void);
void start_outside_thread (void);
void outside_thread_join (void);
#endif
