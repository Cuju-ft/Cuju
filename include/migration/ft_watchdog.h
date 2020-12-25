#ifndef QEMU_FT_WATCHDOG_H
#define QEMU_FT_WATCHDOG_H

void start_ft_timer(void);
void delete_ft_timer(void);
void re_set_ft_timer(void);
void reset_ft_timer_count(void);

void wdgt_snapshot(void);

#endif