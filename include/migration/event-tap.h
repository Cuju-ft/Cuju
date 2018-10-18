/*
 * Event Tap functions for QEMU
 *
 * Copyright (c) 2010 Nippon Telegraph and Telephone Corporation. 
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#ifndef EVENT_TAP_H
#define EVENT_TAP_H

#include "qemu-common.h"

enum EVENT_TAP_STATE {
    EVENT_TAP_OFF,
    EVENT_TAP_ON,
    EVENT_TAP_SUSPEND,
    EVENT_TAP_LOAD,
    EVENT_TAP_REPLAY,
};

int event_tap_register(int (*cb)(void));
int event_tap_unregister(void);
void event_tap_suspend(void);
void event_tap_resume(void);
int event_tap_get_state(void);
void event_tap_ioport(int index, uint32_t address, uint32_t data);
void event_tap_mmio(uint64_t address, uint8_t *buf, int len);
void event_tap_init(void);
int event_tap_flush(void* cb, void *opaque);
int event_tap_flush_old(void* cb, void *state, void *opaque, void *opaque2);
void event_tap_save_old_buffer(void);
int event_tap_flush_one(void);
void event_tap_save_event_list(void **be, void **ne);
void event_tap_take_snapshot(void **n, void **e);
void event_tap_start_epoch(void *n, void *e, void *oldn, void *olde);
void *event_tap_get_list(int state, int event);
void event_tap_extend(int index);
void event_tap_flush_net_list(void *net_list, void *cb, void *opaque);
void *event_tap_net_list_new(void);
bool event_tap_net_list_empty(void *net_list);
int event_tap_load(QEMUFile *f, void *opaque, int version_id);
void event_tap_save(QEMUFile *f, void *opaque);
BlockAIOCB *blk_aio_pwritev_proxy(BlockBackend *blk, int64_t offset,
                            QEMUIOVector *qiov, BdrvRequestFlags flags,
                            BlockCompletionFunc *cb, void *opaque);
BlockAIOCB *blk_aio_preadv_proxy(BlockBackend *blk, int64_t offset,
                           QEMUIOVector *qiov, BdrvRequestFlags flags,
                           BlockCompletionFunc *cb, void *opaque);
void bdrv_event_tap(BlockDriverState *bs, BlockRequest *reqs,
                           int num_reqs, bool is_multiwrite);
void event_tap_bh_read_fast(void *p);
#endif
