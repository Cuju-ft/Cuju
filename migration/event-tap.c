/*
 * Event Tap functions for QEMU
 *
 * Copyright (c) 2010 Nippon Telegraph and Telephone Corporation.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "block/block.h"
#include "qemu/error-report.h"
#include "hw/hw.h"
#include "qemu/cutils.h"
#include "qemu/queue.h"
#include "qemu/timer.h"
#include "sysemu/sysemu.h"
#include "net/net.h"
#include "net/hub.h"
#include "exec/ioport.h"
#include "migration/event-tap.h"
#include "migration/cuju-ft-trans-file.h"
#include "migration/migration.h"
#include <linux/kvm.h>

#include "qemu/sockets.h"
#define DEBUG_EVENT_TAP

#ifdef DEBUG_EVENT_TAP
#define DPRINTF(fmt, ...) \
    do { printf("event-tap: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif


#ifdef ft_debug_mode_enable
#define FTPRINTF(fmt, ...) \
    do { printf(fmt, ## __VA_ARGS__); } while (0)
#else
#define FTPRINTF(fmt, ...) \
    do { } while (0)
#endif




static int bdrv_write_through = 0;

static enum EVENT_TAP_STATE event_tap_state = EVENT_TAP_OFF;

BlockAIOCB dummy_acb; /* we may need a pool for dummies */

typedef struct NetListFlushRequest {
    void *list;
    void (*cb)(void *);
    void *opaque;
    QEMUBH *bh;
} NetListFlushRequest;

typedef struct EventTapIOport {
    uint32_t address;
    uint32_t data;
    int      index;
} EventTapIOport;

#define MMIO_BUF_SIZE 8

typedef struct EventTapMMIO {
    uint64_t address;
    uint8_t  buf[MMIO_BUF_SIZE];
    int      len;
} EventTapMMIO;

typedef struct EventTapNetReq {
    char *device_name;
    int iovcnt;
    struct iovec *iov;
    int vlan_id;
    bool vlan_needed;
    bool async;
	NetPacketSent *sent_cb;
	NetClientState *vc;
} EventTapNetReq;

#define MAX_BLOCK_REQUEST 32

typedef struct EventTapBlkReadReq {
    struct BlockRequest req;
    QEMUBH *bh;
} EventTapBlkReadReq;

typedef struct EventTapBlkReq {
    char *device_name;
    int num_reqs;
    int num_cbs;
    bool is_multiwrite;
    int left_req;           // requests callbed back by real writing
    QEMUBH *bh;
    QEMUIOVector qiov[MAX_BLOCK_REQUEST];
    BlockRequest reqs[MAX_BLOCK_REQUEST];
    BlockCompletionFunc *cb[MAX_BLOCK_REQUEST];
    void *opaque[MAX_BLOCK_REQUEST];
} EventTapBlkReq;

#define EVENT_TAP_IOPORT (1 << 0)
#define EVENT_TAP_MMIO   (1 << 1)
#define EVENT_TAP_NET    (1 << 2)
#define EVENT_TAP_BLK    (1 << 3)

#define EVENT_TAP_TYPE_MASK (EVENT_TAP_NET - 1)

typedef struct EventTapLog {
    int mode;
    union {
        EventTapIOport ioport ;
        EventTapMMIO mmio;
    };
    union {
        EventTapNetReq net_req;
        EventTapBlkReq blk_req;
    };
    QTAILQ_ENTRY(EventTapLog) node;
} EventTapLog;

typedef QTAILQ_HEAD(, EventTapLog) QueueEventTapLog;

#define MAX_EventTapLog 10240
typedef struct EventTapLogList {
	unsigned int head;
	unsigned int tail;
	EventTapLog *logs[MAX_EventTapLog];
} EventTapLogList;

static EventTapLogList **event_tap_log_list;

static EventTapLog *last_event_tap;

static EventTapLogList *net_event_list;



static QueueEventTapLog *event_list;           // currently buffered output
static QueueEventTapLog *event_list_old;       // buffered output for last epoch

static QueueEventTapLog event_list_data[3];


static int event_list_data_offset = 0;

static QueueEventTapLog event_list_pending;   // last epoch, synced but not finished
static QueueEventTapLog event_pool;


static VMChangeStateEntry *vmstate;

static int pending_bdrv_request = 0;
static int pending_bdrv_request_old = 0;
static void (*bdrv_request_flush_cb)(void *) = NULL;
static void *bdrv_request_flush_opaque = NULL;


static void event_tap_free_log(EventTapLog *log)
{
    int i, mode = log->mode & ~EVENT_TAP_TYPE_MASK;

    if (mode == EVENT_TAP_NET) {
        EventTapNetReq *net_req = &log->net_req;
        for (i = 0; i < net_req->iovcnt; i++) {
            g_free(net_req->iov[i].iov_base);
        }
        g_free(net_req->iov);
        g_free(net_req->device_name);
    } else if (mode == EVENT_TAP_BLK) {
        EventTapBlkReq *blk_req = &log->blk_req;


        g_free(blk_req->device_name);
    }

	g_free(log);
	return;

    log->mode = 0;

    /* return the log to event_pool */
    QTAILQ_INSERT_HEAD(&event_pool, log, node);
}

static int event_tap_alloc_net_req(EventTapNetReq *net_req,
                                   NetClientState *vc,
                                   const struct iovec *iov, int iovcnt,
                                   NetPacketSent *sent_cb, bool async)
{
    int i, ret = 0;

    net_req->iovcnt = iovcnt;
    net_req->async = async;
	net_req->sent_cb = sent_cb;
	net_req->vc = vc;
    net_req->device_name = g_strdup(vc->name);

    if (vc->peer) {
        net_req->vlan_needed = 1;
        int id;
        if (!net_hub_id_for_client(vc, &id)) {
            net_req->vlan_id = id;
        }
        else {
            net_req->vlan_id = -1;
        }
    } else {
        net_req->vlan_needed = 0;
    }

    net_req->iov = g_malloc(sizeof(struct iovec) * iovcnt);

    for (i = 0; i < iovcnt; i++) {
        net_req->iov[i].iov_base = g_malloc(iov[i].iov_len);
        memcpy(net_req->iov[i].iov_base, iov[i].iov_base, iov[i].iov_len);
        net_req->iov[i].iov_len = iov[i].iov_len;
        ret += iov[i].iov_len;
    }

    return ret;
}


static void *event_tap_alloc_log(void)
{
    EventTapLog *log;

	return g_malloc0(sizeof(EventTapLog));

    if (QTAILQ_EMPTY(&event_pool)) {
        log = g_malloc0(sizeof(EventTapLog));
    } else {
        log = QTAILQ_FIRST(&event_pool);
        QTAILQ_REMOVE(&event_pool, log, node);
    }

    return log;
}


static void event_tap_free_pool(void)
{
    EventTapLog *log, *next;

    QTAILQ_FOREACH_SAFE(log, &event_pool, node, next) {
        QTAILQ_REMOVE(&event_pool, log, node);
        g_free(log);
    }
}

/* This func is called by qemu_net_queue_flush() when a packet is appended */
static void event_tap_net_cb(NetClientState *vc, ssize_t len)
{
    DPRINTF("%s: %zd bytes packet was sended\n", vc->name, len);
}

extern int event_tap_flush_net(EventTapLogList *list);


static int net_event_tap(NetClientState *vc, const struct iovec *iov,
                         int iovcnt, NetPacketSent *sent_cb, bool async)
{
    EventTapLog *log;
    int ret;

    log = event_tap_alloc_log();
    assert(log != NULL);

    log->mode |= EVENT_TAP_NET;
    ret = event_tap_alloc_net_req(&log->net_req, vc, iov, iovcnt, sent_cb,
                                  async);

	assert(net_event_list->tail < MAX_EventTapLog);
	net_event_list->logs[net_event_list->tail] = log;
	++net_event_list->tail;


    return ret;
}



void event_tap_fill_buffer(QEMUIOVector *dst, int64_t sector_num)
{
    int nb_sectors;
    int size = 0;

	// TODO disabled because write-through
	if (bdrv_write_through)
		return;

    if (event_tap_state == EVENT_TAP_ON) {
        EventTapLog *log;
        EventTapBlkReq *blk_req;

        nb_sectors = dst->size / 512;

        QTAILQ_FOREACH(log, &event_list_pending, node) {
            if ( (log->mode & ~EVENT_TAP_TYPE_MASK) != EVENT_TAP_BLK )
                continue;
            blk_req = &log->blk_req;
            if ( sector_num >= blk_req->reqs[0].offset+blk_req->reqs[0].bytes
                    || blk_req->reqs[0].offset >= sector_num + nb_sectors )
                continue;

            /* keep copy from all logs to get the newest data */
            if (sector_num <= blk_req->reqs[0].offset) {
                size = (sector_num + nb_sectors - blk_req->reqs[0].offset) * 512;
                if (size > blk_req->qiov[0].size)
                    size = blk_req->qiov[0].size;
                qemu_iovec_copy_sup(dst, (blk_req->reqs[0].offset - sector_num) * 512,
                                    &blk_req->qiov[0], 0, size);

            } else {
                size = (blk_req->reqs[0].offset + blk_req->reqs[0].bytes - sector_num)
                            * 512;
                if (size > dst->size)
                    size = dst->size;
                qemu_iovec_copy_sup(dst, 0, &blk_req->qiov[0],
                                    (sector_num - blk_req->reqs[0].offset) * 512, size);

            }
        }


        QTAILQ_FOREACH(log, event_list_old, node) {
            if ( (log->mode & ~EVENT_TAP_TYPE_MASK) != EVENT_TAP_BLK )
                continue;
            blk_req = &log->blk_req;
            if ( sector_num >= blk_req->reqs[0].offset+blk_req->reqs[0].bytes
                    || blk_req->reqs[0].offset >= sector_num + nb_sectors )
                continue;

            /* keep copy from all logs to get the newest data */
            if (sector_num <= blk_req->reqs[0].offset) {
                size = (sector_num + nb_sectors - blk_req->reqs[0].offset) * 512;
                if (size > blk_req->qiov[0].size)
                    size = blk_req->qiov[0].size;
                qemu_iovec_copy_sup(dst, (blk_req->reqs[0].offset - sector_num) * 512,
                                    &blk_req->qiov[0], 0, size);

            } else {
                size = (blk_req->reqs[0].offset + blk_req->reqs[0].bytes - sector_num)
                            * 512;
                if (size > dst->size)
                    size = dst->size;
                qemu_iovec_copy_sup(dst, 0, &blk_req->qiov[0],
                                    (sector_num - blk_req->reqs[0].offset) * 512, size);


            }
        }

        QTAILQ_FOREACH(log, event_list, node) {
            if ( (log->mode & ~EVENT_TAP_TYPE_MASK) != EVENT_TAP_BLK )
                continue;
            blk_req = &log->blk_req;
            if ( sector_num >= blk_req->reqs[0].offset+blk_req->reqs[0].bytes
                    || blk_req->reqs[0].offset >= sector_num + nb_sectors )
                continue;

            /* keep copy from all logs to get the newest data */
            if (sector_num <= blk_req->reqs[0].offset) {
                size = (sector_num + nb_sectors - blk_req->reqs[0].offset) * 512;
                if (size > blk_req->qiov[0].size)
                    size = blk_req->qiov[0].size;
                qemu_iovec_copy_sup(dst, (blk_req->reqs[0].offset - sector_num) * 512,
                                    &blk_req->qiov[0], 0, size);
            } else {
                size = (blk_req->reqs[0].offset + blk_req->reqs[0].bytes - sector_num)
                            * 512;
                if (size > dst->size)
                    size = dst->size;
                qemu_iovec_copy_sup(dst, 0, &blk_req->qiov[0],
                                    (sector_num - blk_req->reqs[0].offset) * 512, size);
            }
        }
    }
}


void qemu_send_packet_proxy(NetClientState *vc, const uint8_t *buf, int size)
{
    struct iovec iov;
    int ret;

    if (event_tap_state != EVENT_TAP_ON) {
        goto out;
	}

    if (gft_packet_can_send(buf, size)) {
        goto out;
	}

    iov.iov_base = (uint8_t*)buf;
    iov.iov_len = size;

    ret = net_event_tap(vc, &iov, 1, NULL, 1);
    assert(ret > 0);

#ifdef CONFIG_EPOCH_OUTPUT_TRIGGER
    extern kvmft_notify_new_output();
    kvmft_notify_new_output();
#endif

    return;
out:
    return qemu_send_packet(vc, buf, size);
}
ssize_t qemu_sendv_packet_async_proxy(NetClientState *vc,
                                      const struct iovec *iov,
                                      int iovcnt, NetPacketSent *sent_cb)
{
	int i, size = 0;
	if (event_tap_state != EVENT_TAP_ON)
		goto out;

	for (i = 0; i < iovcnt; ++i) {
		size += iov[i].iov_len;
	}

	if (gft_packet_can_send(iov->iov_base, iov->iov_len)) {
        goto out;
	}

#ifdef CONFIG_EPOCH_OUTPUT_TRIGGER
    extern kvmft_notify_new_output();
    kvmft_notify_new_output();
#endif

	return net_event_tap(vc, iov, iovcnt, sent_cb, 1);
out:
    return qemu_sendv_packet_async(vc, iov, iovcnt, sent_cb);
}

int event_tap_register(int (*cb)(void))
{
    if (event_tap_state != EVENT_TAP_OFF)
        return -1;

    event_tap_state = EVENT_TAP_ON;

    return 0;
}

int event_tap_unregister(void)
{
    if (event_tap_state == EVENT_TAP_OFF)
        return -1;

    event_tap_state = EVENT_TAP_OFF;

    event_tap_flush(NULL, NULL);
    event_tap_free_pool();

    return 0;
}

void event_tap_suspend(void)
{
    if (event_tap_state == EVENT_TAP_ON) {
        event_tap_state = EVENT_TAP_SUSPEND;
    }
}

void event_tap_resume(void)
{
    if (event_tap_state == EVENT_TAP_SUSPEND) {
        event_tap_state = EVENT_TAP_ON;
    }
}

int event_tap_get_state(void)
{
    return event_tap_state;
}

void event_tap_ioport(int index, uint32_t address, uint32_t data)
{
    if (event_tap_state != EVENT_TAP_ON) {
        return;
    }

    FTPRINTF("%s %x %d\n", __func__, address, data);

    if (!last_event_tap) {
        last_event_tap = event_tap_alloc_log();
    }

    last_event_tap->mode = EVENT_TAP_IOPORT;
    last_event_tap->ioport.index = index;
    last_event_tap->ioport.address = address;
    last_event_tap->ioport.data = data;
}

void event_tap_mmio(uint64_t address, uint8_t *buf, int len)
{
    if (event_tap_state != EVENT_TAP_ON || len > MMIO_BUF_SIZE) {
        return;
    }

    if (!last_event_tap) {
        last_event_tap = event_tap_alloc_log();
    }

    last_event_tap->mode = EVENT_TAP_MMIO;
    last_event_tap->mmio.address = address;
    last_event_tap->mmio.len = len;
    memcpy(last_event_tap->mmio.buf, buf, len);
}

static void event_tap_net_flush(EventTapNetReq *net_req)
{
    NetClientState *vc;
    ssize_t len;

    if (net_req->vlan_needed) {
        vc = net_hub_find_client_by_name(net_req->vlan_id,
                                           net_req->device_name);
    } else {
        vc = qemu_find_netdev(net_req->device_name);
    }

    if (net_req->async) {
        len = qemu_sendv_packet_async(vc, net_req->iov, net_req->iovcnt,
										event_tap_net_cb);
		assert(len != 0);
        if (len == 0) {
            printf("This packet is appended\n");
        }
    } else {
        qemu_send_packet(vc, net_req->iov[0].iov_base,
                         net_req->iov[0].iov_len);
    }
}

/* returns 1 if the queue gets emtpy */
static int event_tap_flush_one_net(EventTapLogList *list)
{
    EventTapLog *log;

	if (list->head >= list->tail)
		return 1;

    log = list->logs[list->head];
	list->logs[list->head] = NULL;
	++list->head;

    assert ((log->mode & ~EVENT_TAP_TYPE_MASK) == EVENT_TAP_NET);

    event_tap_net_flush(&log->net_req);

    event_tap_free_log(log);

    return list->head >= list->tail;
}


/* returns 1 if the queue gets emtpy */

int event_tap_flush_one(void)
{
    EventTapLog *log;

    if (cuju_ft_mode == CUJU_FT_TRANSACTION_HANDOVER) {
        FTPRINTF("%s is empty? %d\n", __func__, QTAILQ_EMPTY(event_list));
    }

    if (QTAILQ_EMPTY(event_list)) {
        return 1;
    }

    log = QTAILQ_FIRST(event_list);
    switch (log->mode & ~EVENT_TAP_TYPE_MASK) {
    case EVENT_TAP_NET:
        event_tap_net_flush(&log->net_req);
        QTAILQ_REMOVE(event_list, log, node);
        event_tap_free_log(log);
        break;
    case EVENT_TAP_BLK:


        fprintf(stderr, "ERROR: EVENT_TAP_BLK is handled by virtio-blk\n");
        break;
    default:
        fprintf(stderr, "Unknown state %d\n", log->mode);
        return -1;
    }

    return QTAILQ_EMPTY(event_list);
}

int event_tap_flush(void* cb, void *opaque)
{
    int ret;

    bdrv_request_flush_cb = cb;
    bdrv_request_flush_opaque = opaque;

    do {
        ret = event_tap_flush_one();
    } while (ret == 0);

    if (pending_bdrv_request == 0) {
        bdrv_request_flush_cb(opaque);
	}
    return ret;
}

int event_tap_flush_net(EventTapLogList *list)
{
    int ret;

    do {
        ret = event_tap_flush_one_net(list);
    } while (ret == 0);

    return ret;
}


// must be invoked when previous output flushed.
void event_tap_take_snapshot(void **n, void **e)
{
    pending_bdrv_request_old = pending_bdrv_request;
    pending_bdrv_request = 0;
}

static void event_tap_replay(void *opaque, int running, RunState reason)
{
    EventTapLog *log, *next;

    return;

    if (!running) {
        return;
    }

    if (event_tap_state != EVENT_TAP_LOAD) {
        return;
    }

    event_tap_state = EVENT_TAP_REPLAY;

    QTAILQ_FOREACH(log, event_list, node) {

        /* event resume */
        switch (log->mode & ~EVENT_TAP_TYPE_MASK) {
        case EVENT_TAP_NET:
            event_tap_net_flush(&log->net_req);
            break;
        case EVENT_TAP_BLK:
            if ((log->mode & EVENT_TAP_TYPE_MASK) == EVENT_TAP_IOPORT) {
                FTPRINTF("%s ioport %x %d\n", __func__, log->ioport.address, log->ioport.data);
                switch (log->ioport.index) {
                case 0:
                    cpu_outb(log->ioport.address, log->ioport.data);
                    break;
                case 1:
                    cpu_outw(log->ioport.address, log->ioport.data);
                    break;
                case 2:
                    cpu_outl(log->ioport.address, log->ioport.data);
                    break;
                }
            } else {
                /* EVENT_TAP_MMIO */
                cpu_physical_memory_rw(log->mmio.address,
                                       log->mmio.buf,
                                       log->mmio.len, 1);
            }
            break;
        case 0:
            DPRINTF("No event\n");
            break;
        default:
            fprintf(stderr, "Unknown state %d\n", log->mode);
            return;
        }
    }

    /* remove event logs from queue */
    // free after tap cb is called.
    QTAILQ_FOREACH_SAFE(log, event_list, node, next) {
        QTAILQ_REMOVE(event_list, log, node);
        event_tap_free_log(log);
    }

    event_tap_state = EVENT_TAP_OFF;
    qemu_del_vm_change_state_handler(vmstate);
}

static inline void event_tap_ioport_save(QEMUFile *f, EventTapIOport *ioport)
{
    qemu_put_be32(f, ioport->index);
    qemu_put_be32(f, ioport->address);
    qemu_put_byte(f, ioport->data);
}

static inline void event_tap_ioport_load(QEMUFile *f,
                                         EventTapIOport *ioport)
{
    ioport->index = qemu_get_be32(f);
    ioport->address = qemu_get_be32(f);
    ioport->data = qemu_get_byte(f);
}

static inline void event_tap_mmio_save(QEMUFile *f, EventTapMMIO *mmio)
{
    qemu_put_be64(f, mmio->address);
    qemu_put_byte(f, mmio->len);
    qemu_put_buffer(f, mmio->buf, mmio->len);
}

static inline void event_tap_mmio_load(QEMUFile *f, EventTapMMIO *mmio)
{
    mmio->address = qemu_get_be64(f);
    mmio->len = qemu_get_byte(f);
    qemu_get_buffer(f, mmio->buf, mmio->len);
}

static void event_tap_net_save(QEMUFile *f, EventTapNetReq *net_req)
{
    int i, len;

    len = strlen(net_req->device_name);
    qemu_put_byte(f, len);
    qemu_put_buffer(f, (uint8_t *)net_req->device_name, len);
    qemu_put_byte(f, net_req->vlan_id);
    qemu_put_byte(f, net_req->vlan_needed);
    qemu_put_byte(f, net_req->iovcnt);

    for (i = 0; i < net_req->iovcnt; i++) {
        qemu_put_be64(f, net_req->iov[i].iov_len);
        qemu_put_buffer(f, (uint8_t *)net_req->iov[i].iov_base,
                        net_req->iov[i].iov_len);
    }
}

static void event_tap_net_load(QEMUFile *f, EventTapNetReq *net_req)
{
    int i, len;

    len = qemu_get_byte(f);
    net_req->device_name = g_malloc(len + 1);
    qemu_get_buffer(f, (uint8_t *)net_req->device_name, len);
    net_req->device_name[len] = '\0';
    net_req->vlan_id = qemu_get_byte(f);
    net_req->vlan_needed = qemu_get_byte(f);
    net_req->iovcnt = qemu_get_byte(f);
    net_req->iov = g_malloc(sizeof(struct iovec) * net_req->iovcnt);

    for (i = 0; i < net_req->iovcnt; i++) {
        net_req->iov[i].iov_len = qemu_get_be64(f);
        net_req->iov[i].iov_base = g_malloc(net_req->iov[i].iov_len);
        qemu_get_buffer(f, (uint8_t *)net_req->iov[i].iov_base,
                        net_req->iov[i].iov_len);
    }
}

static void event_tap_blk_save(QEMUFile *f, EventTapBlkReq *blk_req)
{
    int len;

    len = strlen(blk_req->device_name);
    qemu_put_byte(f, len);
    qemu_put_buffer(f, (uint8_t *)blk_req->device_name, len);
    qemu_put_byte(f, blk_req->num_reqs);
    qemu_put_byte(f, blk_req->num_cbs);

}

static void event_tap_blk_load(QEMUFile *f, EventTapBlkReq *blk_req)
{
    int len;

    len = qemu_get_byte(f);
    blk_req->device_name = g_malloc(len + 1);
    qemu_get_buffer(f, (uint8_t *)blk_req->device_name, len);
    blk_req->device_name[len] = '\0';
    blk_req->num_reqs = qemu_get_byte(f);
    blk_req->num_cbs = qemu_get_byte(f);

}

void event_tap_save(QEMUFile *f, void *opaque)
{
    EventTapLog *log;

    FTPRINTF("%s is empty %d\n", __func__, QTAILQ_EMPTY(event_list));

    QTAILQ_FOREACH(log, event_list, node) {
        qemu_put_byte(f, log->mode);
        DPRINTF("log->mode=%d\n", log->mode);
        switch (log->mode & EVENT_TAP_TYPE_MASK) {
        case EVENT_TAP_IOPORT:
            event_tap_ioport_save(f, &log->ioport);
            break;
        case EVENT_TAP_MMIO:
            event_tap_mmio_save(f, &log->mmio);
            break;
        case 0:
            DPRINTF("No event\n");
            break;
        default:
            fprintf(stderr, "Unknown state %d\n", log->mode);
            return;
        }

        switch (log->mode & ~EVENT_TAP_TYPE_MASK) {
        case EVENT_TAP_NET:
            event_tap_net_save(f, &log->net_req);
            break;
        case EVENT_TAP_BLK:
            event_tap_blk_save(f, &log->blk_req);
            break;
        default:
            fprintf(stderr, "Unknown state %d\n", log->mode);
            return;
        }
    }

    qemu_put_byte(f, 0); /* EOF */
}


int event_tap_load(QEMUFile *f, void *opaque, int version_id)
{
    EventTapLog *log, *next;
    int mode;

    FTPRINTF("%s is_emptyr ? %d\n", __func__, QTAILQ_EMPTY(event_list));

    event_tap_state = EVENT_TAP_LOAD;

    QTAILQ_FOREACH_SAFE(log, event_list, node, next) {
        QTAILQ_REMOVE(event_list, log, node);
        event_tap_free_log(log);
    }

    /* loop until EOF */
    while ((mode = qemu_get_byte(f)) != 0) {
        EventTapLog *log = event_tap_alloc_log();

        log->mode = mode;
        switch (log->mode & EVENT_TAP_TYPE_MASK) {
        case EVENT_TAP_IOPORT:
            event_tap_ioport_load(f, &log->ioport);
            break;
        case EVENT_TAP_MMIO:
            event_tap_mmio_load(f, &log->mmio);
            break;
        case 0:
            DPRINTF("No event\n");
            break;
        default:
            fprintf(stderr, "Unknown state %d\n", log->mode);
            return -1;
        }

        switch (log->mode & ~EVENT_TAP_TYPE_MASK) {
        case EVENT_TAP_NET:
            event_tap_net_load(f, &log->net_req);
            break;
        case EVENT_TAP_BLK:
            event_tap_blk_load(f, &log->blk_req);
            break;
        default:
            fprintf(stderr, "Unknown state %d\n", log->mode);
            return -1;
        }

        QTAILQ_INSERT_TAIL(event_list, log, node);
    }

    return 0;
}

void *event_tap_get_list(int state, int event)
{
	if (event)
		return &event_list_data[state];
	return event_tap_log_list[state];
}

void event_tap_start_epoch(void *net_list, void *blk_list, void *old_net_list, void *old_blk_list)
{
	event_list = (QueueEventTapLog *)blk_list;
	net_event_list = (EventTapLogList *)net_list;

	if (net_event_list->head != net_event_list->tail) {
        printf("%s %p\n", __func__, net_event_list);
        printf("%s %d != %d\n", __func__, net_event_list->head, net_event_list->tail);
    }
	assert(net_event_list->head == net_event_list->tail);
	net_event_list->head = 0;
	net_event_list->tail = 0;

    QTAILQ_INIT(event_list);
	// NOTE _old is useless right now
	event_list_old = (QueueEventTapLog *)old_blk_list;
}

void event_tap_extend(int index)
{
    event_tap_log_list = g_realloc(event_tap_log_list,
                                   sizeof(EventTapLogList*) * (index + 1));
    event_tap_log_list[index] = g_malloc0(sizeof(EventTapLogList));
}

static void __event_tap_flush_net_list(void *opaque)
{
    NetListFlushRequest *req = opaque;
    int ret = event_tap_flush_net(req->list);
    assert(ret);
    req->cb(req->opaque);
    qemu_bh_delete(req->bh);
    g_free(req->list);
    g_free(req);
}

void event_tap_flush_net_list(void *net_list, void *cb, void *opaque)
{
    NetListFlushRequest *req = g_malloc(sizeof(NetListFlushRequest));
    req->list = net_list;
    req->cb = cb;
    req->opaque = opaque;
    req->bh = qemu_bh_new(__event_tap_flush_net_list, req);
    qemu_bh_set_mig_survive(req->bh, true);
    qemu_bh_schedule(req->bh);
}

void *event_tap_net_list_new(void)
{
    return g_malloc0(sizeof(EventTapLogList));
}

bool event_tap_net_list_empty(void *net_list)
{
    EventTapLogList *list = net_list;
    return list->head == list->tail;
}

void event_tap_init(void)
{
    int i;

    event_tap_log_list = (EventTapLogList **)g_malloc0(sizeof(EventTapLogList*) * KVM_DIRTY_BITMAP_INIT_COUNT);
    for (i = 0; i < KVM_DIRTY_BITMAP_INIT_COUNT; i++) {
        event_tap_log_list[i] = g_malloc0(sizeof(EventTapLogList));
    }

    net_event_list = event_tap_log_list[1];
    event_list = &event_list_data[1];

    event_list_old = &event_list_data[0];

	// the one this epoch is using
	event_list_data_offset = 0;

    QTAILQ_INIT(event_list);
    QTAILQ_INIT(event_list_old);

    QTAILQ_INIT(&event_list_pending);
    QTAILQ_INIT(&event_pool);

    vmstate = qemu_add_vm_change_state_handler(event_tap_replay, NULL);
}
