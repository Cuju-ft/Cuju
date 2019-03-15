#ifndef _INCLUDE_KVM_BLK_H
#define _INCLUDE_KVM_BLK_H

#include <stdint.h>

#include "qemu/osdep.h"
#include "trace.h"
#include "block/block_int.h"
#include "block/blockjob.h"
#include "block/nbd.h"
#include "qemu/error-report.h"
#include "module_block.h"
#include "qemu/module.h"
#include "qapi/qmp/qerror.h"
#include "qapi/qmp/qbool.h"
#include "qapi/qmp/qjson.h"
#include "sysemu/block-backend.h"
#include "sysemu/sysemu.h"
#include "qemu/notify.h"
#include "qemu/coroutine.h"
#include "block/qapi.h"
#include "qmp-commands.h"
#include "qemu/timer.h"
#include "qapi-event.h"
#include "qemu/cutils.h"
#include "qemu/id.h"
#include "qapi/util.h"

#include "qemu/atomic.h"
#include "qemu/thread.h"

//-----------

//#define DEBUG_BLK_SERVER 1

#ifdef DEBUG_BLK_SERVER
#define debug_printf(fmt, ...) \
    do { printf("blk-server: " fmt, ## __VA_ARGS__); } while (0)
#else
#define debug_printf(fmt, ...) \
    do { } while (0)
#endif

#define KVM_BLK_INPUT_BUF_LEN  1024000

typedef struct kvm_blk_header {
    uint32_t cmd;
    int32_t payload_len;
    int32_t id;
    int32_t num_reqs;
} KvmBlkHeader;

typedef int (*BLK_CMD_HANDLER)(void *opaque);

typedef void (*BLK_ACK_CB)(void *opaque);

typedef void (*BLK_CLOSE_CB)(void *opaque);

struct kvm_blk_session;

extern uint32_t write_request_id;

#define KVM_BLK_CMD_READ        0x1
#define KVM_BLK_CMD_WRITE       0x2
#define KVM_BLK_CMD_EPOCH_TIMER 0x3
#define KVM_BLK_CMD_COMMIT      0x4
#define KVM_BLK_CMD_COMMIT_ACK  0x5
#define KVM_BLK_CMD_FT          0x6
#define KVM_BLK_CMD_ISSUE       0x7

//------------------------------

struct kvm_blk_request {
    int64_t sector;
    int nb_sectors;
    int cmd;
    QEMUIOVector iov;
    struct kvm_blk_session *session;

    BlockCompletionFunc *cb;
    void *opaque;
    QEMUIOVector *piov;

    int32_t id;
    BdrvRequestFlags flags;
    int num_reqs;

    int ret_fast_read;
		
	struct kvm_blk_request *next;
	struct kvm_blk_request *prev;
	
	//for control disk call back speed
	double time_write,time_cb,time_recv;

    QTAILQ_ENTRY(kvm_blk_request) node;
};

typedef struct kvm_blk_session {
    int sockfd;
    int is_payload;
    BlockDriverState *bs;
    
    void *output_buf;
    int output_buf_size;
    int output_buf_tail;  // where to start put new bytes.
    int output_buf_head;  // where to start transfer, until tail.

    void *input_buf;
    int input_buf_size;
    int input_buf_tail;
    int input_buf_head;

    KvmBlkHeader send_hdr;
    KvmBlkHeader recv_hdr;
    BLK_CMD_HANDLER cmd_handler;

    // when client closes, drop all pending read requests,
    // and drop all pending write request backwards until last epoch_start.
    BLK_CLOSE_CB close_handler;

    BLK_ACK_CB ack_cb;
    void *ack_cb_opaque;

    QTAILQ_HEAD(request_list, kvm_blk_request) request_list;

    QemuMutex mutex;
	QemuMutex list_mutex;

    struct kvm_blk_request *issue;

	QemuThread send_thread;
	QemuCond cond;
	QemuMutex send_mutex;
    int id;
    int ft_mode;
	//for control disk call back speed
	double disk_speed;
	double time_last_send;
} KvmBlkSession;

struct kvm_blk_read_control {
    int64_t sector_num;
    int32_t nb_sectors;
} __attribute__((packed));

struct kvm_blk_bh {
    QEMUBH *bh;
    KvmBlkSession *session; 
};

// ret value passed for kvm_blk_rw_cb
// can be negative to indicate err.
#define KVM_BLK_RW_NONE     0
#define KVM_BLK_RW_FAST     1
#define KVM_BLK_RW_PARTIAL  2

extern KvmBlkSession *kvm_blk_session;
extern bool kvm_blk_is_server;

int kvm_blk_server_init(const char *port);
void kvm_blk_server_internal_init(KvmBlkSession *s);
int kvm_blk_client_init(const char *ipnport);
int kvm_blk_serv_handle_cmd(void *opaque);
void kvm_blk_serv_handle_close(void *opaque);
KvmBlkSession* kvm_blk_serv_wait_prev(uint32_t wid);
int kvm_blk_client_handle_cmd(void *opaque);

// only append to output buf.
void kvm_blk_output_append(KvmBlkSession *s, void *buf, int len);
void kvm_blk_output_flush(KvmBlkSession *s);
void kvm_blk_output_append_iov(KvmBlkSession *s, QEMUIOVector *iov);

// read from session's input buf.
// return length of bytes read.
int kvm_blk_recv(KvmBlkSession *s, void *buf, int len);

// put everything inside input_buf to iov.
void kvm_blk_input_to_iov(KvmBlkSession *s, QEMUIOVector *iov);
struct kvm_blk_request *kvm_blk_aio_readv(BlockBackend *blk,
                                        int64_t sector_num,
                                        QEMUIOVector *iov,
                                        BdrvRequestFlags flags,
                                        BlockCompletionFunc *cb,
                                        void *opaque);
struct kvm_blk_request *kvm_blk_aio_write(BlockBackend *blk,int64_t sector_num,QEMUIOVector *iov,BdrvRequestFlags flags,BlockCompletionFunc *cb,void *opaque);

// insert an epoch mark in serv's pending request list.
void kvm_blk_epoch_start(KvmBlkSession *s);
// commit all pending request after the epoch mark.
void kvm_blk_epoch_commit(KvmBlkSession *s);
void kvm_blk_epoch_timer(KvmBlkSession *s);
void kvm_blk_notify_ft(KvmBlkSession *s);

static inline void kvm_blk_set_ack_cb(KvmBlkSession *s,
                                    BLK_ACK_CB cb, void *opaque) {
    s->ack_cb = cb;
    s->ack_cb_opaque = opaque;
}

static inline bool kvm_blk_check_ack_cb(KvmBlkSession *s) {
    return s->ack_cb != NULL;
}

//send write callback to client
#define BLK_SERVER_WRITE_CALLBACK_LIMIT 32
void* kvm_blk_server_wcallback(void*);
void kvm_blk_server_free_wreq(void);
void kvm_blk_write_speed(KvmBlkSession *s,struct kvm_blk_request *br);
void kvm_blk_fake_write_waiting(struct kvm_blk_request *br);

//for failover:handle pending request
struct kvm_blk_request *kvm_blk_save_pending_request(BlockBackend *blk,int64_t sector_num,QEMUIOVector *iov, BdrvRequestFlags flags,BlockCompletionFunc *cb,void *opaque,int cmd);
void kvm_blk_do_pending_request(KvmBlkSession *s);

//for send thread
void *kvm_blk_send_thread(void *opaque);

#endif
