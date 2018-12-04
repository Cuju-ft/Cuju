/*
 *
 * Copyright (c) 2017 ITRI
 *
 * Authors:
 *  Yi-feng Sun         <pkusunyifeng@gmail.com>
 *  Wei-Chen Liao       <ms0472904@gmail.com>
 *  Po-Jui Tsao         <pjtsao@itri.org.tw>
 *  Yu-Shiang Lin       <YuShiangLin@itri.org.tw>
 *
 */

#ifndef QEMU_CUJU_FT_TRANS_FILE_H
#define QEMU_CUJU_FT_TRANS_FILE_H

#include "hw/hw.h"

enum CUJU_QEMU_VM_TRANSACTION_STATE {
    CUJU_QEMU_VM_TRANSACTION_NACK = -1,
    CUJU_QEMU_VM_TRANSACTION_INIT,
    CUJU_QEMU_VM_TRANSACTION_BEGIN,
    CUJU_QEMU_VM_TRANSACTION_CONTINUE,
    CUJU_QEMU_VM_TRANSACTION_COMMIT,
    CUJU_QEMU_VM_TRANSACTION_CANCEL,
    CUJU_QEMU_VM_TRANSACTION_ATOMIC, // 5
    CUJU_QEMU_VM_TRANSACTION_ACK,
    CUJU_QEMU_VM_TRANSACTION_ACK1,
    CUJU_QEMU_VM_TRANSACTION_COMMIT1,
    CUJU_QEMU_VM_TRANSACTION_NOCOPY,
    CUJU_QEMU_VM_TRANSACTION_DEV_HEADER,
    CUJU_QEMU_VM_TRANSACTION_DEV_STATES,
};

enum CUJU_FT_MODE {
    CUJU_FT_ERROR = -1,
    CUJU_FT_OFF,
    CUJU_FT_INIT,                    // 1
    CUJU_FT_TRANSACTION_PRE_RUN,
    CUJU_FT_TRANSACTION_ITER,
    CUJU_FT_TRANSACTION_ATOMIC,
    CUJU_FT_TRANSACTION_RECV,        // 5
    CUJU_FT_TRANSACTION_HANDOVER,
    CUJU_FT_TRANSACTION_SPECULATIVE,
    CUJU_FT_TRANSACTION_FLUSH_OUTPUT,
    CUJU_FT_TRANSACTION_TRANSFER,
    CUJU_FT_TRANSACTION_SNAPSHOT,    // 10
    CUJU_FT_TRANSACTION_RUN,
};

extern enum CUJU_FT_MODE cuju_ft_mode;

typedef ssize_t (CujuFtTransPutBufferFunc)(void *opaque, const void *data, size_t size);
typedef int (CujuFtTransGetBufferFunc)(void *opaque, uint8_t *buf, int64_t pos, size_t size);
typedef ssize_t (CujuFtTransPutVectorFunc)(void *opaque, const struct iovec *iov, int iovcnt);
typedef int (CujuFtTransPutReadyFunc)(void);
typedef int (CujuFtTransGetReadyFunc)(void *opaque);
typedef void (CujuFtTransWaitForUnfreezeFunc)(void *opaque);
typedef int (CujuFtTransCloseFunc)(void *opaque);

/* a list of buf to be sent */
struct cuju_buf_desc {
    void *opaque;
    void *buf;
    size_t size;
    size_t off;
    struct cuju_buf_desc *next;
};

typedef struct CujuFtTransHdr
{
    uint64_t serial;
    uint32_t magic;
    uint32_t payload_len;
    uint16_t cmd;
    uint16_t id;
    uint16_t seq;
} CujuFtTransHdr;

#define CUJU_FT_HDR_MAGIC    0xa5a6a7a8

typedef struct CujuQEMUFileFtTrans
{
    CujuFtTransPutBufferFunc *put_buffer;
    CujuFtTransGetBufferFunc *get_buffer;
    CujuFtTransPutReadyFunc *put_ready;
    CujuFtTransGetReadyFunc *get_ready;
    CujuFtTransWaitForUnfreezeFunc *wait_for_unfreeze;
    CujuFtTransCloseFunc *close;
    void *opaque;
    QEMUFile *file;

    unsigned long ft_serial;

    enum CUJU_QEMU_VM_TRANSACTION_STATE state;
    uint32_t seq;
    uint16_t id;

    int has_error;

    bool freeze_output;
    bool freeze_input;
    bool is_sender;
    bool is_payload;

    uint8_t *buf;
    size_t buf_max_size;
    size_t put_offset;
    size_t get_offset;

    struct cuju_buf_desc _buf_header;
    struct cuju_buf_desc *buf_header;
    struct cuju_buf_desc *buf_tail;

    CujuFtTransHdr header;
    size_t header_offset;

    int last_cmd;
    int index;

    void *ram_buf;
    int ram_buf_size;
    int ram_buf_put_off;

    void *ram_hdr_buf;
    int ram_hdr_buf_size;
    int ram_hdr_buf_put_off;

    // sent by sender in COMMIT1.payload_len
    // -1 if not received.
    int ram_buf_expect;

    int ram_hdr_fd;

    int ram_fd;
    int ram_fd_recved;  // reset to -1
    int ram_fd_expect;  // reset to -1
    int ram_fd_ack;     // should ram_fd handler send back ack?

} CujuQEMUFileFtTrans;

void *cuju_process_incoming_thread(void *opaque);

extern void *cuju_ft_trans_s1;
extern void *cuju_ft_trans_s2;
extern void *cuju_ft_trans_curr;
extern void *cuju_ft_trans_next;

#define CUJU_FT_TRANS_ERR_UNKNOWN        0x01 /* Unknown error */
#define CUJU_FT_TRANS_ERR_SEND_HDR       0x02 /* Send header failed */
#define CUJU_FT_TRANS_ERR_RECV_HDR       0x03 /* Recv header failed */
#define CUJU_FT_TRANS_ERR_SEND_PAYLOAD   0x04 /* Send payload failed */
#define CUJU_FT_TRANS_ERR_RECV_PAYLOAD   0x05
#define CUJU_FT_TRANS_ERR_FLUSH          0x06 /* Flush buffered data failed */
#define CUJU_FT_TRANS_ERR_STATE_INVALID  0x07 /* Invalid state */


void cuju_ft_trans_init(void);
void cuju_ft_trans_set(int index, void *s);
void cuju_ft_trans_extend(void *opaque);

int cuju_ft_trans_commit1(void *opaque, int ram_len, unsigned long serial);
int cuju_ft_trans_flush_output(void *opaque);
int cuju_ft_trans_begin(void *opaque);
int cuju_ft_trans_commit(void *opaque);
int cuju_ft_trans_cancel(void *opaque);
int cuju_ft_trans_is_sender(void *opaque);
void cuju_ft_trans_set_buffer_mode(int on);
int cuju_ft_trans_is_buffer_mode(void);
void cuju_ft_trans_flush_buffer(void *opaque);
void cuju_ft_trans_init_buf_desc(QemuMutex *mutex, QemuCond *cond);
void cuju_ft_trans_flush_buf_desc(void *opaque);
int cuju_ft_trans_receive_ack1(void *opaque);
int cuju_ft_trans_recv_ack(void *opaque);
int cuju_ft_trans_send_begin(void *opaque);
void cuju_qemu_set_last_cmd(void *file, int cmd);

void cuju_ft_trans_read_pages(void *opaque);
void cuju_ft_trans_skip_pages(void *opaque);
void cuju_ft_trans_read_headers(void *opaque);
int cuju_ft_trans_send_header(CujuQEMUFileFtTrans *s,
                            enum CUJU_QEMU_VM_TRANSACTION_STATE state,
                            uint32_t payload_len);

QEMUFile *cuju_qemu_fopen_ops_ft_trans(void *opaque,
                                  CujuFtTransPutBufferFunc *put_buffer,
                                  CujuFtTransGetBufferFunc *get_buffer,
                                  CujuFtTransPutReadyFunc *put_ready,
                                  CujuFtTransGetReadyFunc *get_ready,
                                  CujuFtTransWaitForUnfreezeFunc *wait_for_unfreeze,
                                  CujuFtTransCloseFunc *close,
                                  bool is_sender,
                                  int ram_fd,
                                  int ram_hdr_fd);
extern int cuju_is_load;
extern QemuMutex cuju_load_mutex;
extern QemuCond cuju_load_cond;

void cuju_socket_set_nodelay(int fd);
void cuju_socket_unset_nodelay(int fd);
void cuju_socket_set_quickack(int fd);

#endif
