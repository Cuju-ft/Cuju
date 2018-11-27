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
 *
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "migration/qemu-file.h"
#include "sysemu/sysemu.h"
#include "block/block.h"
#include "qapi/qmp/qerror.h"
#include "qapi/util.h"
#include "qemu/sockets.h"
#include "qemu/rcu.h"
#include "qemu/thread.h"
#include "qmp-commands.h"
#include "trace.h"
#include "qapi-event.h"
#include "qom/cpu.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "migration/cuju-ft-trans-file.h"
#include "io/channel-socket.h"
#include <linux/kvm.h>
#include "migration/migration.h"
#include "kvm_blk.h"

static QemuMutex *cuju_buf_desc_mutex = NULL;
static QemuCond *cuju_buf_desc_cond = NULL;

int cuju_is_load = 0;
QemuMutex cuju_load_mutex;
QemuCond cuju_load_cond;

extern void kvm_shmem_load_ram(void *buf, int size);
extern void kvm_shmem_load_ram_with_hdr(void *buf, int size, void *hdr_buf, int hdr_size);

char *blk_server = NULL;
extern bool check_is_blk;

static CujuQEMUFileFtTrans **cuju_ft_trans;
static int cuju_ft_trans_count;
static int cuju_ft_trans_current_index;

static CujuQEMUFileFtTrans *cuju_ft_trans_get_next(CujuQEMUFileFtTrans *s)
{
    int index = s->index;
    index = (index + 1) % cuju_ft_trans_count;
    return cuju_ft_trans[index];
}

static void cuju_ft_trans_buf_desc_insert(CujuQEMUFileFtTrans *s, struct cuju_buf_desc *buf)
{
    s->buf_tail->next = buf;
    s->buf_tail = buf;
}

static struct cuju_buf_desc *cuju_ft_trans_buf_desc_delete_first(CujuQEMUFileFtTrans *s)
{
    struct cuju_buf_desc *desc = s->buf_header->next;

    assert(desc);

    s->buf_header->next = desc->next;
    if (s->buf_header->next == NULL)
        s->buf_tail = s->buf_header;
    return desc;
}

static struct cuju_buf_desc *cuju_ft_trans_buf_desc_peek_first(CujuQEMUFileFtTrans *s)
{
    return s->buf_header->next;
}

void cuju_ft_trans_flush_buf_desc(void *opaque)
{
    struct cuju_buf_desc *desc;
    size_t offset;
    QEMUFile *f = opaque;
    CujuQEMUFileFtTrans *s = f->opaque;

    do {
        desc = cuju_ft_trans_buf_desc_peek_first(s);
        if (!desc)
            return;

        if (s->has_error) {
            error_report("flush when error %d, bailing\n", s->has_error);
            return;
        }

        offset = desc->off;
        while (offset < desc->size) {
            ssize_t ret;

            ret = s->put_buffer(s->opaque, desc->buf + offset, desc->size - offset);
            if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
                //desc->off = offset;
                //break;
                continue;
            } else if (ret <= 0) {
                error_report("error flushing data, %s\n", strerror(errno));
                printf("%s %p + %lu\n", __func__, desc->buf, offset);
                s->has_error = CUJU_FT_TRANS_ERR_FLUSH;
                abort();
                return;
            } else {
                offset += ret;
            }
        }

        if (offset == desc->size) {
            assert(desc == cuju_ft_trans_buf_desc_delete_first(s));
            g_free(desc->buf);
            g_free(desc);
        } else {
            // should try again..
            abort();
        }
    } while (1);
}

void cuju_ft_trans_init_buf_desc(QemuMutex *mutex, QemuCond *cond)
{
    cuju_buf_desc_mutex = mutex;
    cuju_buf_desc_cond = cond;
}

static int cuju_ft_trans_buffer_mode = 0;
void cuju_ft_trans_set_buffer_mode(int on)
{
    cuju_ft_trans_buffer_mode = on;
}

int cuju_ft_trans_is_buffer_mode(void)
{
    return cuju_ft_trans_buffer_mode;
}

int cuju_ft_trans_is_sender(void *opaque)
{
    CujuQEMUFileFtTrans *f = opaque;
    return f->is_sender;
}

static void cuju_ft_trans_clean_buf(CujuQEMUFileFtTrans *s)
{
    int consumed = s->file->pos;
    int left = s->get_offset - consumed;
    if (left == 0) {
        s->get_offset = 0;
        s->file->pos = 0;
    }
}

static void cuju_ft_trans_append(CujuQEMUFileFtTrans *s,
                            const uint8_t *buf, size_t size)
{
    if (size > (s->buf_max_size - s->put_offset)) {
        trace_cuju_ft_trans_realloc(s->buf_max_size, s->put_offset + size);
        s->buf_max_size = s->put_offset + size;
        s->buf = g_realloc(s->buf, s->buf_max_size);
    }

    trace_cuju_ft_trans_append(size);
    memcpy(s->buf+s->put_offset, buf, size);
    s->put_offset += size;
}

static void cuju_ft_trans_flush_sync(void *opaque, size_t *off)
{
    CujuQEMUFileFtTrans *s = opaque;
    size_t offset = *off;

    if (s->has_error) {
        error_report("flush when error %d, bailing\n", s->has_error);
        return;
    }

    while (offset < s->put_offset) {
        ssize_t ret;

        ret = s->put_buffer(s->opaque, s->buf + offset, s->put_offset - offset);
        if (ret == -EAGAIN || ret == -EWOULDBLOCK)
            break;

        if (ret <= 0) {
            error_report("error flushing data, %s\n", strerror(errno));
            s->has_error = CUJU_FT_TRANS_ERR_FLUSH;
            break;
        } else {
            offset += ret;
        }
    }
    *off = offset;
}

static void cuju_ft_trans_flush(void *opaque)
{
    CujuQEMUFileFtTrans *s = opaque;
    size_t offset = 0;

    if (s->has_error) {
        error_report("flush when error %d, bailing\n", s->has_error);
        return;
    }

    while (offset < s->put_offset) {
        ssize_t ret;

        ret = s->put_buffer(s->opaque, s->buf + offset, s->put_offset - offset);
        if (ret == -EAGAIN || ret == -EWOULDBLOCK)
            break;

        if (ret <= 0) {
            error_report("error flushing data, %s\n", strerror(errno));
            s->has_error = CUJU_FT_TRANS_ERR_FLUSH;
            break;
        } else {
            offset += ret;
        }
    }

    trace_cuju_ft_trans_flush(offset, s->put_offset);
    memmove(s->buf, s->buf + offset, s->put_offset - offset);
    s->put_offset -= offset;
    s->freeze_output = !!s->put_offset;
}

void cuju_ft_trans_flush_buffer(void *opaque)
{
    CujuQEMUFileFtTrans *s = opaque;
    size_t offset = 0;
    while (!s->has_error && offset != s->put_offset) {
        cuju_ft_trans_flush_sync(s, &offset);
        if (s->freeze_output)
            s->wait_for_unfreeze(s);
    }
    s->put_offset = 0;
}

/*
    buf - from g_malloc, should be freed after using.
*/
static ssize_t cuju_ft_trans_put(void *opaque, void *buf, int size)
{
    CujuQEMUFileFtTrans *s = opaque;
    size_t offset = 0;
    ssize_t len;

    if (cuju_ft_trans_buffer_mode) {
        struct cuju_buf_desc *desc = g_malloc(sizeof(struct cuju_buf_desc));
        desc->opaque = s;
        desc->off = 0;
        desc->buf = buf;
        desc->size = size;
        desc->next = NULL;
        cuju_ft_trans_buf_desc_insert(s, desc);
        return size;
    }

    if (s->is_sender)
        printf("%s: unexpected here.\n", __func__);

    if (!s->freeze_output && s->put_offset)
        cuju_ft_trans_flush(s);

    while (!s->freeze_output && offset < size) {
        len = s->put_buffer(s->opaque, (uint8_t *)buf + offset, size - offset);

        if (len == -EAGAIN || len == -EWOULDBLOCK) {
            continue;
            //trace_cuju_ft_trans_freeze_output();
            //s->freeze_output = 1;
            //break;
        }

        if (len <= 0) {
            error_report("putting data failed, %ld %s\n", len, strerror(errno));
            s->has_error = 1;
            offset = -EINVAL;
            break;
        }

        offset += len;
    }

    if (s->freeze_output) {
        cuju_ft_trans_append(s, buf + offset, size - offset);
        offset = size;
    }

    assert(offset == size);
    return offset;
}

int cuju_ft_trans_send_header(CujuQEMUFileFtTrans *s,
                        enum CUJU_QEMU_VM_TRANSACTION_STATE state,
                        uint32_t payload_len)
{
    int ret;
    //FtTransHdr *hdr = &s->header;
    CujuFtTransHdr *hdr = g_malloc0(sizeof(s->header));
    static int hdr_idx = 0;

    //HDRPRINTF("(%8d)%s %d [%u]\n", ++hdr_idx, __func__, state, payload_len);

    //if (state == QEMU_VM_TRANSACTION_BEGIN)
        ++hdr_idx;

#ifdef ft_debug_mode_enable
    if (state != QEMU_VM_TRANSACTION_CONTINUE) {
        printf("%s (%8d) %d %d\n", __func__, hdr_idx, state, payload_len);
    }
#endif

    trace_cuju_ft_trans_send_header(state);

    hdr->magic = CUJU_FT_HDR_MAGIC;
    hdr->cmd = s->state = state;
    hdr->id = s->id;
    hdr->payload_len = payload_len;
    hdr->seq = hdr_idx;
    hdr->serial = s->ft_serial;

    ret = cuju_ft_trans_put(s, hdr, sizeof(*hdr));
    if (ret < 0) {
        error_report("send header failed\n");
        s->has_error = CUJU_FT_TRANS_ERR_SEND_HDR;
    }

    cuju_ft_trans_flush_buf_desc(s->file);

    assert(ret == sizeof(*hdr));

    return ret;
}

static int cuju_ft_trans_put_buffer(void *opaque, uint8_t *buf, int64_t pos, int size)
{
    CujuQEMUFileFtTrans *s= opaque;
    ssize_t ret = 0;

    //printf("%s %d\n", __func__, __LINE__);

    trace_cuju_ft_trans_put_buffer(size, pos);

    if (s->has_error) {
        error_report("put_buffer when error %d, bailing\n", s->has_error);
        exit(-1);
        return -EINVAL;
    }

    /* assuming qemu_file_put_notify() is calling */
    if (pos == 0 && size == 0) {
        qemu_mutex_lock(cuju_buf_desc_mutex);
        qemu_cond_broadcast(cuju_buf_desc_cond);
        qemu_mutex_unlock(cuju_buf_desc_mutex);
        goto out;

        trace_cuju_ft_trans_put_ready();
        cuju_ft_trans_flush(s);

        // not freeze_output means all buf has been flushed
        if (!s->freeze_output) {
            trace_cuju_ft_trans_cb(s->put_ready);
            ret = s->put_ready();
        }

        goto out;
    }

    //printf("%s %d\n", __func__, __LINE__);
    ret = cuju_ft_trans_send_header(s, CUJU_QEMU_VM_TRANSACTION_CONTINUE, size);
    if (ret < 0)
        goto out;

    //printf("%s %d\n", __func__, __LINE__);
    ret = cuju_ft_trans_put(s, (uint8_t *)buf, size);
    if (ret < 0) {
        error_report("send payload failed\n");
        s->has_error = CUJU_FT_TRANS_ERR_SEND_PAYLOAD;
        goto out;
    }

    cuju_ft_trans_flush_buf_desc(s->file);

    s->seq++;

out:
    return ret;
}

static int cuju_ft_trans_fill_buffer(void *opaque, void *buf, int size)
{
    CujuQEMUFileFtTrans *s = opaque;
    size_t offset = 0;
    ssize_t len;

    while (!s->freeze_output && offset < size) {
        len = s->get_buffer(s->opaque, (uint8_t *)buf + offset,
                            0, size - offset);
        if (len == -EAGAIN || len == -EWOULDBLOCK) {
            trace_cuju_ft_trans_freeze_input();
            s->freeze_input = 1;
            break;
        }

        if (len < 0) {
            error_report("fill buffer failed, eagain %d ret %d %s\n",
                EAGAIN, errno, strerror(errno));
            s->has_error = 1;
            return -EINVAL;
        }

        offset += len;
    }

    return offset;
}

static int cuju_ft_trans_recv_header(CujuQEMUFileFtTrans *s)
{
    int ret;
    char *buf = (char *)&s->header + s->header_offset;
    static int hdr_idx = 0;

    ret = cuju_ft_trans_fill_buffer(s, buf, sizeof(CujuFtTransHdr) - s->header_offset);
    if (ret < 0) {
        error_report("recv header failed\n");
        s->has_error = CUJU_FT_TRANS_ERR_RECV_HDR;
        goto out;
    }

    s->header_offset += ret;

    if (s->freeze_input) {
        goto out;
    }

    if (s->header_offset == sizeof(CujuFtTransHdr)) {
        ++hdr_idx;
#ifdef ft_debug_mode_enable
        if (s->header.cmd != QEMU_VM_TRANSACTION_CONTINUE) {
            printf("%s (%8d) %d %d\n", __func__, s->header.seq, s->header.cmd,
                (int)s->header.payload_len);
        }
#endif

        if (s->header.cmd == CUJU_QEMU_VM_TRANSACTION_COMMIT1)
            s->ram_buf_expect = s->header.payload_len;

        if (s->header.magic != CUJU_FT_HDR_MAGIC) {
            error_report("recv header magic wrong: %x\n", s->header.magic);
            s->has_error = CUJU_FT_TRANS_ERR_RECV_HDR;
            goto out;
        }

        trace_cuju_ft_trans_recv_header(s->header.cmd);
        s->state = s->header.cmd;
        s->header_offset = 0;
        s->ft_serial = s->header.serial;


        if (!s->is_sender) {
            s->id = s->header.id;
            s->seq = s->header.seq;
        }
    }

out:
    return ret;
}

static int cuju_ft_trans_recv_payload(CujuQEMUFileFtTrans *s)
{
    int ret = -1;

    if (s->header.payload_len > (s->buf_max_size - s->get_offset)) {
        s->buf_max_size += (s->header.payload_len -
                            (s->buf_max_size - s->get_offset));
        s->buf = g_realloc(s->buf, s->buf_max_size);
    }

    ret = cuju_ft_trans_fill_buffer(s, s->buf + s->get_offset,
                               s->header.payload_len);
    if (ret < 0) {
        error_report("recv payload failed\n");
        s->has_error = CUJU_FT_TRANS_ERR_RECV_PAYLOAD;
        goto out;
    }

    trace_cuju_ft_trans_recv_payload(ret, s->header.payload_len, s->get_offset);

    s->header.payload_len -= ret;
    s->get_offset += ret;
    s->is_payload = !!s->header.payload_len;

out:
    return ret;
}

CujuQEMUFileFtTrans *last_cuju_ft_trans = NULL;

static void cuju_ft_trans_load(CujuQEMUFileFtTrans *s)
{
#ifdef ft_debug_mode_enable
    qemu_timeval stime, etime;
    qemu_gettimeofday(&stime);
#endif

    if (s->ram_hdr_buf_put_off > 0)
        kvm_shmem_load_ram_with_hdr(s->ram_buf, s->ram_buf_put_off, s->ram_hdr_buf, s->ram_hdr_buf_put_off);
    else
        kvm_shmem_load_ram(s->ram_buf, s->ram_buf_put_off);

    s->ram_buf_put_off = 0;
    s->ram_hdr_buf_put_off = 0;
    s->ram_buf_expect = -1;
    last_cuju_ft_trans = s;

#ifdef ft_debug_mode_enable
    qemu_gettimeofday(&etime);
    printf("%s take time(ms) %lf\n", __func__, (TIMEVAL_TO_DOUBLE(etime) - TIMEVAL_TO_DOUBLE(stime))*1000);
#endif

	// TODO
	// check protocol in qemu_loadvm_state()
	// qemu_loadvm_state(s->file, 1);
    qemu_loadvm_state(s->file, 1);

    cuju_ft_trans_clean_buf(s);

    qemu_mutex_lock(&cuju_load_mutex);
    cuju_is_load = 0;
    qemu_cond_broadcast(&cuju_load_cond);
    qemu_mutex_unlock(&cuju_load_mutex);

#ifdef ft_debug_mode_enable
    qemu_gettimeofday(&etime);
    printf("%s %lf\n", __func__, (TIMEVAL_TO_DOUBLE(etime) - TIMEVAL_TO_DOUBLE(stime))*1000);
#endif
}

static bool cuju_ft_trans_load_ready(CujuQEMUFileFtTrans *s)
{
    return s->ram_buf_put_off + s->ram_hdr_buf_put_off == s->ram_buf_expect;
}

static int cuju_ft_trans_try_load(CujuQEMUFileFtTrans *s)
{
    int ret = 0;
    static unsigned long ft_serial = 1;

    qemu_mutex_lock(&cuju_load_mutex);
    while (cuju_is_load == 1)
        qemu_cond_wait(&cuju_load_cond, &cuju_load_mutex);
    cuju_is_load = 1;
    qemu_mutex_unlock(&cuju_load_mutex);

#ifdef ft_debug_mode_enable
    if (cuju_ft_trans_load_ready(s)) {
        printf("%s %p->ft_serial = %ld/%ld ready %d\n", __func__, s, s->ft_serial, ft_serial, cuju_ft_trans_load_ready(s));
    }
#endif

    while (s->ft_serial == ft_serial && cuju_ft_trans_load_ready(s)) {
        ret = cuju_ft_trans_send_header(s, CUJU_QEMU_VM_TRANSACTION_ACK1, 0);
        if (ret < 0) {
            printf("%s send ack failed.\n", __func__);
            goto out;
        }
        cuju_ft_trans_load(s);
        s = cuju_ft_trans_get_next(s);
        ft_serial++;
#ifdef ft_debug_mode_enable
        printf("%s try next %p->ft_serial = %ld/%ld ready %d\n", __func__, s, s->ft_serial, ft_serial, cuju_ft_trans_load_ready(s));
#endif
    }
out:
    qemu_mutex_lock(&cuju_load_mutex);
    cuju_is_load = 0;
    qemu_cond_broadcast(&cuju_load_cond);
    qemu_mutex_unlock(&cuju_load_mutex);

    return ret;
}

static int cuju_ft_trans_recv(CujuQEMUFileFtTrans *s)
{
    static int first_commit1 = true;
    int ret;

    if (s->is_payload) {
        ret = cuju_ft_trans_recv_payload(s);
        goto out;
    }

    ret = cuju_ft_trans_recv_header(s);
    if (ret < 0 || s->freeze_input) {
        goto out;
    }

    //if (s->state != QEMU_VM_TRANSACTION_CONTINUE)
    //    printf("%s received header %d %d\n", __func__, s->state, s->header.payload_len);

    switch (s->state) {
    case CUJU_QEMU_VM_TRANSACTION_BEGIN:
        s->is_payload = 0;
        //kvm_shm_tick_start(s->time_trace);
        //kvm_shm_tick_step(s->time_trace, "begin");
        break;

    case CUJU_QEMU_VM_TRANSACTION_NOCOPY: {
        //printf("%s %p nocopy %d, after %d\n", __func__, s, s->ram_fd_expect,
        //  s->header.payload_len * 4096);
        if (s->ram_fd_expect == -1)
            s->ram_fd_expect = 0;
        s->ram_fd_expect += s->header.payload_len * 4096;
        s->is_payload = 0;
        break;
    }

    case CUJU_QEMU_VM_TRANSACTION_CONTINUE:
        s->is_payload = 1;
        break;
    case CUJU_QEMU_VM_TRANSACTION_COMMIT:
        s->is_payload = 0;
        ret = cuju_ft_trans_send_header(s, CUJU_QEMU_VM_TRANSACTION_ACK, 0);
        if (ret < 0) {
          printf("%s send ack failed.\n", __func__);
          goto out;
        }
        break;

    case CUJU_QEMU_VM_TRANSACTION_COMMIT1:
        s->is_payload = 0;

        trace_cuju_ft_trans_cb(s->get_ready);

        ret = cuju_ft_trans_try_load(s);
        if (ret < 0) {
          goto out;
        }

        if (first_commit1) {
            first_commit1 = false;
            printf("first commit\n");
            qemu_loadvm_dev(s->file);
        }

        break;

    case CUJU_QEMU_VM_TRANSACTION_ATOMIC:
        error_report("QEMU_VM_TRANSACTION_ATOMIC not implemented. %d\n",
            ret);
        break;

    case CUJU_QEMU_VM_TRANSACTION_CANCEL:
        ret = -EINVAL;
        break;

    default:
        error_report("unknown QEMU_VM_TRANSACTION_STATE %d\n", ret);
        s->has_error = CUJU_FT_TRANS_ERR_STATE_INVALID;
        ret = -EINVAL;
    }

out:
    return ret;
}



static ssize_t cuju_ft_trans_get_buffer(void *opaque, uint8_t *buf,
								int64_t pos, size_t size)
{
    CujuQEMUFileFtTrans *s = opaque;
    int ret;

    //if (s->has_error) {
    //    error_report("get_buffer when error %d, bailing\n", s->has_error);
    //    return -EINVAL;
    //}

    // assuming qemu_file_get_notify() is calling
    if (pos == 0 && size == 0) {
        trace_cuju_ft_trans_get_ready();
        s->freeze_input = 0;

        // sender should be waiting for ACK
        // after successfully receiving ACK, ft_mode = FT_INIT, s->state = ACK
        if (s->is_sender) {

            goto newver;

            ret = cuju_ft_trans_recv_header(s);
            if (s->freeze_input) {
                ret = 0;
                goto out;
            }
            if (ret < 0) {
                error_report("recv ack failed\n");
                goto out;
            }

            if (s->state != CUJU_QEMU_VM_TRANSACTION_ACK) {
                error_report("recv invalid state %d %d\n", __LINE__, s->state);
                s->has_error = CUJU_FT_TRANS_ERR_STATE_INVALID;
                ret = -EINVAL;
                goto out;
            }

            s->state = CUJU_QEMU_VM_TRANSACTION_CONTINUE;

            trace_cuju_ft_trans_cb(s->get_ready);

newver:
            // notify sender that we received ACK from backup
            ret = s->get_ready(s->opaque);
            if (ret < 0)
                goto out;

            s->id++;

            return 0;
        }


        ret = cuju_ft_trans_recv(s);
        goto out;
    }

    if (pos >= s->get_offset)
        return 0;
    if (pos + size > s->get_offset)
        size = s->get_offset - pos;
    //printf("%s copying from FtTRansFileBuf to QEMUFile buf\n", __func__);
    memcpy(buf, s->buf+pos, size);

    ret = size;
    // old: ret = s->get_offset;

out:
    return ret;
}

static int cuju_ft_trans_close(void *opaque)
{
    Error *local_err = NULL;
    CujuQEMUFileFtTrans *s = opaque;
    int ret;
    
    trace_cuju_ft_trans_close();
    ret = s->close(s->opaque);
    if (s->is_sender)
        g_free(s->buf);
    if (!s->is_sender) {
        qemu_mutex_lock(&cuju_load_mutex);
        while (cuju_is_load == 1)
            qemu_cond_wait(&cuju_load_cond, &cuju_load_mutex);
        qemu_mutex_unlock(&cuju_load_mutex);
        if(s != last_cuju_ft_trans)
            return 0;
        bdrv_drain_all();
        bdrv_invalidate_cache_all(&local_err);

		if (local_err) {
			error_report_err(local_err);
			exit(EXIT_FAILURE);
		}

        s->has_error = 0;
		s->file->last_error = 0;
		qemu_loadvm_dev(s->file);

        bdrv_drain_all();

        bdrv_invalidate_cache_all(&local_err);

		if (local_err) {
			error_report_err(local_err);
			exit(EXIT_FAILURE);
		}

        qemu_announce_self();
        
        vm_state_notify(1, RUN_STATE_RUNNING);
        if (blk_server) {
            int ret = kvm_blk_client_init(blk_server);
            check_is_blk = true;
            if (ret < 0) {
                exit(ret);
            }
        }
        
        cuju_ft_mode = CUJU_FT_TRANSACTION_HANDOVER;
        vm_start();
        printf("%s vm_started.\n", __func__);
    }

    return ret;
}


int cuju_ft_trans_recv_ack(void *opaque)
{
    int ret;
    CujuQEMUFileFtTrans *s = opaque;

    ret = cuju_ft_trans_recv_header(s);
    if (ret < 0) {
        if (!s->freeze_input) {
            error_report("recv ack failed\n");
            goto out;
        }
    }

    if (s->freeze_input) {
        ret = -EAGAIN;
        goto out;
    }

    if (s->header.cmd != CUJU_QEMU_VM_TRANSACTION_ACK) {
        error_report("recv invalid state %d %d\n", s->header.cmd,
            CUJU_QEMU_VM_TRANSACTION_ACK);
        s->has_error = CUJU_FT_TRANS_ERR_STATE_INVALID;
        ret = -EINVAL;
        goto out;
    }
out:
    return ret;
}

int cuju_ft_trans_send_begin(void *opaque)
{
    int ret;
    CujuQEMUFileFtTrans *s = opaque;

    assert(s->last_cmd == CUJU_QEMU_VM_TRANSACTION_COMMIT);
    s->last_cmd = CUJU_QEMU_VM_TRANSACTION_BEGIN;

    ret = cuju_ft_trans_send_header(s, CUJU_QEMU_VM_TRANSACTION_BEGIN, 0);
    if (ret < 0) {
        printf("%s send BEGIN failed %d\n", __func__, ret);
        goto out;
    }

    s->state = CUJU_QEMU_VM_TRANSACTION_CONTINUE;

out:
    return ret;
}

int cuju_ft_trans_begin(void *opaque)
{
    CujuQEMUFileFtTrans *s = opaque;
    int ret;
    s->seq = 0;

    /* receiver sends ACK to start transaction */
    if (!s->is_sender) {
        if (s->state != CUJU_QEMU_VM_TRANSACTION_INIT) {
            error_report("invalid state %d\n", s->state);
            s->has_error = CUJU_FT_TRANS_ERR_STATE_INVALID;
            ret = -EINVAL;
            goto out;
        }

        ret = cuju_ft_trans_send_header(s, CUJU_QEMU_VM_TRANSACTION_ACK, 0);
        last_cuju_ft_trans = s;
        if (ret != sizeof(CujuFtTransHdr))
            ret = -EAGAIN;

        goto out;
    }

    /* sender waits for ACK to start transaction */
    //if (s->state == QEMU_VM_TRANSACTION_INIT) {
    if (1) {
        ret = cuju_ft_trans_recv_header(s);
        if (ret < 0) {
            if (!s->freeze_input) {
                error_report("recv ack failed\n");
                goto out;
            }
        }

        if (s->freeze_input) {
            ret = -EAGAIN;
            goto out;
        }

        if (s->state != CUJU_QEMU_VM_TRANSACTION_ACK) {
            error_report("recv invalid state %d %d\n", s->state,
                CUJU_QEMU_VM_TRANSACTION_ACK);
            s->has_error = CUJU_FT_TRANS_ERR_STATE_INVALID;
            ret = -EINVAL;
            goto out;
        }
    }

    ret = cuju_ft_trans_send_header(s, CUJU_QEMU_VM_TRANSACTION_BEGIN, 0);
    if (ret < 0) {
        printf("%s send BEGIN failed %d\n", __func__, ret);
        goto out;
    }

    assert(s->last_cmd == CUJU_QEMU_VM_TRANSACTION_COMMIT);
    s->last_cmd = CUJU_QEMU_VM_TRANSACTION_BEGIN;

    s->state = CUJU_QEMU_VM_TRANSACTION_CONTINUE;

out:
    return ret;
}

int cuju_ft_trans_receive_ack1(void *opaque)
{
    CujuQEMUFileFtTrans *s = opaque;
    int ret = -1;

    /* sender waits for ACK1 to start transaction */
    ret = cuju_ft_trans_recv_header(s);
    if (ret < 0) {
        goto out;
    }

    if (s->state != CUJU_QEMU_VM_TRANSACTION_ACK1) {
        ret = -EINVAL;
        goto out;
    }

out:
    return ret;
}

void cuju_ft_trans_read_headers(void *opaque)
{
    CujuQEMUFileFtTrans *s = opaque;
    int ret;
    const int bunk = 4096;

    do {
        if (s->ram_hdr_buf_size < s->ram_hdr_buf_put_off + bunk) {
            s->ram_hdr_buf_size += bunk;
            s->ram_hdr_buf = g_realloc(s->ram_hdr_buf, s->ram_hdr_buf_size);
        }

        ret = recv(s->ram_hdr_fd, s->ram_hdr_buf + s->ram_hdr_buf_put_off, bunk, 0);
        if (ret == 0) {
            printf("%s: disconn\n", __func__);
            goto clear;
        }
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                return;
            printf("%s recv %d err.\n", __func__, s->ram_hdr_fd);
            perror("recv err: ");
            goto clear;
        }
        s->ram_hdr_buf_put_off += ret;
        ret = cuju_ft_trans_try_load(s);
        if (ret < 0) {
            goto clear;
        }
    } while (1);
    return;
clear:
    qemu_set_fd_handler(s->ram_hdr_fd, NULL, NULL, NULL);
    close(s->ram_hdr_fd);
    s->ram_hdr_fd = -1;
}

void cuju_ft_trans_read_pages(void *opaque)
{
    CujuQEMUFileFtTrans *s = opaque;
    int ret;
    const int bunk = 4096;

    do {
        if (s->ram_buf_size < s->ram_buf_put_off + bunk) {
            s->ram_buf_size += bunk;
            s->ram_buf = g_realloc(s->ram_buf, s->ram_buf_size);
        }

        ret = recv(s->ram_fd, s->ram_buf + s->ram_buf_put_off, bunk, 0);
        if (ret == 0) {
            printf("%s: disconn\n", __func__);
            goto clear;
        }
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                return;
            perror("recv err: ");
            goto clear;
        }
        cuju_socket_set_quickack(s->ram_fd);
        s->ram_buf_put_off += ret;
        if (cuju_ft_trans_load_ready(s)) {
            ret = cuju_ft_trans_try_load(s);
            if (ret < 0) {
                goto clear;
            }
        }
    } while (1);
    return;
clear:
    qemu_set_fd_handler(s->ram_fd, NULL, NULL, NULL);
    close(s->ram_fd);
    s->ram_fd = -1;
}

void cuju_ft_trans_skip_pages(void *opaque)
{
    int fd = (long long)opaque;
    int ret;
    char buf[4096];

    do {
        ret = recv(fd, buf, 4096, 0);
        if (ret == 0)
            goto clear;
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN)
                return;
            goto clear;
        }
        cuju_socket_set_quickack(fd);
    } while (1);
    return;
clear:
    qemu_set_fd_handler(fd, NULL, NULL, NULL);
    close(fd);
    fd = -1;
}

int cuju_ft_trans_flush_output(void *opaque)
{
    CujuQEMUFileFtTrans *s = opaque;
    int ret = -1;

    if (s->is_sender) {
        /* sender waits for ACK1 to start transaction */
        ret = cuju_ft_trans_recv_header(s);
        if (ret < 0) {
            if (!s->freeze_input) {
                error_report("recv ack1 failed\n");
                goto out;
            }
        }

        if (s->freeze_input) {
            ret = -EAGAIN;
            goto out;
        }

        if (s->header.cmd != CUJU_QEMU_VM_TRANSACTION_ACK1) {
            error_report("recv invalid state %d\n", s->header.cmd);
            s->has_error = CUJU_FT_TRANS_ERR_STATE_INVALID;
            ret = -EINVAL;
            goto out;
        }
    }

    s->state = CUJU_QEMU_VM_TRANSACTION_CONTINUE;

out:
    return ret;
}

int cuju_ft_trans_commit1(void *opaque, int ram_len, unsigned long serial)
{
    CujuQEMUFileFtTrans *s = opaque;
    int ret;

    assert(s->is_sender);

    assert(s->last_cmd == CUJU_QEMU_VM_TRANSACTION_BEGIN);
    s->last_cmd = CUJU_QEMU_VM_TRANSACTION_COMMIT1;

    s->ft_serial = serial;

    ret = cuju_ft_trans_send_header(s, CUJU_QEMU_VM_TRANSACTION_COMMIT1, ram_len);
    if (ret < 0) {
        printf("%s send COMMIT1 failed %d\n", __func__, ret);
        goto out;
    }

    s->state = CUJU_QEMU_VM_TRANSACTION_CONTINUE;

out:
    return ret;
}

/*
    sync wait until all buf are flushed.
    returns 0 on success or -err
*/
int cuju_ft_trans_commit(void *opaque)
{
    CujuQEMUFileFtTrans *s = opaque;
    int ret;

    if (!s->is_sender) {
        ret = cuju_ft_trans_send_header(s, CUJU_QEMU_VM_TRANSACTION_ACK, 0);
        goto out;
    }

    assert(s->last_cmd == CUJU_QEMU_VM_TRANSACTION_COMMIT1 ||
        s->last_cmd == CUJU_QEMU_VM_TRANSACTION_BEGIN);

    s->last_cmd = CUJU_QEMU_VM_TRANSACTION_COMMIT;

    ret = cuju_ft_trans_send_header(s, CUJU_QEMU_VM_TRANSACTION_COMMIT, 0);

out:
    return ret;
}

int cuju_ft_trans_cancel(void *opaque)
{
    CujuQEMUFileFtTrans *s = opaque;

    if (!s->is_sender) {
        return -EINVAL;
    }

    return cuju_ft_trans_send_header(s, CUJU_QEMU_VM_TRANSACTION_CANCEL, 0);
}

void cuju_qemu_set_last_cmd(void *file, int cmd)
{
    QEMUFile *f = file;
    CujuQEMUFileFtTrans *s = f->opaque;
    s->last_cmd = cmd;
}

// TODO
// Complete the cuju version QEMUFileOps
static const QEMUFileOps cuju_ops = {
    .put_buffer = cuju_ft_trans_put_buffer,
	.get_buffer = cuju_ft_trans_get_buffer,
    .close = cuju_ft_trans_close,
	// TODO
	// complete The following function in cuju-version
    //.shut_down = channel_shutdown,
    //.set_blocking = channel_set_blocking,
    //.get_return_path = channel_get_output_return_path,
};

QEMUFile *cuju_qemu_fopen_ops_ft_trans(void *opaque,
                                  CujuFtTransPutBufferFunc *put_buffer,
                                  CujuFtTransGetBufferFunc *get_buffer,
                                  CujuFtTransPutReadyFunc *put_ready,
                                  CujuFtTransGetReadyFunc *get_ready,
                                  CujuFtTransWaitForUnfreezeFunc *wait_for_unfreeze,
                                  CujuFtTransCloseFunc *close,
                                  bool is_sender,
                                  int ram_fd,
                                  int ram_hdr_fd)
{
    CujuQEMUFileFtTrans *s;

    s = g_malloc0(sizeof(*s));

    s->opaque = opaque;
    s->put_buffer = put_buffer;
    s->get_buffer = get_buffer;
    s->put_ready = put_ready;
    s->get_ready = get_ready;
    s->wait_for_unfreeze = wait_for_unfreeze;
    s->close = close;
    s->is_sender = is_sender;
    s->id = 0;
    s->seq = 0;
    // better to explicitly give a value
    s->state = CUJU_QEMU_VM_TRANSACTION_INIT;

    s->ram_hdr_fd = ram_hdr_fd;

    s->ram_fd = ram_fd;
    s->ram_fd_expect = -1;
    s->ram_fd_recved = -1;
    s->ram_fd_ack = 0;

    s->ram_buf_expect = -1;

    s->last_cmd = CUJU_QEMU_VM_TRANSACTION_COMMIT;

    s->_buf_header.next = NULL;
    s->buf_header = &s->_buf_header;
    s->buf_tail = &s->_buf_header;

    if (!s->is_sender) {
        s->buf_max_size = 0;
        static const QEMUFileOps cuju_ops = {
            .get_buffer = cuju_ft_trans_get_buffer,
            .close = cuju_ft_trans_close,
        };
        s->file = qemu_fopen_ops(s, &cuju_ops);
        return s->file;
    }

    //assert(!kvm_shm_tick_alloc(1, 30, &s->time_trace));

	// TODO
	// Uncomment this when completing the cuju version QEMUFileOps
    s->file = qemu_fopen_ops(s, &cuju_ops);

    return s->file;
}

void cuju_ft_trans_init(void)
{
    cuju_ft_trans_count = KVM_DIRTY_BITMAP_INIT_COUNT;
    cuju_ft_trans = g_malloc0(sizeof(CujuQEMUFileFtTrans *) * cuju_ft_trans_count);
    cuju_ft_trans_current_index = 0;
}

void cuju_ft_trans_set(int index, void *opaque)
{
    CujuQEMUFileFtTrans *s = opaque;
    assert(index < cuju_ft_trans_count);
    cuju_ft_trans[index] = s;
    s->index = index;
}

void cuju_ft_trans_extend(void *opaque)
{
    cuju_ft_trans = g_realloc(cuju_ft_trans, sizeof(CujuQEMUFileFtTrans *)
                                    * (cuju_ft_trans_count + 1));
    cuju_ft_trans_count++;
    cuju_ft_trans_set(cuju_ft_trans_count - 1, opaque);
}
void cuju_socket_set_nodelay(int fd)
{
    int val = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
}

void cuju_socket_unset_nodelay(int fd)
{
    int val = 0;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
}

void cuju_socket_set_quickack(int fd)
{
    int i = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, (void *)&i, sizeof(i));
}

