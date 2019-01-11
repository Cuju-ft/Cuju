#include "kvm_blk.h"
#include "error.h"
#include "qemu/sockets.h"
#include "qemu/main-loop.h"
#include "qemu/queue.h"
#include "qapi/error.h"
#include <stdio.h>
#include <stdlib.h>
#include "block/block_int.h"
#include "qemu/atomic.h"
#include "block/block.h"
#include "qemu/osdep.h"
#include "migration/migration.h"
extern QTAILQ_HEAD(, BlockDriverState) all_bdrv_states;


#define BLK_SERVER_WRITE_CALLBACK_LIMIT 10
#define BLK_SERVER_SESSION_INIT_BUF  4096000

KvmBlkSession *kvm_blk_session = NULL;
bool kvm_blk_is_server = false;

uint32_t write_request_id = 0;

uint32_t debug_flag = 0;

int wreq_quota;
struct kvm_blk_request *wreq_head,*wreq_last;

static inline int kvm_blk_recv_header(KvmBlkSession *s)
{
    int retval;
    int err;

retry:
   retval = recv(s->sockfd, (void *)(&s->recv_hdr) + s->input_buf_tail,sizeof(s->recv_hdr) - s->input_buf_tail, 0); 
   err = errno;
    if (retval == 0) {
        if (debug_flag == 1) {
          printf("disconn %d\n", s->sockfd);
        }
        return -ENOTCONN;
    }
    if (retval < 0) {
        if (err == EINTR)
            goto retry;
        return -err;
    }
    s->input_buf_tail += retval;
    if (s->input_buf_tail != sizeof(s->recv_hdr))
        goto retry;

    s->input_buf_tail = 0;
    s->input_buf_head = 0;

    if (debug_flag == 1) {
         debug_printf("\n\nreceived header, cmd %d paylen %d\n", s->recv_hdr.cmd, s->recv_hdr.payload_len);
    }

    if (s->recv_hdr.payload_len > 0)
        s->is_payload = 1;
    else
        s->is_payload = 0;

    return sizeof(s->recv_hdr);
}


static void kvm_blk_read_ready(void *opaque)
{
    int retval, err;
    KvmBlkSession *s = opaque;
    assert(!qemu_iohandler_is_ft_paused());
    if (debug_flag == 1) {
        debug_printf("read ready called %p is_payload %d.\n", s, s->is_payload);
    }
    do {
        if (s->is_payload == 0) {
            retval = kvm_blk_recv_header(s);
            if (retval == -EAGAIN || retval == -EWOULDBLOCK)
                break;
            if (retval < 0) {
                perror("blk-server-> recv header");
                goto clear;
            }
            if (s->recv_hdr.payload_len == 0) {
                s->cmd_handler(s);
                continue;
            }
            // we got payload, fall throught.
        }

        if (s->recv_hdr.payload_len > s->input_buf_size) {
            s->input_buf_size = s->recv_hdr.payload_len;
            s->input_buf = g_realloc(s->input_buf, s->recv_hdr.payload_len);
        }
        retval = recv(s->sockfd, s->input_buf + s->input_buf_tail,
                      s->recv_hdr.payload_len - s->input_buf_tail, 0);
        err = errno;
        if (retval == 0) {
            printf("%s: disconn.\n", __func__);
            goto clear;
        }
        if (retval < 0) {
            if (err == EINTR)
                continue;
            if (err == EAGAIN)
                break;
            perror("blk-server->recv header");
            goto clear;
        }
        s->input_buf_tail += retval;
        if (s->input_buf_tail == s->recv_hdr.payload_len) {
            s->cmd_handler(s);
            s->input_buf_head = 0;
            s->input_buf_tail = 0;
            s->is_payload = 0;
        }
    } while (1);
    return;
clear:
    qemu_set_fd_handler(s->sockfd, 0, 0, 0);
    if (s->close_handler)
        s->close_handler(s);
}
static void kvm_blk_write_ready(void *opaque)
{
    int retval;
    KvmBlkSession *s = opaque;
    if (unlikely(s->sockfd == -1))
        return;
    qemu_set_fd_handler(s->sockfd, CUJU_IO_HANDLER_KEEP, NULL, s);
    if (debug_flag == 1) {
        debug_printf("%p write ready called, %d.\n", s,
                    s->output_buf_tail - s->output_buf_head);
    }

    if (s->output_buf_tail - s->output_buf_head == 0)
        return;

    do {
        retval = send(s->sockfd, s->output_buf + s->output_buf_head,
                      s->output_buf_tail - s->output_buf_head, 0);
        if (debug_flag == 1) {
            debug_printf("send returns %d\n", retval);
        }
        if (retval <= 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN) {
                break;
            }
            perror("blk-server send: ");
            goto error;
        }

        s->output_buf_head += retval;
    } while (s->output_buf_tail > s->output_buf_head);

    if (s->output_buf_tail == s->output_buf_head) {
        s->output_buf_head = 0;
        s->output_buf_tail = 0;
    } else
        qemu_set_fd_handler(s->sockfd, CUJU_IO_HANDLER_KEEP, kvm_blk_write_ready, s);
    return;
error:
    if (debug_flag == 1) {
       debug_printf("clear called.\n");
    }
    qemu_set_fd_handler(s->sockfd, 0, 0, 0);

}

void kvm_blk_output_flush(KvmBlkSession *s)
{
    kvm_blk_write_ready(s);
}

static inline void kvm_blk_output_expand(KvmBlkSession *s, int len)
{
    if (s->output_buf_tail + len > s->output_buf_size) {
        s->output_buf_size = s->output_buf_tail + len;
        s->output_buf = g_realloc(s->output_buf, s->output_buf_size);
    }
}

void kvm_blk_output_append(KvmBlkSession *s, void *buf, int len)
{
    kvm_blk_output_expand(s, len);
    memcpy(s->output_buf + s->output_buf_tail, buf, len);
    s->output_buf_tail += len;
}
void kvm_blk_output_append_iov(KvmBlkSession *s, QEMUIOVector *iov)
{
    kvm_blk_output_expand(s, iov->size);
    qemu_iovec_to_buf(iov,0, s->output_buf + s->output_buf_tail,iov->size);
    s->output_buf_tail += iov->size;
}

int kvm_blk_recv(KvmBlkSession *s, void *buf, int len)
{
    if (len > s->input_buf_tail - s->input_buf_head)
        len = s->input_buf_tail - s->input_buf_head;
    if (len == 0)
        return 0;
    memcpy(buf, s->input_buf + s->input_buf_head, len);
    s->input_buf_head += len;
    return len;
}

void kvm_blk_input_to_iov(KvmBlkSession *s, QEMUIOVector *iov)
{
    qemu_iovec_from_buf(iov, 0,s->input_buf + s->input_buf_head,
                            s->input_buf_tail - s->input_buf_head);
}
static void kvm_blk_accept(void *opaque)
{
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int s = (intptr_t)opaque;
    int c;
    KvmBlkSession *session;
    uint32_t wid = -1;

    do {
        c = qemu_accept(s, (struct sockaddr *)&addr, &addrlen);
    } while (c == -1 && socket_error() == EINTR);
printf("accepted blk client %d.\n", c);

    if (c == -1) {
        fprintf(stderr, "could not accept blk client.\n");
        goto out;
    }

    session = kvm_blk_serv_wait_prev(wid);

    session = g_malloc0(sizeof(KvmBlkSession));

    // read latest write_request_id
    recv(c, &wid, sizeof(wid), 0);    
    session->sockfd = c;
    session->ft_mode = 0;
    session->bs = QTAILQ_FIRST(&all_bdrv_states);
    if (!session->bs) {
        fprintf(stderr, "%s: no aviablable block device.\n", __func__);
        return;
    }

    session->output_buf_size = BLK_SERVER_SESSION_INIT_BUF;
    session->output_buf = g_malloc(session->output_buf_size);

    session->input_buf_size = BLK_SERVER_SESSION_INIT_BUF;
    session->input_buf = g_malloc(session->input_buf_size);

    session->cmd_handler = kvm_blk_serv_handle_cmd;
    session->close_handler = kvm_blk_serv_handle_close;

    kvm_blk_server_internal_init(session);
    socket_set_nodelay(c);
    qemu_set_nonblock(c);
    qemu_set_fd_handler(c, kvm_blk_read_ready,
                       NULL, session);
    kvm_blk_session = session;
		//for wreq list callback to client
		wreq_quota = BLK_SERVER_WRITE_CALLBACK_LIMIT; 
		wreq_head = NULL;
		wreq_last = NULL;
    return;
out:
    qemu_set_fd_handler(s, NULL, NULL, NULL);
    close(s);
}
int kvm_blk_server_init(const char *p)
{
    int s;
    Error *err = NULL;
    kvm_blk_is_server = true;

    SocketAddress* sa = socket_parse(p, &err);

    if (err) {
        error_report_err(err);
    }
    
    s = socket_listen(sa, &err);
    if (err) {
        error_report_err(err);
    }
    if (s <= 0)
        return -1;

    assert(!qemu_iohandler_is_ft_paused());
    qemu_set_fd_handler(s,kvm_blk_accept,NULL,(void *)(intptr_t)s);
    return 0;
}
int kvm_blk_client_init(const char *ipnport)
{
    int sockfd;
    Error *err = NULL;
    KvmBlkSession *s;
    int retval;
    QIOChannelSocket *sioc = NULL;
    //gft_init(4445);
    SocketAddress* sa = socket_parse(ipnport, &err);
    if (err) {
        error_report_err(err);
        return -1;
    }
    sioc = qio_channel_socket_new();
    qio_channel_set_name(QIO_CHANNEL(sioc), "blkserver");
    trace_qio_channel_socket_connect_sync(sioc, sa);
    qio_channel_socket_connect_sync(sioc,
                                    sa,
                                    &err);
    if (err) {
        error_report_err(err);
        return -1;
    }
    sockfd = sioc->fd;
    retval = send(sockfd, &write_request_id, sizeof(write_request_id), 0);
    assert(retval == sizeof(write_request_id));

    s = g_malloc0(sizeof(KvmBlkSession));
    s->sockfd = sockfd;
    s->bs = QTAILQ_FIRST(&all_bdrv_states);

    s->output_buf_size = BLK_SERVER_SESSION_INIT_BUF;
    s->output_buf = g_malloc(s->output_buf_size);

    s->input_buf_size = BLK_SERVER_SESSION_INIT_BUF;
    s->input_buf = g_malloc(s->input_buf_size);

    QTAILQ_INIT(&s->request_list);

    s->cmd_handler = kvm_blk_client_handle_cmd;
    socket_set_nodelay(sockfd);
    qemu_set_nonblock(sockfd);
    assert(!qemu_iohandler_is_ft_paused());
    qemu_set_fd_handler(sockfd,kvm_blk_read_ready,NULL,s);

    kvm_blk_session = s;
    qemu_mutex_init(&s->mutex);
    return 0;
}
