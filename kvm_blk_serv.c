#include "kvm_blk.h"
#include "qemu/thread.h"
#include "qemu/typedefs.h"
extern uint32_t debug_flag;
void kvm_blk_server_internal_init(KvmBlkSession *s)
{
    QTAILQ_INIT(&s->request_list);
}

static void _kvm_blk_free_read_iov(struct kvm_blk_request *br)
{
	g_free(br->iov.iov[0].iov_base);
	qemu_iovec_destroy(&br->iov);
}

static void _kvm_blk_free_write_iov(struct kvm_blk_request *br)
{
	int i;
	for (i = 0; i < br->num_reqs; ++i) {
		BlockRequest *r = &br->reqs[i];
		g_free(r->qiov->iov[0].iov_base);
		qemu_iovec_destroy(r->qiov);
		g_free(r->qiov);
	}
	g_free(br->reqs);
}

static int kvm_blk_fast_readv(KvmBlkSession *s, struct kvm_blk_request *br)
{
	struct kvm_blk_request *var;
	int i, ret = KVM_BLK_RW_NONE;

	assert(br->cmd == KVM_BLK_CMD_READ);

    var = s->issue;
    do {
        var = QTAILQ_NEXT(var, node);
        if (var == br)
            goto out;

        if (var->cmd != KVM_BLK_CMD_WRITE)
            continue;

        for (i = 0; i < var->num_reqs; ++i) {
            BlockRequest *r = &var->reqs[i];
            int src_skip, dst_skip, len;
            if (br->sector >= r->offset && br->sector+br->nb_sectors <= r->offset+r->qiov->size) {
                ret = KVM_BLK_RW_FAST;
                dst_skip = 0;
                src_skip = (br->sector - r->offset) ;
                len = br->nb_sectors ;
            } else if (br->sector < r->offset && br->sector+br->nb_sectors > r->offset) {
                ret = KVM_BLK_RW_PARTIAL;
                dst_skip = (r->offset - br->sector) ;
                src_skip = 0;
                len = MIN(br->sector+br->nb_sectors,r->offset+r->qiov->size) - r->offset;
            } else if (br->sector >= r->offset && br->sector < r->offset+r->qiov->size
                        && br->sector+br->nb_sectors > r->offset+r->qiov->size) {
                ret = KVM_BLK_RW_PARTIAL;
                dst_skip = 0;
                src_skip = (br->sector - r->offset) ;
                len = r->offset + r->qiov->size - br->sector;
            } else {
                continue;
            }
            assert(dst_skip >= 0 && src_skip >= 0 && len > 0);
            qemu_iovec_copy_sup(&br->iov, dst_skip, r->qiov, src_skip, len);
        }
	} while (1);
out:
	return ret;
}

static void kvm_blk_rw_cb(void *opaque, int ret)
{
    struct kvm_blk_request *br = opaque, *p;
    KvmBlkSession *s = br->session;

    if (debug_flag == 1) {
        debug_printf("%s, br = %p cmd = %d ret = %d\n",
    				__func__, br, br->cmd, ret);
    }

    s->send_hdr.cmd = br->cmd;
    s->send_hdr.id = br->id;

    if (debug_flag == 1) {
    	QTAILQ_FOREACH(p, &s->request_list, node) {
    		debug_printf("%s: pending request: %p cmd %d\n", __func__, p, p->cmd);
    	}
    }

    if (ret < 0) {
        s->send_hdr.payload_len = ret;
        kvm_blk_output_append(s, &s->send_hdr, sizeof(s->send_hdr));
        goto out;
    }

    switch (br->cmd) {
        case KVM_BLK_CMD_READ: {
			if (br->ret_fast_read == KVM_BLK_RW_PARTIAL)
				kvm_blk_fast_readv(s, br);
            s->send_hdr.payload_len = br->nb_sectors;
            kvm_blk_output_append(s, &s->send_hdr, sizeof(s->send_hdr));
            kvm_blk_output_append_iov(s, &br->iov);            
            if (debug_flag == 1) {
                debug_printf("send back read %d\n", (int)br->iov.size);
            }
            break;
        }
        case KVM_BLK_CMD_WRITE: {
            if (--br->num_reqs)
                return;
            s->send_hdr.payload_len = 0;
            s->send_hdr.num_reqs = 0;
            kvm_blk_output_append(s, &s->send_hdr, sizeof(s->send_hdr));
            // TODO free reqs, iov bufs            
            if (debug_flag == 1) {
                debug_printf("send write ack.\n");
            }
            break;
        }
        default: {
            fprintf(stderr, "%s, unknown command %d\n", __func__, br->cmd);
            abort();
        }
    }

out:
    kvm_blk_output_flush(s);

    QTAILQ_REMOVE(&s->request_list, br, node);

	if (br->cmd == KVM_BLK_CMD_READ)
		_kvm_blk_free_read_iov(br);
	else if (br->cmd == KVM_BLK_CMD_WRITE)
		_kvm_blk_free_write_iov(br);
    g_free(br);
}

static void __kvm_blk_wait_read_done(KvmBlkSession *s)
{
	struct kvm_blk_request *br;
	do {
		QTAILQ_FOREACH(br, &s->request_list, node) {
			if (br->ret_fast_read == KVM_BLK_RW_PARTIAL) {
				break;
			}
		}
		if (!br)
			break;
		aio_poll(qemu_get_aio_context(), true);
	} while (1);
}

static void __kvm_blk_server_ack_commit(KvmBlkSession *s)
{
	s->send_hdr.cmd = KVM_BLK_CMD_COMMIT_ACK;
	s->send_hdr.payload_len = 0;
	kvm_blk_output_append(s, &s->send_hdr, sizeof(s->send_hdr));
	kvm_blk_output_flush(s);
}

static void __kvm_blk_flush_all(KvmBlkSession *s)
{
	struct kvm_blk_request *br;

    // between issue and epoch_timer
    struct BlockBackend *blk ;
    blk = blk_new();
    br = s->issue;

    do {
		br = QTAILQ_NEXT(br, node);
        assert(br);

		if (br->cmd == KVM_BLK_CMD_EPOCH_TIMER)
			break;

		if (br->cmd == KVM_BLK_CMD_WRITE) {
            // TODO nasty hack, mark br as busy by setting its cb.
            //br->cb = (BlockCompletionFunc *)1;
            blk_insert_bs(blk, s->bs);
            blk_aio_pwritev(blk, br->reqs->offset, br->reqs->qiov,
            0, br->reqs->cb, br->reqs->opaque);
        }
        if (br->cmd == KVM_BLK_CMD_READ) {

            // TODO nasty hack, mark br as busy by setting its cb.
            br->cb = (BlockCompletionFunc *)1;
            blk_insert_bs(blk, s->bs);
            blk_aio_preadv(blk, br->reqs->offset , br->reqs->qiov,
            0, br->reqs->cb, br->reqs->opaque);
        }
	} while (1);

    QTAILQ_REMOVE(&s->request_list, s->issue, node);
    g_free(s->issue);
    br->cmd = KVM_BLK_CMD_ISSUE;
    s->issue = br;
}

KvmBlkSession* kvm_blk_serv_wait_prev(uint32_t wid)
{
    KvmBlkSession *s = kvm_blk_session;
	struct kvm_blk_request *br;
    struct BlockBackend *blk ;
    blk = blk_new();
    printf("\nflag 0\n");
	if (!s)
		return NULL;

    printf("\nflag 1\n");
    __kvm_blk_wait_read_done(s);

    printf("\nflag 2\n");
    // drop all write request behind wid;    
    printf("\n\ndropping~~~~~~~~~~~\n\n");
again:
    QTAILQ_FOREACH(br, &s->request_list, node) {
        if (br->cmd != KVM_BLK_CMD_WRITE) {
            QTAILQ_REMOVE(&s->request_list, br, node);
            g_free(br);
            goto again;
        }
        printf("\nflag 3\n");
        // TODO nasty hacking, pending write request.
        if (br->cb) {
            aio_poll(qemu_get_aio_context(), true);
            goto again;
        }
        printf("\n\n********** br->id = %d **********\n\n", br->id);
        if (br->id > wid) {
            printf("\nflag QQ\n");
            QTAILQ_REMOVE(&s->request_list, br, node);
            g_free(br);
            goto again;
        }
    }
    printf("\nflag 4\n");

    QTAILQ_FOREACH(br, &s->request_list, node) {
        // TODO nasty hack, mark br as busy by setting its cb.
        br->cb = (BlockCompletionFunc *)1;
        blk_insert_bs(blk, s->bs);
        blk_aio_pwritev(blk, br->reqs->offset, br->reqs->qiov,
            br->reqs->flags, br->reqs->cb, br->reqs->opaque);
    }
    printf("\nflag 5\n");

    while (!QTAILQ_EMPTY(&s->request_list))
        aio_poll(qemu_get_aio_context(), true);
    printf("\nflag 6\n");

    // reset buf.
    s->output_buf_tail = s->output_buf_head = 0;
    s->input_buf_tail = s->input_buf_head = 0;
    
    return kvm_blk_session;
}

void kvm_blk_serv_handle_close(void *opaque)
{
    KvmBlkSession *s = opaque;
	struct kvm_blk_request *br;

    // drop all requests after ISSUE
    if (s->ft_mode) {
        br = s->issue;
        while (br != NULL) {
            QTAILQ_REMOVE(&s->request_list, br, node);
            br = QTAILQ_NEXT(br, node);
        }
        s->issue = NULL;
        s->ft_mode = 0;
        s->input_buf_head = 0;
        s->input_buf_tail = 0;
        s->is_payload = 0;
    }

	//qemu_aio_set_fd_handler(s->sockfd, NULL, NULL, NULL, NULL);
    printf("%s close %d\n", __func__, s->sockfd);
    close(s->sockfd);
    s->sockfd = -1;
}



int kvm_blk_serv_handle_cmd(void *opaque)
{
    KvmBlkSession *s = opaque;
    struct kvm_blk_request *br = NULL;
    int ret = 0;
    struct BlockBackend *blk ;
    blk = blk_new();

    if (debug_flag == 1) {
        debug_printf("received cmd %d len %d id num_req %d (%d)\n", s->recv_hdr.cmd,
                      s->recv_hdr.payload_len, s->recv_hdr.num_reqs, s->recv_hdr.id);
    }
    switch (s->recv_hdr.cmd) {
    case KVM_BLK_CMD_READ: {
        struct kvm_blk_read_control c;
		void *new_buf;
		int len;
        ret = kvm_blk_recv(s, &c, sizeof(c));
        if (ret != sizeof(c))
            return -EINVAL;
        if (debug_flag == 1) {
            printf("client read: %ld %d\n", (long)c.sector_num, c.nb_sectors);
        }
        br = g_malloc0(sizeof(struct kvm_blk_request));
        br->sector = c.sector_num;
        br->nb_sectors = c.nb_sectors;
        br->cmd = s->recv_hdr.cmd;
        br->id = s->recv_hdr.id;
        br->session = s;
        qemu_iovec_init(&br->iov, 1);
		len = c.nb_sectors ;
		new_buf = g_malloc(len);
		qemu_iovec_add(&br->iov, new_buf, len);
        QTAILQ_INSERT_TAIL(&s->request_list, br, node);
		// if the read request can be satisfied by pending write requests.
		if (s->ft_mode) {
			ret = kvm_blk_fast_readv(s, br);
			br->ret_fast_read = ret;
			if (ret == KVM_BLK_RW_FAST) {
				kvm_blk_rw_cb(br, 0);
				break;
			}
		}
		// if ret == KVM_BLK_RW_PARTIAL, after read from disk,
		// we need to renew partially from write request list.
        blk_insert_bs(blk, s->bs);
        blk_aio_preadv(blk, c.sector_num, &br->iov,0,
                        kvm_blk_rw_cb, br);
        ret = 0;

        break;
    }
    case KVM_BLK_CMD_WRITE: {
 
        struct kvm_blk_read_control c;
        void *new_buf;
        int len;
        ret = kvm_blk_recv(s, &c, sizeof(c));
        if (ret != sizeof(c))
            return -EINVAL;
        if (debug_flag == 1) {
            printf("client write: %ld %d\n", (long)c.sector_num, c.nb_sectors);
        }
        br = g_malloc0(sizeof(struct kvm_blk_request));
        br->sector = c.sector_num;
        br->nb_sectors = c.nb_sectors;
        br->cmd = s->recv_hdr.cmd;
        br->id = s->recv_hdr.id;
        br->session = s;
        qemu_iovec_init(&br->iov, 1);
        len = c.nb_sectors ;
        new_buf = g_malloc(len);
        ret = kvm_blk_recv(s, new_buf, len);
            //debug_printf("read buf, expect %d get %d\n", len, ret);
            if (ret != len)
                return -EINVAL;
            qemu_iovec_add(&br->iov, new_buf, len);
        QTAILQ_INSERT_TAIL(&s->request_list, br, node);

        if (!s->ft_mode) {

            blk_insert_bs(blk, s->bs);
            blk_aio_pwritev(blk, c.sector_num , &br->iov,0,
                        kvm_blk_rw_cb, br);
        }
        break;
    }

    case KVM_BLK_CMD_EPOCH_TIMER: {
        br = g_malloc0(sizeof(struct kvm_blk_request));
        br->cmd = s->recv_hdr.cmd;
        br->session = s;

        QTAILQ_INSERT_TAIL(&s->request_list, br, node);

        break;
    }

    case KVM_BLK_CMD_COMMIT: {
        // need to wait all reading first.
        // in case: a read request that can be partially satisfied by write list,
        //          after we issue the read
        //          server receives commit, write list flushed before read returns
        //          then read will read old data.
        //__kvm_blk_wait_read_done(s);
        __kvm_blk_flush_all(s);
        __kvm_blk_server_ack_commit(s);
        break;
    }

    case KVM_BLK_CMD_FT: {
        br = g_malloc0(sizeof(struct kvm_blk_request));
        br->cmd = KVM_BLK_CMD_ISSUE;
        br->session = s;

        QTAILQ_INSERT_TAIL(&s->request_list, br, node);
        s->issue = br;
        s->ft_mode = 1;
        break;
    }

    default: {
        printf("%s, unknown command: %d\n", __func__, s->recv_hdr.cmd);
        break;
    }

    }
    return ret;
}