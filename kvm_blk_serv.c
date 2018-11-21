#include "kvm_blk.h"
#include "qemu/thread.h"
#include "qemu/typedefs.h"
extern uint32_t debug_flag;
extern int wreq_quota;
extern struct kvm_blk_request *wreq_head,*wreq_last;

void kvm_blk_server_wcallback(KvmBlkSession *s) {
		struct kvm_blk_request *br;

		//error handle
		if(wreq_head == NULL) {
				printf("Error:wreq null");
				return ;
		}
		//remove from wreq list
		br = wreq_head;
		if(wreq_head->next == NULL) {
				wreq_head = NULL;
				wreq_last = NULL;
		}
		else { 
				wreq_head = wreq_head->next;
				wreq_head->prev = NULL;
		}
		//callback to client
		s->send_hdr.cmd = KVM_BLK_CMD_WRITE;
		s->send_hdr.id = br->id;
		s->send_hdr.payload_len = 0;
		s->send_hdr.num_reqs = 0;
		kvm_blk_output_append(s, &s->send_hdr, sizeof(s->send_hdr));
		if (debug_flag == 1) {
				debug_printf("send write ack.\n");                      
		}
		kvm_blk_output_flush(s);
		
		//free br
		free(br);
}

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
		g_free(br->piov->iov[0].iov_base);
		qemu_iovec_destroy(br->piov);
		g_free(br->piov);
}

static int kvm_blk_fast_readv(KvmBlkSession *s, struct kvm_blk_request *br)
{
	struct kvm_blk_request *var;
	int  ret = KVM_BLK_RW_NONE;

	assert(br->cmd == KVM_BLK_CMD_READ);

    var = s->issue;
    do {
        var = QTAILQ_NEXT(var, node);
        if (var == br)
            goto out;

        if (var->cmd != KVM_BLK_CMD_WRITE)
            continue;

            int src_skip, dst_skip, len;
            if (br->sector >= var->sector && br->sector+br->nb_sectors <= var->sector+var->nb_sectors) {
                ret = KVM_BLK_RW_FAST;
                dst_skip = 0;
                src_skip = (br->sector - var->sector) ;
                len = br->nb_sectors ;
            } else if (br->sector < var->sector && br->sector+br->nb_sectors > var->sector) {
                ret = KVM_BLK_RW_PARTIAL;
                dst_skip = (var->sector - br->sector) ;
                src_skip = 0;
                len = MIN(br->sector+br->nb_sectors,var->sector+var->nb_sectors) - var->sector;
            } else if (br->sector >= var->sector && br->sector < var->sector+var->nb_sectors
                        && br->sector+br->nb_sectors > var->sector+var->nb_sectors) {
                ret = KVM_BLK_RW_PARTIAL;
                dst_skip = 0;
                src_skip = (br->sector - var->sector) ;
                len = var->sector + var->nb_sectors - br->sector;
            } else {
                continue;
            }
            assert(dst_skip >= 0 && src_skip >= 0 && len > 0);
            qemu_iovec_copy_sup(&br->iov, dst_skip, var->piov, src_skip, len);
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

    //s->send_hdr.cmd = br->cmd;
    //s->send_hdr.id = br->id;

    if (debug_flag == 1) {
    	QTAILQ_FOREACH(p, &s->request_list, node) {
    		debug_printf("%s: pending request: %p cmd %d\n", __func__, p, p->cmd);
    	}
    }

    if (ret < 0) {
				s->send_hdr.cmd = br->cmd;
				s->send_hdr.id = br->id;
        s->send_hdr.payload_len = ret;
        kvm_blk_output_append(s, &s->send_hdr, sizeof(s->send_hdr));
        kvm_blk_output_flush(s);
				goto out;
    }

    switch (br->cmd) {
        case KVM_BLK_CMD_READ: {
			if (br->ret_fast_read == KVM_BLK_RW_PARTIAL)
				kvm_blk_fast_readv(s, br);
						s->send_hdr.cmd = br->cmd;
						s->send_hdr.id = br->id;
            s->send_hdr.payload_len = br->nb_sectors;
            kvm_blk_output_append(s, &s->send_hdr, sizeof(s->send_hdr));
            kvm_blk_output_append_iov(s, &br->iov);            
            if (debug_flag == 1) {
                debug_printf("send back read %d\n", (int)br->iov.size);
            }
						kvm_blk_output_flush(s);
            break;
        }
        case KVM_BLK_CMD_WRITE: {
            if (--br->num_reqs)
                return;
						//TODO:s is br->session if fall over;
						if(wreq_quota < 0)
								kvm_blk_server_wcallback(s);
						++wreq_quota;
            //s->send_hdr.payload_len = 0;
            //s->send_hdr.num_reqs = 0;
            //kvm_blk_output_append(s, &s->send_hdr, sizeof(s->send_hdr));
            // TODO free reqs, iov bufs            
            //if (debug_flag == 1) {
            //    debug_printf("send write ack.\n");
            //}
            break;
        }
        default: {
            fprintf(stderr, "%s, unknown command %d\n", __func__, br->cmd);
            abort();
        }
    }

out:
    //kvm_blk_output_flush(s);

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
    struct BlockBackend *blk ;
	do {
		QTAILQ_FOREACH(br, &s->request_list, node) {
			if (br->ret_fast_read == KVM_BLK_RW_PARTIAL) {
				break;
			}
		}
		if (!br)
			break;
        blk = blk_new();
        blk_insert_bs(blk, br->session->bs);
        aio_poll(blk_get_aio_context(blk), true);
        blk_unref(blk);
	} while (1);
    g_free(br);
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
    br = s->issue;

    do {
		br = QTAILQ_NEXT(br, node);
        assert(br);

		if (br->cmd == KVM_BLK_CMD_EPOCH_TIMER)
			break;

		if (br->cmd == KVM_BLK_CMD_WRITE) {
            // TODO nasty hack, mark br as busy by setting its cb.
            br->cb = (BlockCompletionFunc *)1;
            blk = blk_new();
            blk_insert_bs(blk, br->session->bs);
            blk_aio_pwritev(blk, br->sector, br->piov,
            0, kvm_blk_rw_cb, br);
            blk_unref(blk);
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
	if (!s)
		return NULL;

    __kvm_blk_wait_read_done(s);

    // drop all write request behind wid;    
again:
    QTAILQ_FOREACH(br, &s->request_list, node) {
        if (br->cmd != KVM_BLK_CMD_WRITE) {
            QTAILQ_REMOVE(&s->request_list, br, node);
            g_free(br);
            goto again;
        }
        // TODO nasty hacking, pending write request.
        if (br->cb) {
            blk = blk_new();
            blk_insert_bs(blk, br->session->bs);
            aio_poll(blk_get_aio_context(blk), true);
            blk_unref(blk);
            g_free(br);
            goto again;
        }
        if (br->id > wid) {
            QTAILQ_REMOVE(&s->request_list, br, node);
            g_free(br);
            goto again;
        }
    }


    QTAILQ_FOREACH(br, &s->request_list, node) {
        // TODO nasty hack, mark br as busy by setting its cb.
        br->cb = (BlockCompletionFunc *)1;
        blk = blk_new();
        blk_insert_bs(blk, br->session->bs);
        blk_aio_pwritev(blk, br->sector, br->piov,
            br->flags, kvm_blk_rw_cb, br);
        blk_unref(blk);
    }
    while (!QTAILQ_EMPTY(&s->request_list)){
        aio_poll(qemu_get_aio_context(), true);
    }
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
    close(s->sockfd);
    s->sockfd = -1;
}



int kvm_blk_serv_handle_cmd(void *opaque)
{
    KvmBlkSession *s = opaque;
    struct kvm_blk_request *br = NULL;
    int ret = 0;
    struct BlockBackend *blk ;

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
            debug_printf("client read: %ld %d\n", (long)c.sector_num, c.nb_sectors);
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
        blk = blk_new();
        blk_insert_bs(blk, s->bs);
        blk_aio_preadv(blk, c.sector_num, &br->iov,0,
                        kvm_blk_rw_cb, br);
        blk_unref(blk);
        ret = 0;

        break;
    }
    case KVM_BLK_CMD_WRITE: {
 
        struct kvm_blk_read_control c;
        void *new_buf;
        int len;
				struct kvm_blk_request *wbr;

        ret = kvm_blk_recv(s, &c, sizeof(c));
        if (ret != sizeof(c))
            return -EINVAL;
        if (debug_flag == 1) {
            debug_printf("client write: %ld %d\n", (long)c.sector_num, c.nb_sectors);
        }

        br = g_malloc0(sizeof(struct kvm_blk_request));
        br->cmd = s->recv_hdr.cmd;
        br->id = s->recv_hdr.id;
        br->session = s;
        br->num_reqs = s->recv_hdr.num_reqs;
        br->opaque = opaque;

        br->sector = c.sector_num;
        br->nb_sectors = c.nb_sectors;
        br->piov  = g_malloc0(sizeof(QEMUIOVector));
        qemu_iovec_init(br->piov, 1);
        len = c.nb_sectors ;
        new_buf = g_malloc(len);
        ret = kvm_blk_recv(s, new_buf, len);
            if (ret != len)
                return -EINVAL;

        
        qemu_iovec_add(br->piov, new_buf, len);
        QTAILQ_INSERT_TAIL(&s->request_list, br, node);
				
				//handle write call back : init wbr
				wbr = g_malloc0(sizeof(*br));
				memcpy(wbr,br,sizeof(*br));
				wbr->next = NULL;
				wbr->prev = NULL;
				//insert wbr to wreq list for server call back
				if(wreq_head == NULL) {
						wreq_head = wbr;
						wreq_last = wbr;
				}
				else {
						wbr->prev = wreq_last;
						wreq_last->next = wbr;
						wreq_last = wbr;
				}
				//weather to call back or not
				if(wreq_quota > 0) 
						kvm_blk_server_wcallback(s);
				--wreq_quota;
						

        if (!s->ft_mode) {
            blk = blk_new();
            blk_insert_bs(blk, s->bs);
            blk_aio_pwritev(blk, c.sector_num , br->piov,0,
                        kvm_blk_rw_cb, br);
            blk_unref(blk);

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
        debug_printf("%s, unknown command: %d\n", __func__, s->recv_hdr.cmd);
        break;
    }

    }
    return ret;
}
