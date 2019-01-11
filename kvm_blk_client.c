#include "kvm_blk.h"
extern uint32_t debug_flag;
struct kvm_blk_request *pending_read_head=NULL,*pending_read_now=NULL;

int kvm_blk_client_handle_cmd(void *opaque)
{
    KvmBlkSession *s = opaque;
	struct kvm_blk_request *br;
	uint32_t cmd = s->recv_hdr.cmd;
	int32_t id = s->recv_hdr.id;
	int ret = 0;

    if (debug_flag == 1) {
    	debug_printf("received cmd %d len %d id %d\n", cmd, s->recv_hdr.payload_len,
					s->recv_hdr.id);
    }

	if (cmd == KVM_BLK_CMD_COMMIT_ACK) {
		if (s->ack_cb)
			s->ack_cb(s->ack_cb_opaque);
		return 0;
	}

	QTAILQ_FOREACH(br, &s->request_list, node)
		if (br->id == id)
			break;

	if (!br) {
		fprintf(stderr, "%s can't find record for id = %d\n",
				__func__, id);
		return -1;
	}

    qemu_mutex_lock(&s->mutex);
	QTAILQ_REMOVE(&s->request_list, br, node);
    qemu_mutex_unlock(&s->mutex);

	// handle WRITE
	if (s->recv_hdr.cmd == KVM_BLK_CMD_WRITE) {
				br->cb(br->opaque, 0);
        // for quick write
        goto out;
	}

	// handle SYNC_READ
	if (br->cb == NULL) {
		// hack for kvm_blk_rw_co
		br->cb = (void *)0xFFFFFFFF;
		goto out;
	}

	// handle READ
	if (s->recv_hdr.payload_len < 0) {
		br->cb(br->opaque, s->recv_hdr.payload_len);
		goto out;
	}
	
	if (s->recv_hdr.payload_len != br->nb_sectors) {
		fprintf(stderr, "%s expect %d, get %d\n", __func__,
				br->nb_sectors, s->recv_hdr.payload_len);
	}

	kvm_blk_input_to_iov(s, br->piov);
	br->cb(br->opaque, 0);

out:
	g_free(br);
  	return ret;
}

struct kvm_blk_request *kvm_blk_aio_readv(BlockBackend *blk,
                                        int64_t sector_num,
                                        QEMUIOVector *iov,
                                        BdrvRequestFlags flags,
                                        BlockCompletionFunc *cb,
                                        void *opaque)
{
	KvmBlkSession *s = kvm_blk_session;
	struct kvm_blk_read_control c;
	struct kvm_blk_request *br;

	assert(s->bs = blk_bs(blk));
	br = g_malloc0(sizeof(*br));
	br->sector = sector_num;
	br->nb_sectors = iov->size;
	br->cmd = KVM_BLK_CMD_READ;
	br->session = s;
	br->flags = flags;
	br->piov = iov;
	br->cb = cb;
	br->opaque = opaque;

	c.sector_num = sector_num;
	c.nb_sectors = iov->size;

    qemu_mutex_lock(&s->mutex);

	br->id = ++s->id;
	QTAILQ_INSERT_TAIL(&s->request_list, br, node);
	s->send_hdr.cmd = KVM_BLK_CMD_READ;
	s->send_hdr.payload_len = sizeof(c);
	s->send_hdr.id = s->id;
	s->send_hdr.num_reqs = 1;

	kvm_blk_output_append(s, &s->send_hdr, sizeof(s->send_hdr));
  	kvm_blk_output_append(s, &c, sizeof(c));
  	kvm_blk_output_flush(s);
    qemu_mutex_unlock(&s->mutex);

    if (debug_flag == 1) {
		debug_printf("sent read cmd: %ld %d %d\n", (long)c.sector_num, c.nb_sectors, s->id);
	}

	return br;
}
struct kvm_blk_request *kvm_blk_aio_write(BlockBackend *blk,int64_t sector_num,QEMUIOVector *iov, BdrvRequestFlags flags,BlockCompletionFunc *cb,void *opaque){
	KvmBlkSession *s = kvm_blk_session;
	struct kvm_blk_read_control c;
	struct kvm_blk_request *br;
	assert(s->bs = blk_bs(blk));
	br = g_malloc0(sizeof(*br));
	br->sector = sector_num;
	br->nb_sectors = iov->size;
	br->cmd = KVM_BLK_CMD_WRITE;
	br->session = s;
	br->flags = flags;
	br->piov = iov;
	br->cb = cb;
	br->opaque = opaque;

    qemu_mutex_lock(&s->mutex);
	br->id = ++s->id;
	write_request_id = s->id;
	QTAILQ_INSERT_TAIL(&s->request_list, br, node);

	s->send_hdr.cmd = KVM_BLK_CMD_WRITE;
	s->send_hdr.payload_len = sizeof(c)+iov->size;
	s->send_hdr.id = s->id;
	s->send_hdr.num_reqs = 1;


	kvm_blk_output_append(s, &s->send_hdr, sizeof(s->send_hdr));
	
	c.sector_num = sector_num;
	c.nb_sectors = iov->size;

	kvm_blk_output_append(s, &c, sizeof(c));
	kvm_blk_output_append_iov(s, iov);
	kvm_blk_output_flush(s);

    qemu_mutex_unlock(&s->mutex);
	//cb(opaque, 0);

	return br;
}


static void _kvm_blk_send_cmd(KvmBlkSession *s, int cmd)
{
    qemu_mutex_lock(&s->mutex);

    s->send_hdr.cmd = cmd;
	s->send_hdr.payload_len = 0;

	kvm_blk_output_append(s, &s->send_hdr, sizeof(s->send_hdr));
	kvm_blk_output_flush(s);

    qemu_mutex_unlock(&s->mutex);
}

void kvm_blk_epoch_timer(KvmBlkSession *s)
{
    _kvm_blk_send_cmd(s, KVM_BLK_CMD_EPOCH_TIMER);
}

void kvm_blk_epoch_commit(KvmBlkSession *s)
{
    _kvm_blk_send_cmd(s, KVM_BLK_CMD_COMMIT);
}

void kvm_blk_notify_ft(KvmBlkSession *s)
{
    _kvm_blk_send_cmd(s, KVM_BLK_CMD_FT);
}

struct kvm_blk_request *kvm_blk_save_pending_request(BlockBackend *blk,int64_t sector_num,QEMUIOVector *iov, BdrvRequestFlags flags,BlockCompletionFunc *cb,void *opaque,int cmd) {
    struct kvm_blk_request *br;
    
		br = g_malloc0(sizeof(*br));
    br->sector = sector_num;
    br->nb_sectors = iov->size;
    if(cmd == KVM_BLK_CMD_READ)
        br->cmd = KVM_BLK_CMD_READ;
    else if(cmd == KVM_BLK_CMD_WRITE)
        br->cmd = KVM_BLK_CMD_WRITE;
    br->cb = cb;
    br->opaque = opaque;
    br->piov = iov;
    br->flags = flags;

    if(!pending_read_head)
        pending_read_head = br;
    else
        pending_read_now->next = br;

    pending_read_now = br;
    return br;
}

void kvm_blk_do_pending_request(KvmBlkSession *s) {
    if(!pending_read_head)
        return;
    pending_read_now = pending_read_head;
    while(pending_read_now) {
        QEMUIOVector *iov;
        struct kvm_blk_read_control c;

        if(pending_read_now->cmd == KVM_BLK_CMD_WRITE) {
            struct kvm_blk_request *br;
            pending_read_now->cb(pending_read_now->opaque,0);
            br = pending_read_now;
            pending_read_now = pending_read_now->next;
            free(br);
            continue;
        }

        pending_read_now->session = s;
        pending_read_now->id = ++s->id;
        
        iov = pending_read_now->piov;
        c.sector_num = pending_read_now->sector;
        c.nb_sectors = iov->size;
           
        QTAILQ_INSERT_TAIL(&s->request_list, pending_read_now, node);
        if(pending_read_now->cmd == KVM_BLK_CMD_READ) {
            s->send_hdr.cmd = KVM_BLK_CMD_READ;
            s->send_hdr.payload_len = sizeof(c);
        }
        /*else if(pending_read_now->cmd == KVM_BLK_CMD_WRITE) {
            s->send_hdr.cmd = KVM_BLK_CMD_WRITE;
            s->send_hdr.payload_len = sizeof(c)+iov->size;
        }*/
        s->send_hdr.id = s->id;
        s->send_hdr.num_reqs = 1;

        kvm_blk_output_append(s, &s->send_hdr, sizeof(s->send_hdr));
        kvm_blk_output_append(s, &c, sizeof(c));
        /*if(pending_read_now->cmd == KVM_BLK_CMD_WRITE)
            kvm_blk_output_append_iov(s, iov);*/
        kvm_blk_output_flush(s);
        pending_read_now = pending_read_now->next;
    }
}
