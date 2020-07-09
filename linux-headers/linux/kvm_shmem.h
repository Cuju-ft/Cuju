#ifndef _LINUX_KVM_SHMEM_H
#define _LINUX_KVM_SHMEM_H

#include <linux/types.h>

struct kvm;

struct kvmft_dirty_list {
    volatile __u32 put_off;     // [spcl_put_off, put_off) stores dirty pages tracked by fault
    __u32 dirty_stop_num;
    __u32 spcl_put_off;         // [0, spcl_put_off) stores speculated pages dirtied in previous epoch

    __u32 spcl_pages_off;
    __u32 *spcl_pages;

    __u32 *spcl_bitmap;
    __u32 pages[];
};

struct kvm_collect_log {
    __u32 cur_index;
    __u32 is_last;
};

void kvm_shm_mark_page_dirty(struct kvm *kvm, unsigned long gfn);
/* only used to test bitmap is working in first place */
int kvm_shm_enabled(struct kvm *kvm);
int kvm_shm_disabled(struct kvm *kvm);
int kvm_shm_start_log_share_dirty_pages(struct kvm *kvm);
int kvm_shm_flip_sharing(void);

#endif

