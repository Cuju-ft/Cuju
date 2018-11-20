#ifndef _LINUX_KVM_FT_H
#define _LINUX_KVM_FT_H

#include <linux/kconfig.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/diff_req.h>

#define DEBUG_SWAP_PTE  1
#undef DEBUG_SWAP_PTE

//#define ENABLE_SWAP_PTE 1

// sync with the one in qemu
#define KVM_SHM_INIT_INDEX  1

#define KVM_MAX_MIGRATION_DESC  16

struct kvm;
struct kvm_shmem_init;
struct kvm_shmem_extend;
struct kvm_shm_alloc_pages;
struct kvm_dirty_log;
struct kvm_shmem_child;
struct kvm_vcpu;
struct kvm_vcpu_get_shared_all_state;
struct kvmft_set_master_slave_sockets;

struct kvmft_dirty_list {
    volatile __u32 put_off;     // [spcl_put_off, put_off) stores dirty pages tracked by fault
    __u32 dirty_stop_num;
    __u32 spcl_put_off;         // [0, spcl_put_off) stores speculated pages dirtied in previous epoch

    __u32 gva_spcl_pages_off;
    __u32 *gva_spcl_pages;

    __u32 *spcl_bitmap;         // if set, the speculated page corresponding in pages is dirty
    __u32 pages[];
};

struct kvm_collect_log {    
    __u32 cur_index;
    __u32 is_last;
};  

struct zerocopy_callback_arg {
	struct kvm *kvm;
	unsigned long gfn;
	atomic_t counter;
    struct page *page1;
    struct page *page2;
    int trans_index;
    int run_serial;
    bool check_modify;
};

struct ft_modified_during_transfer_list {
    int put_off;
    int get_off;
    int size;
    struct zerocopy_callback_arg **records;
};

struct kvmft_master_slave_conn_info {
    int nsocks;
    volatile int run_serial;
    int *trans_ret;
    struct socket **socks;
    struct task_struct **kthreads;
    wait_queue_head_t *events;
};

struct kvmft_context {
    unsigned long shared_page_num;
    unsigned long shared_watermark;
    volatile int cur_index;
    int max_desc_count;
    bool shm_enabled;
    bool log_full;

    // array of (struct kvmft_dirty_list *)
    struct kvmft_dirty_list **page_nums_snapshot_k;  
    // array of (struct page*)
    struct page **page_nums_snapshot_page;

    unsigned int page_nums_page_order;

    // array of
    //  [k1,k2,...,kn], kx points to a kernel page, size is shared_log_size
    void ***shared_pages_snapshot_k;  
    // array of
    //  [struct page*, struct page*, ...]
    struct page ***shared_pages_snapshot_pages;

    struct kvmft_master_slave_conn_info master_slave_info[KVM_MAX_MIGRATION_DESC];

    struct diff_req_list *diff_req_list[KVM_MAX_MIGRATION_DESC];
    volatile struct diff_req_list *diff_req_list_cur;

    unsigned int *spcl_backup_dirty_list;
    unsigned int spcl_backup_dirty_num;

    int pending_tran_num;
    wait_queue_head_t tran_event;
};

int kvm_shm_init(struct kvm *kvm, struct kvm_shmem_init *info);
int kvm_shm_extend(struct kvm *kvm, struct kvm_shmem_extend *extend);
struct page *kvm_shm_alloc_page(struct kvm *kvm,
                                struct kvm_shm_alloc_pages *param);
void kvm_shm_exit(struct kvm *kvm);
int kvm_shm_enable(struct kvm *kvm);
int kvm_shm_start_log_share_dirty_pages(struct kvm *kvm, struct kvm_collect_log *log);
int kvm_shm_flip_sharing(struct kvm *kvm, __u32 cur_off, __u32 run_serial);
void kvm_shm_start_timer(struct kvm_vcpu *vcpu);
//int kvm_shm_log_full(struct kvm *kvm);
int kvmft_page_dirty(struct kvm *kvm, unsigned long gfn,
                     void *orig, bool is_user,
                     unsigned long *replacer_pfn);
int kvm_shm_set_child_pid(struct kvm_shmem_child *);
int kvm_shm_sync_dev_pages(void);
void kvm_shm_timer_cancel(struct kvm_vcpu *vcpu);
int kvmft_fire_timer(struct kvm_vcpu *vcpu, int moff);

struct kvm_shmem_report_trackable;
int kvm_shm_report_trackable(struct kvm *kvm,
						struct kvm_shmem_report_trackable *t);
int kvm_shm_collect_trackable_dirty(struct kvm *kvm,
						void * __user bitmap);
int kvm_start_kernel_transfer(struct kvm *kvm,
                              int trans_index,
                              int ram_fd,
                              int intr,
                              int conn_index,
                              int max_conn);

int kvm_vm_ioctl_get_dirty_log_batch(struct kvm *kvm, __u32 cur_index);
int kvm_vm_ioctl_ft_protect_speculative_and_prepare_next_speculative(struct kvm *kvm, __u32 cur_index);
int kvm_vm_ioctl_ft_backup_speculative(struct kvm *kvm, __u32 cur_index);
int kvm_vm_ioctl_ft_write_protect_dirty(struct kvm *kvm, __u32 cur_index);
int kvm_vm_ioctl_clear_dirty_bitmap(struct kvm *kvm, __u32 cur_index);
int kvm_vm_ioctl_adjust_dirty_tracking(struct kvm* kvm, int diff);
int kvm_vm_ioctl_adjust_epoch(struct kvm* kvm, unsigned long newepoch);
unsigned long kvm_get_put_off(struct kvm *kvm, int cur_index);
int kvm_reset_put_off(struct kvm *kvm, int cur_index);

int kvmft_vcpu_alloc_shared_all_state(struct kvm_vcpu *vcpu,
        struct kvm_vcpu_get_shared_all_state *state);
void kvmft_gva_spcl_unprotect_page(struct kvm *kvm, unsigned long gfn);
int kvmft_ioctl_set_master_slave_sockets(struct kvm *kvm,
    struct kvmft_set_master_slave_sockets *socks);

#endif

