/*
 * Cuju
 * (a.k.a. Fault Tolerance, Continuous Replication, or Checkpointing)
 *
 * Copyright (c) 2017 ITRI
 *
 * Authors:
 *  Wei-Chen Liao   <ms0472904@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#ifndef QEMU_CUJU_KVM_SHARE_MEM_H
#define QEMU_CUJU_KVM_SHARE_MEM_H

#include "qemu-common.h"
#include "migration/migration.h"
#include "hw/loader.h"
#include "qemu/main-loop.h"

#define KVM_SHARE_MEM   1
#define EPOCH_TIME_IN_MS    5
#define PAGES_PER_MS        2000
#define SHARED_DIRTY_SIZE   10000
#define SHARED_DIRTY_WATERMARK  9600

bool cuju_supported(void);

void kvmft_pre_init(void);
void kvm_share_mem_init(unsigned long ram_size);

void trans_ram_init(void);
void trans_ram_add(MigrationState *s);

void kvm_shmem_trans_ram_bh(void *opaque);

void kvm_shmem_start_ft(void);
int kvmft_started(void);
int kvmft_write_protect_dirty_pages(int cur_index);
int kvm_shm_clear_dirty_bitmap(int cur_index);
int kvmft_set_master_slave_sockets(MigrationState *s, int nsocks);

int kvm_shmem_mark_page_dirty_range(MemoryRegion *mr, hwaddr addr, hwaddr length);
int kvm_shmem_mark_page_dirty(void *ptr, unsigned long gfn);
void kvm_shmem_send_dirty_kernel(MigrationState *s);
void kvm_shmem_start_timer(void);
void kvm_shmem_cancel_timer(void);
int kvm_shmem_flip_sharing(int cur_index);

int kvmft_fire_timer(int moff);
void kvmft_reset_put_off(MigrationState *s);
void kvmft_assert_ram_hash_and_dlist(unsigned int *gfns, int size);
void kvmft_update_epoch_flush_time(double time_s);
void kvmft_update_epoch_flush_time_linear(double time_s);

void *kvm_shmem_alloc_trackable(unsigned int size);
void kvm_shmem_free_trackable(void *ptr);
void kvm_shmem_vmstate_register_callback(void *opaque);
void kvm_shmem_sortup_trackable(void);
int kvm_shmem_report_trackable(void);
int kvm_shmem_collect_trackable_dirty(void);
int kvm_shmem_trackable_dirty_test(void *opaque);
void kvm_shmem_trackable_dirty_reset(void);
void kvm_shmem_adjust_dirty_tracking(int delay);

void* gpa_to_hva(unsigned long addr);
void kvm_shmem_load_ram_with_hdr(void *buf, int size, void *hdr_buf, int hdr_size);
void kvm_shmem_load_ram(void *buf, int size);
void* kvm_shmem_map_pfn(unsigned long pfn, unsigned long size);
void kvm_shmem_unmap_pfn(void *ptr, unsigned long size);
int kvm_vm_ioctl_proxy(void *s);
#endif
