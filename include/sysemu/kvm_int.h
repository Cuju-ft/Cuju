/*
 * Internal definitions for a target's KVM support
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_KVM_INT_H
#define QEMU_KVM_INT_H

#include "sysemu/sysemu.h"
#include "sysemu/accel.h"
#include "sysemu/kvm.h"

typedef struct KVMSlot
{
    hwaddr start_addr;
    ram_addr_t memory_size;
    void *ram;
    int slot;
    int flags;
    //For Cuju
    int log_sync_mark;
    void *dirty_bitmap;
    void **epoch_dirty_bitmaps;
    __u64 *epoch_dirty_bitmap_pfn;
    __u64 epoch_dirty_bitmap_plen;

    void **epoch_gfn_to_put_offs;
    __u64 *epoch_gfn_to_put_off_pfn;
    __u64 epoch_gfn_to_put_off_plen;

    void **epoch_gfn_to_put_off;
    int bitmap_count;
} KVMSlot;

typedef struct KVMMemoryListener {
    MemoryListener listener;
    KVMSlot *slots;
    int as_id;
} KVMMemoryListener;

#define TYPE_KVM_ACCEL ACCEL_CLASS_NAME("kvm")

#define KVM_STATE(obj) \
    OBJECT_CHECK(KVMState, (obj), TYPE_KVM_ACCEL)

void kvm_memory_listener_register(KVMState *s, KVMMemoryListener *kml,
                                  AddressSpace *as, int as_id);

#endif
