// Cuju Add file
#ifndef __TEST_DEV_H
#define __TEST_DEV_H

#include "iodev.h"

struct kvm_test_dev {
    struct kvm_io_device dev;
    struct kvm *kvm;
    int irq_source_id;
};

void kvm_test_dev_update(struct kvm_vcpu *vcpu);
struct kvm_test_dev *kvm_create_test_dev(struct kvm *kvm);
void kvm_free_test_dev(struct kvm *kvm);

#endif
