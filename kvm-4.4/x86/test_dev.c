
#include <linux/kvm_host.h>

#include "irq.h"
#include "test_dev.h"
#include "x86.h"

#define KVM_TEST_DEV_BASE_ADDRESS   0x66
#define KVM_TEST_DEV_MEM_LENGTH     1

static int test_dev_ioport_read(struct kvm_io_device *this,
                gpa_t addr, int len, void *data)
{
    return 0;
}

static int test_dev_ioport_write(struct kvm_io_device *this,
                gpa_t addr, int len, const void *data)
{
    printk("%s\n", __func__);
    return 0;
}

static const struct kvm_io_device_ops test_dev_ops = {
    .read       = test_dev_ioport_read,
    .write      = test_dev_ioport_write,
};

extern void kvmft_prepare_upcall(struct kvm_vcpu *vcpu);

void kvm_test_dev_update(struct kvm_vcpu *vcpu)
{
    return;

    kvmft_prepare_upcall(vcpu);
    kvm_set_irq(vcpu->kvm, 2, 13, 1,false);
    kvm_set_irq(vcpu->kvm, 2, 13, 0,false);
    return;

    /*
	if (!vcpu->arch.interrupt.pending) {
        kvm_queue_interrupt(vcpu, 13, 1);
        kvm_make_request(KVM_REQ_EVENT, vcpu);
    }
    */
    /*
    int ret;
    ret = kvm_ioapic_set_irq(kvm->arch.vioapic, kvm->arch.test_dev->irq_source_id, 55, 1);
    if (ret < 0)
        printk("%s kvm_set_irq return %d\n", __func__, ret);
    ret = kvm_ioapic_set_irq(kvm->arch.vioapic, kvm->arch.test_dev->irq_source_id, 55, 0);
    if (ret < 0)
        printk("%s kvm_set_irq return %d\n", __func__, ret);
    */
}

struct kvm_test_dev *kvm_create_test_dev(struct kvm *kvm)
{
    struct kvm_test_dev *test_dev;
    int ret;

    test_dev = kzalloc(sizeof(struct kvm_test_dev), GFP_KERNEL);
    if (!test_dev)
        return NULL;

    test_dev->irq_source_id = kvm_request_irq_source_id(kvm);
    if (test_dev->irq_source_id < 0) {
        kfree(test_dev);
        return NULL;
    }
    printk("%s irq_source_id = %d\n", __func__, test_dev->irq_source_id);

    kvm->arch.test_dev = test_dev;
    test_dev->kvm = kvm;

    kvm_iodevice_init(&test_dev->dev, &test_dev_ops);
    ret = kvm_io_bus_register_dev(kvm, KVM_PIO_BUS, KVM_TEST_DEV_BASE_ADDRESS,
                        KVM_TEST_DEV_MEM_LENGTH, &test_dev->dev);
    if (ret < 0) {
        kfree(test_dev);
        return NULL;
    }
    printk("%s ok\n", __func__);
    return test_dev;
}

void kvm_free_test_dev(struct kvm *kvm)
{
    if (kvm->arch.test_dev) {
        kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS, &kvm->arch.test_dev->dev);
        kfree(kvm->arch.test_dev);
    }
}
