// Cuju Add file
#include <linux/shared_pages_array.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>    // Cuju

static int shared_pages_array_alloc_single(struct shared_pages_array *spa,
                                    int index)
{
    int order = ilog2(spa->plen);
    struct page *page;
    unsigned long *vaddr;

    BUG_ON (index >= spa->array_size);

    if (order <= 10) {
	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (!page)
		return -1;

    	spa->pfn[index] = page_to_pfn(page);
#define pfn_to_virt(pfn)  __va((pfn) << PAGE_SHIFT)
	spa->kaddr[index] = pfn_to_virt(page_to_pfn(page));
    } else {
	vaddr = vzalloc(spa->plen * 4096);
	if (!vaddr)
		return -1;

	spa->kaddr[index] = vaddr;
    }


    return 0;
}

int shared_pages_array_init(struct shared_pages_array *spa,
                            int array_size,
                            int memory_size)
{
    int page_count = memory_size / 4096 + !!(memory_size % 4096);
    int order = page_count == 0 ? 0 : ilog2(page_count);
    int i, size;

    memset(spa, 0, sizeof(*spa));

    if ((1 << order) < page_count)
        ++order;

    spa->plen = (1 << order);
    spa->array_size = array_size;

    size = sizeof(void *) * array_size;
    spa->kaddr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
    if (!spa->kaddr)
        goto nomem;

    size = sizeof(unsigned long) * array_size;
    spa->pfn = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
    if (!spa->pfn)
        goto nomem;

    for (i = 0; i < array_size; i++) {
        int ret = shared_pages_array_alloc_single(spa, i);
        if (ret < 0)
            goto nomem;
    }

    return 0;
nomem:
    shared_pages_array_free(spa);
    return -ENOMEM;
}

int shared_page_array_extend(struct shared_pages_array *spa)
{
    int size;

    if (!spa->plen)
        return -EINVAL;

    size = sizeof(void *) * (spa->array_size + 1);
    spa->kaddr = krealloc(spa->kaddr, size, GFP_KERNEL | __GFP_ZERO);
    if (!spa->kaddr)
        return -ENOMEM;

    size = sizeof(unsigned long) * (spa->array_size + 1);
    spa->pfn = krealloc(spa->pfn, size, GFP_KERNEL | __GFP_ZERO);
    if (!spa->pfn)
        return -ENOMEM;

    spa->array_size++;

    return shared_pages_array_alloc_single(spa, spa->array_size);
}

void shared_pages_array_free(struct shared_pages_array *spa)
{
    int i;
    if (spa == NULL)
        return;
    if (spa->plen) {
        if (spa->plen <= 1024) {
            for (i = 0; i < spa->array_size; i++) {
                struct page *page;
                if (!spa->pfn)
                    continue;
                if (!spa->pfn[i])
                    continue;
                page = pfn_to_page(spa->pfn[i]);
                if (!page)
                    continue;
                __free_pages(page, ilog2(spa->plen));
                spa->pfn[i] = 0;
            }
        } else {
            for (i = 0; i < spa->array_size; i++) {
                if (!spa->kaddr)
                    continue;
                if (!spa->kaddr[i])
                    continue;
                vfree(spa->kaddr[i]);
            }
        }
        spa->plen = 0;
    }
    if (spa->kaddr) {
        kfree(spa->kaddr);
        spa->kaddr = NULL;
    }
    if (spa->pfn) {
        kfree(spa->pfn);
        spa->pfn = NULL;
    }
}
