// Cuju Add file
#include <linux/diff_req.h>
#include <linux/slab.h>

#define DIFF_REQ_INIT_SIZE  1024

static struct kmem_cache *req_cache;

int diff_req_init(void)
{
    req_cache = kmem_cache_create("diffreqc",
                                sizeof(struct diff_req),
                                sizeof(unsigned long),
                                0, 0);
    if (!req_cache) {
        return -ENOMEM;
    }
    return 0;
}

void diff_req_exit(void)
{
    if (req_cache) {
        kmem_cache_destroy(req_cache);
        req_cache = NULL;
    }
}

struct diff_req_list *diff_req_list_new(void)
{
    int i;
    struct diff_req_list *list = kmalloc(sizeof(struct diff_req_list),
                                        GFP_KERNEL | __GFP_ZERO);
    if (!list)
        goto nomem;
    spin_lock_init(&list->lock);
    list->reqs = kmalloc(sizeof(struct diff_req *) * DIFF_REQ_INIT_SIZE,
                        GFP_KERNEL | __GFP_ZERO);
    if (!list->reqs)
        goto nomem;
    for (i = 0; i < DIFF_REQ_INIT_SIZE; i++) {
        list->reqs[i] = kmem_cache_alloc(req_cache, GFP_KERNEL);
        if (!list->reqs[i])
            goto nomem;
    }
    list->size = DIFF_REQ_INIT_SIZE;
    return list;
nomem:
    diff_req_list_free(list);
    return NULL;
}

void diff_req_list_free(struct diff_req_list *list)
{
    int i;
    if (list) {
        if (list->reqs) {
            for (i = 0; i < list->size; i++) {
                if (list->reqs[i] != NULL) {
                    kmem_cache_free(req_cache, list->reqs[i]);
                }
            }
            kfree(list->reqs);
        }
        kfree(list);
    }
}

static int diff_req_list_expand(struct diff_req_list *list)
{
    int nsize = list->size ? list->size * 2 : DIFF_REQ_INIT_SIZE;
    struct diff_req **reqs = krealloc(list->reqs,
                                    sizeof(struct diff_req *) * nsize,
                                    GFP_KERNEL | __GFP_ZERO);
    if (reqs == ZERO_SIZE_PTR) {
        return -ENOMEM;
    }
    list->reqs = reqs;
    list->size = nsize;
    return 0;
}

int diff_req_list_put(struct diff_req_list *list,
                       unsigned long gfn,
                       void *memslot)
{
    struct diff_req *req;

    spin_lock(&list->lock);
    req = list->reqs[list->off];
    req->gfn = gfn;
    req->memslot = memslot;
    req->offsets_off = DIFF_REQ_OFFSETS_OFF_NO;
    list->off++;
    spin_unlock(&list->lock);
    return 0;
}

void diff_req_list_clear(struct diff_req_list *list)
{
    list->off = 0;
}
