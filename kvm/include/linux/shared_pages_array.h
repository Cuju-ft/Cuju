// Cuju Add file
#ifndef _LINUX_SHARED_PAGES_ARRAY_H
#define _LINUX_SHARED_PAGES_ARRAY_H

struct shared_pages_array {
    void **kaddr;
    unsigned long *pfn;
    int plen;
    int array_size;
};

int shared_pages_array_init(struct shared_pages_array *spa,
                            int array_size,
                            int memory_size);
int shared_page_array_extend(struct shared_pages_array *spa);
void shared_pages_array_free(struct shared_pages_array *spa);

#endif  // _LINUX_SHARED_PAGES_ARRAY_H
