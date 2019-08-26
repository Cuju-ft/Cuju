// Cuju Add file
#ifndef _LINUX_DIFF_REQ_H
#define _LINUX_DIFF_REQ_H

typedef struct __attribute__((__packed__)) c16x8_header {
    __u64 gfn;
    __u32 size;
    __u8 h[16];
} c16x8_header_t;

struct diff_req {
    unsigned long gfn;
    int offsets_off;
    void *memslot;
    c16x8_header_t header;
    int offsets[128];
};

#define DIFF_REQ_OFFSETS_OFF_NO -1

struct diff_req_list {
    struct diff_req **reqs;
    spinlock_t lock;
    int size;
    int off;
    int diff_off;
    int trans_index;
};

int diff_req_init(void);
void diff_req_exit(void);
struct diff_req_list *diff_req_list_new(void);
void diff_req_list_free(struct diff_req_list *list);
int diff_req_list_put(struct diff_req_list *list,
                       unsigned long gfn,
                       void *memslot);
void diff_req_list_clear(struct diff_req_list *list);
#endif
