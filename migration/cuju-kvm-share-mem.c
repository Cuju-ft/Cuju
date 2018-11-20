/*
 * Cuju
 * (a.k.a. Fault Tolerance, Continuous Replication, or Checkpointing)
 *
 * Copyright (c) 2017 ITRI
 *
 * Authors:
 *  Yi-feng Sun         <pkusunyifeng@gmail.com>
 *  Wei-Chen Liao       <ms0472904@gmail.com>
 *  Po-Jui Tsao         <pjtsao@itri.org.tw>
 *  Yu-Shiang Lin       <YuShiangLin@itri.org.tw>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */


#include "qemu/osdep.h"
#include <sys/ioctl.h>
#include "qmp-commands.h"
#include "qemu/bitops.h"
#include "qemu/thread.h"
#include "sysemu/kvm.h"
#include "linux/kvm.h"
#include "linux/kvm_shmem.h"
#include "migration/cuju-kvm-share-mem.h"
#include <emmintrin.h>
#include <smmintrin.h>
#include <immintrin.h>
#include <malloc.h>

#define TIMEVAL_TO_DOUBLE(tv)   ((tv).tv_sec + \
								((double)(tv).tv_usec) / 1000000)
#define TIMEVAL_TO_US(tv)   ((tv).tv_sec * 1000000 + (tv).tv_usec)

static unsigned int dirty_pages_userspace_off = 0;
static unsigned int dirty_pages_userspace_off_committed = 0;
static unsigned int dirty_pages_userspace[1024];
static unsigned int dirty_pages_userspace_committed[1024];
static uint8_t dirty_pages_userspace_copy[1024][4096];

static void dirty_pages_userspace_add(unsigned long gfn)
{
    int i, cnt;

    cnt = __sync_fetch_and_add(&dirty_pages_userspace_off, 0);
    for (i = 0; i < cnt; i++)
        if (dirty_pages_userspace[i] == gfn)
            return;
    
    i = __sync_fetch_and_add(&dirty_pages_userspace_off, 1);
    dirty_pages_userspace[i] = gfn;
    assert(i < 1024);
}

static void dirty_pages_userspace_commit(void)
{
    assert(dirty_pages_userspace_off_committed == 0);
    if (dirty_pages_userspace_off != 0) {
        int i;
        memcpy(dirty_pages_userspace_committed, dirty_pages_userspace,
            sizeof(dirty_pages_userspace[0]) * dirty_pages_userspace_off);

        for (i = 0; i < dirty_pages_userspace_off; i++) {
            unsigned int gfn = dirty_pages_userspace_committed[i];
            void *hva = gfn_to_hva(gfn);
            memcpy(dirty_pages_userspace_copy[i], hva, 4096);
        }

        dirty_pages_userspace_off_committed = dirty_pages_userspace_off;
        dirty_pages_userspace_off = 0;
    }
}

static inline int transfer_flat_page(int fd, unsigned int gfn, void *page);

static int dirty_pages_userspace_transfer(int rsock)
{
    int i, r = 0;
    for (i = 0; i < dirty_pages_userspace_off_committed; i++) {
        unsigned int gfn = dirty_pages_userspace_committed[i];
        void *hva = dirty_pages_userspace_copy[i];
        int len = transfer_flat_page(rsock, gfn, hva);
        if (len < 0)
            return len;
        r += len;
    }
    dirty_pages_userspace_off_committed = 0;
    return r;
}

static void* __restrict__ compress_buf;

static inline int64_t time_in_us(void)
{
   qemu_timeval timeval;
   qemu_gettimeofday(&timeval);
   return (int64_t)TIMEVAL_TO_US(timeval);
}

static inline double time_in_double(void)
{
   struct timespec ts;
   double ret;
   clock_gettime(CLOCK_MONOTONIC, &ts);
   ret = ts.tv_sec + ((double)ts.tv_nsec) / 1e9L;
   return ret;
}


extern int ft_ram_conn_count;

static struct trans_ram_conn_descriptor {
    int index;
    QTAILQ_HEAD(, MigrationState) list;
    QemuMutex mutex;
    QemuCond cond;
    QemuThread thread;
} trans_ram_conn_descriptors[4];

struct dirty_page_tracking_logs dirty_page_tracking_logs;

static void*** page_array;
static int bitmap_count;

static int ft_started = 0;

static unsigned int epoch_time_in_us = EPOCH_TIME_IN_MS * 1000;

bool cuju_supported(void)
{
    return true;
}

void qmp_cuju_failover(Error **errp)
{
    printf("qmp_cuju_failover\n");
    //TODO
}

void qmp_cuju_adjust_epoch(uint32_t epoch, Error **errp) {
    printf("new epoch size is %u ms.\n", epoch);
    epoch_time_in_us = epoch;

    uint32_t value = epoch_time_in_us;
    kvm_vm_ioctl(kvm_state, KVM_SHM_ADJUST_EPOCH, &value);
}

void dirty_page_tracking_logs_start_transfer(MigrationState *s)
{
	int cur_off;
    int next_log_off = (dirty_page_tracking_logs.log_off + 1) %
        DIRTY_PAGE_TRACKING_LOG_SIZE;
    struct dirty_page_tracking_log *next_log =
        &dirty_page_tracking_logs.logs[next_log_off];
    qemu_timeval timeval;

    dirty_page_tracking_logs.total_page_nums -= next_log->page_nums;
    dirty_page_tracking_logs.total_transfer_time_us -=
        next_log->transfer_time_us;

    cur_off = s->cur_off;
    next_log->page_nums = kvm_vm_ioctl(kvm_state, KVM_GET_PUT_OFF, &cur_off);

    qemu_gettimeofday(&timeval);
    next_log->transfer_time_us = TIMEVAL_TO_US(timeval);
    dirty_page_tracking_logs.log_off = next_log_off;
    s->dirty_page_tracking_logs_off = next_log_off;
}

void dirty_page_tracking_logs_start_flush_output(MigrationState *s)
{
    struct dirty_page_tracking_log *log =
        &dirty_page_tracking_logs.logs[s->dirty_page_tracking_logs_off];
    qemu_timeval timeval;

    qemu_gettimeofday(&timeval);
    log->transfer_time_us = TIMEVAL_TO_US(timeval) - log->transfer_time_us;
}

unsigned int dirty_page_tracking_logs_max(int bound_ms)
{
    double total_page_nums = dirty_page_tracking_logs.total_page_nums;
    return (unsigned int)(total_page_nums * bound_ms * 1000 /
            dirty_page_tracking_logs.total_transfer_time_us);
}

static inline size_t socket_send_all(int fd, const char *buf, size_t size)
{
    size_t offset;

    offset = 0;
    while (offset < size) {
        ssize_t len;

        len = write(fd, buf + offset, size - offset);
        if (len == -1 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        }

        assert(len > 0);

        offset += len;
    }
    return size;
}


static void compress_init(void);

// called in vl.c
void kvm_share_mem_init(unsigned long ram_size)
{
    struct kvm_shmem_init shmem_init;
    int ret;
    int i, j;

    if (!kvm_enabled()) {
        fprintf(stderr, "%s called without kvm supporting.\n", __func__);
        return;
    }

    shmem_init.ram_page_num = ram_size / 4096;
    shmem_init.shared_page_num = SHARED_DIRTY_SIZE;
    shmem_init.shared_watermark = SHARED_DIRTY_WATERMARK;
    shmem_init.epoch_time_in_ms = EPOCH_TIME_IN_MS;
    shmem_init.pages_per_ms = PAGES_PER_MS;

    ret = kvm_vm_ioctl(kvm_state, KVM_SHM_INIT, &shmem_init);

#ifdef ft_debug_mode_enable
    printf("pfn0 %lu pfn1 %lu pfn0 %lu pfn1 %lu size %lu\n",
        shmem_init.page_nums_pfn_snapshot[0],
        shmem_init.page_nums_pfn_snapshot[1],
		shmem_init.page_nums_pfn_dirty[0],
        shmem_init.page_nums_pfn_dirty[1],
        shmem_init.page_nums_size);
#endif

    if (ret < 0) {
      perror("shmem init failed: ");
      exit(ret);
    }

    page_array = g_malloc0(sizeof(void **) * KVM_DIRTY_BITMAP_INIT_COUNT);
    for (i = 0; i < KVM_DIRTY_BITMAP_INIT_COUNT; i++) {
        page_array[i] = g_malloc0(sizeof(void *) * SHARED_DIRTY_SIZE);
    }

    for (i = 0; i < KVM_DIRTY_BITMAP_INIT_COUNT; ++i) {
      struct kvm_shm_alloc_pages param;
      param.index1 = i;

      for (j = 0; j < SHARED_DIRTY_SIZE; ++j) {
        param.index2 = j;
        param.order = 0;
        ret = kvm_vm_ioctl(kvm_state, KVM_SHM_ALLOC_PAGES, &param);
        if (ret < 0) {
          perror("shmem alloc page: ");
          exit(ret);
        }
        //page_array[i][j] = map_pfn(ram_fd, param.pfn, 4096);
      }
    }

    bitmap_count = KVM_DIRTY_BITMAP_INIT_COUNT;

	compress_init();

    memset(&dirty_page_tracking_logs, 0, sizeof(dirty_page_tracking_logs));
    // starts with a transferring speed of 100 pages per 5ms.
    dirty_page_tracking_logs.total_page_nums = 100 *
        DIRTY_PAGE_TRACKING_LOG_SIZE;
    dirty_page_tracking_logs.total_transfer_time_us = 5000 *
        DIRTY_PAGE_TRACKING_LOG_SIZE;
}

void kvm_shmem_start_ft(void)
{
    int ret;

    //kvm_start_log_share_dirty_pages();

    ret = kvm_vm_ioctl(kvm_state, KVM_SHM_ENABLE);
    if (ret) {
        fprintf(stderr, "%s failed: %d\n", __func__, ret);
        exit(ret);
    }

    ft_started = 1;
}

int kvmft_started(void)
{
    return ft_started;
}

void qemu_ram_savevm_state(QEMUFile *f);

// 0 0 0 0
static inline void compress_32_0(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{

}
// 1 0 0 0
static inline void compress_32_1(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[0];
}
// 0 1 0 0
static inline void compress_32_2(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[1];
}
// 1 1 0 0
static inline void compress_32_3(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[0];
  ((long *)output)[1] = curr[1];
}
// 0 0 1 0
static inline void compress_32_4(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[2];
}
// 1 0 1 0
static inline void compress_32_5(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[0];
  ((long *)output)[1] = curr[2];
}
// 0 1 1 0
static inline void compress_32_6(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[1];
  ((long *)output)[1] = curr[2];
}
// 1 1 1 0
static inline void compress_32_7(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[0];
  ((long *)output)[1] = curr[1];
  ((long *)output)[2] = curr[2];
}
// 0 0 0 1
static inline void compress_32_8(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[3];
}
// 1 0 0 1
static inline void compress_32_9(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[0];
  ((long *)output)[1] = curr[3];
}
// 0 1 0 1
static inline void compress_32_10(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[1];
  ((long *)output)[1] = curr[3];
}
// 1 1 0 1
static inline void compress_32_11(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[0];
  ((long *)output)[1] = curr[1];
  ((long *)output)[2] = curr[3];
}
// 0 0 1 1
static inline void compress_32_12(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[2];
  ((long *)output)[1] = curr[3];
}
// 1 0 1 1
static inline void compress_32_13(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[0];
  ((long *)output)[1] = curr[2];
  ((long *)output)[2] = curr[3];
}
// 0 1 1 1
static inline void compress_32_14(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[1];
  ((long *)output)[1] = curr[2];
  ((long *)output)[2] = curr[3];
}
// 1 1 1 1
static inline void compress_32_15(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  ((long *)output)[0] = curr[0];
  ((long *)output)[1] = curr[1];
  ((long *)output)[2] = curr[2];
  ((long *)output)[3] = curr[3];
}

static int compress_32_func_result_size[16];

#define COMPRESS_32_CASE(x, curr, orig, output) case (x): compress_32_##x(curr, orig, output); break;

// return header instead of length
static inline int compress_32(uint64_t *curr,
    uint64_t *orig, uint8_t *output)
{
  char header;

  header = (!!(curr[0] - orig[0])) << 0;
  header |= (!!(curr[1] - orig[1])) << 1;
  header |= (!!(curr[2] - orig[2])) << 2;
  header |= (!!(curr[3] - orig[3])) << 3;

  switch (header) {
    COMPRESS_32_CASE(0, curr, orig, output)
    COMPRESS_32_CASE(1, curr, orig, output)
    COMPRESS_32_CASE(2, curr, orig, output)
    COMPRESS_32_CASE(3, curr, orig, output)
    COMPRESS_32_CASE(4, curr, orig, output)
    COMPRESS_32_CASE(5, curr, orig, output)
    COMPRESS_32_CASE(6, curr, orig, output)
    COMPRESS_32_CASE(7, curr, orig, output)
    COMPRESS_32_CASE(8, curr, orig, output)
    COMPRESS_32_CASE(9, curr, orig, output)
    COMPRESS_32_CASE(10, curr, orig, output)
    COMPRESS_32_CASE(11, curr, orig, output)
    COMPRESS_32_CASE(12, curr, orig, output)
    COMPRESS_32_CASE(13, curr, orig, output)
    COMPRESS_32_CASE(14, curr, orig, output)
    COMPRESS_32_CASE(15, curr, orig, output)
  }
  return header;
}

int kvm_shmem_flip_sharing(int cur_index)
{
    int ret;
    MigrationState *s = migrate_by_index(cur_index);
    struct kvm_shm_flip_run run;

    run.index = cur_index;
    run.serial = s->run_serial;

    ret = kvm_vm_ioctl(kvm_state, KVM_SHM_FLIP_SHARING, &run);

    return ret;
}

void kvm_shmem_start_timer(void)
{
    kvm_vm_ioctl(kvm_state, KVM_SHM_START_TIMER);
}

static __m128i memcmp_sse2_zero;
static __m256i memcmp_avx2_zero;
static __m256d memcmp_256pd_zero;
static __m256d memcmp_256pd_allone;

// 32 bytes
static inline int memcmp_avx(uint8_t *a, uint8_t *b)
{
    unsigned long eflags;

    //asm volatile("prefetchnta %0" : : "m" (a[0]));
    asm volatile("vmovdqa %0,%%ymm0" : : "m" (a[0]));
    //asm volatile("prefetchnta %0" : : "m" (b[0]));
    asm volatile("vmovdqa %0,%%ymm1" : : "m" (b[0]));
    asm volatile("vxorpd %ymm0,%ymm1,%ymm2");
    asm volatile("vxorpd %ymm3,%ymm3,%ymm3");
    asm volatile("vptest %ymm2, %ymm3");
    asm volatile("pushf \n\t pop %0" : "=&r"(eflags) );
#define X86_EFLAGS_CF   0x00000001 /* Carry Flag */
    return !(eflags & X86_EFLAGS_CF);
}

static inline int memcmp_avx_128(uint8_t *a, uint8_t *b)
{
    unsigned long eflags;

    asm volatile("vmovdqa %0,%%ymm0" : : "m" (a[0]));
    asm volatile("vmovdqa %0,%%ymm1" : : "m" (b[0]));

    asm volatile("vxorpd %ymm0,%ymm1,%ymm2");
    asm volatile("vxorpd %ymm3,%ymm3,%ymm3");
    asm volatile("vptest %ymm2, %ymm3");
    asm volatile("pushf \n\t pop %0" : "=&r"(eflags));

    return !(eflags & X86_EFLAGS_CF);
}

// 64 bytes
static inline int memcmp_avx2(void *orig, void *curr)
{
  __m256d a = _mm256_load_pd((double const *)orig);
  __m256d b = _mm256_load_pd((double const *)curr);
  __m256d e = _mm256_cmp_pd(a, b, _CMP_EQ_OQ);
  
  if (!_mm256_testc_pd(e, memcmp_256pd_allone))
    return 1;

  a = _mm256_load_pd((double const *)(orig + 32));
  b = _mm256_load_pd((double const *)(curr + 32));
  e = _mm256_cmp_pd(a, b, _CMP_EQ_OQ);
  
  if (!_mm256_testc_pd(e, memcmp_256pd_allone))
    return 1;

  return 0;
}

static inline int memcmp_sse2_16(void *orig, void *curr)
{
  __m128i* wrd_ptr = (__m128i*)curr;
  __m128i* dst_ptr = (__m128i*)orig;
  __m128i xmm1;
  __m128i xmm2;
  __m128i c;

  xmm1 = _mm_load_si128(wrd_ptr);
  xmm2 = _mm_load_si128(dst_ptr);
  c = _mm_xor_si128(xmm1, xmm2);

  if (!_mm_testc_si128(memcmp_sse2_zero, c))
    return 1;

  return 0;
}

static inline int memcmp_sse2_32(void *orig, void *curr)
{
  __m128i* wrd_ptr = (__m128i*)curr;
  __m128i* dst_ptr = (__m128i*)orig;
  __m128i xmm1;
  __m128i xmm2;
  __m128i c;

  xmm1 = _mm_load_si128(wrd_ptr);
  xmm2 = _mm_load_si128(dst_ptr);
  c = _mm_xor_si128(xmm1, xmm2);

  if (!_mm_testc_si128(memcmp_sse2_zero, c))
    return 1;

  xmm1 = _mm_load_si128(wrd_ptr + 1);
  xmm2 = _mm_load_si128(dst_ptr + 1);
  c = _mm_xor_si128(xmm1, xmm2);

  if (!_mm_testc_si128(memcmp_sse2_zero, c))
    return 1;

  return 0;
}


static inline int memcmp_sse2_64(void *orig, void *curr)
{
  __m128i* wrd_ptr = (__m128i*)curr;
  __m128i* dst_ptr = (__m128i*)orig;
  __m128i xmm1;
  __m128i xmm2;
  __m128i c;


  xmm1 = _mm_load_si128(wrd_ptr);
  xmm2 = _mm_load_si128(dst_ptr);
  c = _mm_xor_si128(xmm1, xmm2);

  if (!_mm_testc_si128(memcmp_sse2_zero, c))
    return 1;

  xmm1 = _mm_load_si128(wrd_ptr + 1);
  xmm2 = _mm_load_si128(dst_ptr + 1);
  c = _mm_xor_si128(xmm1, xmm2);

  if (!_mm_testc_si128(memcmp_sse2_zero, c))
    return 1;

  xmm1 = _mm_load_si128(wrd_ptr + 2);
  xmm2 = _mm_load_si128(dst_ptr + 2);
  c = _mm_xor_si128(xmm1, xmm2);

  if (!_mm_testc_si128(memcmp_sse2_zero, c))
    return 1;

  xmm1 = _mm_load_si128(wrd_ptr + 3);
  xmm2 = _mm_load_si128(dst_ptr + 3);
  c = _mm_xor_si128(xmm1, xmm2);

  if (!_mm_testc_si128(memcmp_sse2_zero, c))
    return 1;

  return 0;
}

static inline int gather_16(char *orig_page, char *curr_page)
{
  return memcmp_sse2_16(orig_page, curr_page);
 
}

static inline int gather_32(char *orig_page, char *curr_page)
{
  return memcmp_sse2_32(orig_page, curr_page);

}

static inline int gather_64(char *orig_page, char *curr_page)
{
  return memcmp_sse2_64(orig_page, curr_page);

}

// return header
static inline int gather_128(char *orig_page, char *curr_page, char *output)
{
  int j, header = 0;

  for (j = 0; j < 128; j += 16) {
    int ret = gather_16(orig_page+j, curr_page+j);
    header |= ret << (j/16);
  }
  output[0] = header;
  return header;
}


// return header
static inline int gather_256(char *orig_page, char *curr_page, char *output)
{
  int j, header = 0;

  for (j = 0; j < 256; j += 32) {
    int ret = gather_32(orig_page+j, curr_page+j);
    header |= ret << (j/32);
  }
  output[0] = header;
  return header;
}


// return header
static inline int gather_512(char *orig_page, char *curr_page, char *output)
{
  int j, header = 0;

  for (j = 0; j < 512; j += 64) {
    int ret = gather_64(orig_page+j, curr_page+j);
    header |= ret << (j/64);
  }
  output[0] = header;
  return header;
}


static void compress_init(void)
{
    int i;
    char *x1;
    char *x2;

    memcmp_sse2_zero = _mm_setzero_si128();
    memcmp_avx2_zero = _mm256_setzero_si256();
    memcmp_256pd_zero = _mm256_setzero_pd();
    memcmp_256pd_allone = _mm256_cmp_pd(memcmp_256pd_zero, memcmp_256pd_zero, _CMP_EQ_OQ);

	x1 = memalign(256, 64);
	x2 = memalign(256, 64);

    for (i = 0; i < 64; ++i) {
        x1[i] = i;
        x2[i] = i;
    }
    assert(memcmp_sse2_64(x1, x2) == 0);
    x1[63] = 33;
    assert(memcmp_sse2_64(x1, x2) == 1);
    x1[63] = 63;
    assert(memcmp_sse2_64(x1, x2) == 0);

 

    for (i = 0; i < 64; ++i) {
        x1[i] = i;
        x2[i] = i;
    }
    assert(memcmp_avx2(x1, x2) == 0);
    x1[0] = 33;
    assert(memcmp_avx2(x1, x2) == 1);
    x1[0] = 0;
    assert(memcmp_avx2(x1, x2) == 0);

    for (i = 0; i < 64; ++i) {
        x1[i] = i;
        x2[i] = i;
    }
#ifdef ft_debug_mode_enable
    printf("cmp_32 %d (should 0)\n", memcmp_sse2_32(x1, x2));
    x1[0] = 33;
    printf("cmp_32 %d (should 1)\n", memcmp_sse2_32(x1, x2));
    x1[0] = 0;
    printf("cmp_32 %d (should 0)\n", memcmp_sse2_32(x1, x2));
#endif

	compress_buf = memalign(4096, 4096);



    for (i = 0; i < 16; ++i) {
      int j, bitset = 0;
      for (j = 0; j < 4; ++j) {
        if (i & (1 << j))
          ++bitset;
      }
      compress_32_func_result_size[i] = bitset;
    }
}
/***** end ******/

int kvmft_fire_timer(int moff)
{
    __u32 p = moff;
    return kvm_vm_ioctl(kvm_state, KVMFT_FIRE_TIMER, &p);
}

#define TRACKABLE_ARRAY_LEN	128
static struct trackable_ptr {
	void *ptr;
	unsigned int size;
	unsigned int registered;
} trackable_ptrs[TRACKABLE_ARRAY_LEN];

static QemuMutex trackable_ptrs_mutex;

static int trackable_number = 0;
static char trackable_bitmap[KVM_SHM_REPORT_TRACKABLE_COUNT/8];


void *kvm_shmem_alloc_trackable(unsigned int size)
{
	int i;
	struct trackable_ptr *ptr = NULL;
	static int init = 0;
	static int count = 0;

	// kvm won't compile on blk_server, so..
#ifdef CONFIG_NO_TRACK_OBJ
  return g_malloc0(size);
#endif


	if (init == 0) {
		qemu_mutex_init(&trackable_ptrs_mutex);
		init = 1;
	}

	size = (size / 4096) * 4096 + (size % 4096 ? 4096 : 0);

	qemu_mutex_lock(&trackable_ptrs_mutex);
	for (i = 0; i < TRACKABLE_ARRAY_LEN; ++i) {
		if (trackable_ptrs[i].ptr == NULL) {
			ptr = &trackable_ptrs[i];
			ptr->ptr = (void *)0xffffffff;
			break;
		}
	}
	qemu_mutex_unlock(&trackable_ptrs_mutex);

	if (!ptr) {
		printf("%s out of trackable_ptrs array.\n", __func__);
		return NULL;
	}
	
	ptr->ptr = mmap(NULL, (size_t)size, PROT_READ | PROT_WRITE,
					MAP_ANONYMOUS | MAP_SHARED | MAP_LOCKED | MAP_POPULATE,
					-1, 0);
	if (ptr->ptr == MAP_FAILED) {
		perror("trackable_ptrs alloc failed:");
		return NULL;
	}

	++count;

#ifdef ft_debug_mode_enable
	printf("%s %p total %d allocated.\n", __func__, ptr->ptr, count);
	if (size > 4096)
		printf("************%s big size %d\n", __func__, size);
#endif

	ptr->size = size;
	return ptr->ptr;
}

void kvm_shmem_free_trackable(void *ptr)
{
	int i, ret;
	struct trackable_ptr *tptr;

#ifdef CONFIG_NO_TRACK_OBJ
  g_free(ptr);
  return;
#endif

	qemu_mutex_lock(&trackable_ptrs_mutex);
	for (i = 0; i < TRACKABLE_ARRAY_LEN; ++i) {
		tptr = &trackable_ptrs[i];
		if (tptr->ptr == ptr) {
			ret = munmap(ptr, tptr->size);
			if (ret) {
				perror("trackable_ptrs munmap failed:");
				goto out;
			}
			tptr->ptr = NULL;
			tptr->size = 0;
			break;
		}
	}
out:
	qemu_mutex_unlock(&trackable_ptrs_mutex);
}



void kvm_shmem_vmstate_register_callback(void *opaque)
{
	int i;
	struct trackable_ptr *tptr;

#ifdef CONFIG_NO_TRACK_OBJ
  return;
#endif

	if (trackable_number) {
		printf("ERROR, %s after trackable_sortout.\n", __func__);
        exit(-1);
		return;
	}

	for (i = 0; i < TRACKABLE_ARRAY_LEN; ++i) {
		tptr = &trackable_ptrs[i];
		if (tptr->ptr) {
			if (tptr->ptr <= opaque && tptr->ptr + tptr->size > opaque) {
				tptr->registered = 1;
				return;
			}
		}
	}
#ifdef ft_debug_mode_enable
	printf("ERROR, %s can't find entry for vmstate %p.\n", __func__, opaque);
#endif
}

// clean up those that aren't vmstate_registered.
void kvm_shmem_sortup_trackable(void)
{
	int i, j;
	struct trackable_ptr *tptr, tmp;

	j = 0;

	for (i = 0; i < TRACKABLE_ARRAY_LEN; ++i) {
		tptr = &trackable_ptrs[i];
		if (tptr->registered) {
			memcpy(&trackable_ptrs[j], tptr, sizeof(*tptr));
			++j;
		}
	}

	trackable_number = j;
	printf("\n\n%s trackable_number = %d\n\n", __func__, trackable_number);

    for (i = 0; i < trackable_number; i++) {
        for (j = i + 1; j < trackable_number; j++) {
            if (trackable_ptrs[i].ptr > trackable_ptrs[j].ptr) {
                tmp = trackable_ptrs[i];
                trackable_ptrs[i] = trackable_ptrs[j];
                trackable_ptrs[j] = tmp;
            }
        }
    }

	if (trackable_number > 32) {
		printf("%s trackable_number exceed 32 bit, create a larger bitmap.\n",
					__func__);
		exit(-1);
	}
}

int kvm_shmem_report_trackable(void)
{
	struct kvm_shmem_report_trackable report;
	int i;

	report.trackable_count = trackable_number;
	for (i = 0; i < trackable_number; ++i) {
		report.ptrs[i] = trackable_ptrs[i].ptr;
		report.sizes[i] = trackable_ptrs[i].size;
	}
    return kvm_vm_ioctl(kvm_state, KVM_SHM_REPORT_TRACKABLE, &report);
}

int kvm_shmem_collect_trackable_dirty(void)
{
	int ret;
	ret = kvm_vm_ioctl(kvm_state, KVM_SHM_COLLECT_TRACKABLE_DIRTY,
						trackable_bitmap);
#ifdef ft_debug_mode_enable
    printf("%s dirtied count = %d/%d\n", __func__, ret, trackable_number);
#endif
	return ret;
}

// returns 1 on dirty
// 0 on clean
// -1 on not exist
int kvm_shmem_trackable_dirty_test(void *opaque)
{
	struct trackable_ptr *t;
    int l, r;

    l = 0;
    r = trackable_number;

    while (r > l) {
        int m = (l + r) / 2;
        t = &trackable_ptrs[m];
        if (t->ptr <= opaque && t->ptr + t->size > opaque) {
			return test_bit(m,  (unsigned long *)trackable_bitmap);
        } else if (t->ptr < opaque) {
            if (l == m)
                break;
            l = m;
        } else {
            r = m;
        }
    }

    return -1;
}

void kvm_shmem_trackable_dirty_reset(void)
{
    int i;
    for (i = 0; i < trackable_number; i++) {
        clear_bit(i, (unsigned long *)trackable_bitmap);
    }
}

int kvmft_write_protect_dirty_pages(int cur_index)
{
    __u32 cindex = cur_index;
    return kvm_vm_ioctl(kvm_state, KVM_FT_WRITE_PROTECT_DIRTY, &cindex);
}

int kvm_shm_clear_dirty_bitmap(int cur_index)
{
    __u32 cindex = cur_index;
    int r;
    r = kvm_vm_ioctl(kvm_state, KVM_CLEAR_DIRTY_BITMAP, &cindex);
    return r;
}

int kvm_shmem_mark_page_dirty_range(MemoryRegion *mr, hwaddr addr,hwaddr length)
{
	if (kvmft_started()) {
		uint8_t *ptr;
		hwaddr endaddr = addr + length - 1;
		hwaddr nextaddr = addr;
//		printf("%s addr = %"PRIu64" \n", __func__, addr);

		while (nextaddr <= endaddr){
			ptr = qemu_map_ram_ptr(mr->ram_block, nextaddr);
			kvm_shmem_mark_page_dirty(ptr, nextaddr >> TARGET_PAGE_BITS);
//			printf("%s %"PRIu64" gfn = %lu ptr = %"PRIu64"\n", __func__, nextaddr, nextaddr >> TARGET_PAGE_BITS, (hwaddr)ptr);
			nextaddr = nextaddr + TARGET_PAGE_SIZE;
		}
//		printf("%s end addr = %"PRIu64"\n", __func__, endaddr);
//		printf("%s lengeth = %"PRIu64"\n", __func__, length);
	}
	return 0;
}

int kvm_shmem_mark_page_dirty(void *ptr, unsigned long gfn)
{
    if (kvmft_started()) {
        struct kvm_shmem_mark_page_dirty param;
        int r;
        param.hptr = ptr;
        param.gfn = (__u32)gfn;
        r = kvm_vm_ioctl(kvm_state, KVM_SHM_MARK_PAGE_DIRTY, &param);
        assert(r == 0 || r == -ENOENT);
        if (r == -ENOENT)
            dirty_pages_userspace_add(gfn);
        return r;
    }
    return 0;
}

static int kvm_start_kernel_transfer(int trans_index, int ram_fd, int conn_index, int max_conn)
{
    struct kvm_shmem_start_kernel_transfer req;
    int ret;
    int64_t start, end, tmp = 0;
    MigrationState *s = migrate_by_index(trans_index);

    start = time_in_us();
    s->transfer_real_start_time = time_in_double();

    req.trans_index = trans_index;
    req.ram_fd = ram_fd;
    req.interrupted = 0;
    req.conn_index = conn_index;
    req.max_conn = max_conn;

    do {
        end = time_in_us();
        {
            if (end - start > EPOCH_TIME_IN_MS*1000) {
                printf("%s already takes %ldms %d\n", __func__, (end-start)/1000, s->dirty_pfns_len);
            }
        }
        ret = kvm_vm_ioctl(kvm_state, KVM_START_KERNEL_TRANSFER, &req);
        if (ret == -EINTR)
            printf("%s interrupted\n", __func__);
        req.interrupted = 1;
        tmp = time_in_us();
        {
            if (tmp - end > EPOCH_TIME_IN_MS*1000) {
                printf("%s ioctl takes %ldms %d\n", __func__, (tmp-end)/1000, s->dirty_pfns_len);
            }
        }
    } while (ret == -EINTR);

    s->transfer_real_finish_time = time_in_double();

    return ret;
}

static inline int transfer_flat_page(int fd, unsigned int gfn, void *page)
{
    struct __attribute__((__packed__)) c16x8_header {
        uint64_t gfn;
        uint32_t size;
        uint8_t h[16];
    } cheader;
    int len = 0;

    cheader.gfn = gfn << TARGET_PAGE_BITS | 0;
    cheader.size = sizeof(cheader.h) + TARGET_PAGE_SIZE;
    len += socket_send_all(fd, (const char *)&cheader, sizeof(cheader));
    len += socket_send_all(fd, page, TARGET_PAGE_SIZE);
    return len;
}

static void thread_set_realtime(void)
{
    int err;
    struct sched_param param = {
        .sched_priority = 99
    };

    err = pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
    if (err != 0) {
        printf("%s pthread_setschedparam failed\n", __func__);
        exit(-1);
    }
}

static void* trans_ram_conn_thread_func(void *opaque)
{
    struct trans_ram_conn_descriptor *d = opaque;
    MigrationState *s;
    int ret;

    thread_set_realtime();

    while (1) {
        qemu_mutex_lock(&d->mutex);
        s = QTAILQ_FIRST(&d->list);
        if (s != NULL) {
            QTAILQ_REMOVE(&d->list, s, nodes[d->index]);
            qemu_mutex_unlock(&d->mutex);
        } else {
            qemu_cond_wait(&d->cond, &d->mutex);
            qemu_mutex_unlock(&d->mutex);
            continue;
        }

        ret = dirty_pages_userspace_transfer(s->ram_fds[d->index]);
        assert(ret >= 0);
        s->ram_len += ret;

        ret = kvm_start_kernel_transfer(s->cur_off, s->ram_fds[d->index], d->index, ft_ram_conn_count);

        assert(ret >= 0);

        // TODO need lock
        s->ram_len += ret;

        if (d->index == 0) {
#ifdef CONFIG_KVMFT_USERSPACE_TRANSFER
            g_free(s->dirty_pfns);
            s->dirty_pfns = NULL;
#endif

            qemu_bh_schedule(s->bh);
        }
    }

    return NULL;
}

void trans_ram_init(void)
{
    int i;

    for (i = 0; i < ft_ram_conn_count; i++) {
        struct trans_ram_conn_descriptor *d = &trans_ram_conn_descriptors[i];
        d->index = i;
        QTAILQ_INIT(&d->list);
        qemu_mutex_init(&d->mutex);
        qemu_cond_init(&d->cond);
        qemu_thread_create(&d->thread,
                            "trans_ram_conn_thread",
                            trans_ram_conn_thread_func,
                            d,
                            QEMU_THREAD_JOINABLE);
    }

#ifdef CONFIG_KVMFT_USERSPACE_TRANSFER
    QTAILQ_INIT(&trans_ram_waiting_list);
    qemu_mutex_init(&trans_ram_mutex);
    qemu_cond_init(&trans_ram_cond);
    qemu_thread_create(&ft_diff_ram_thread,
                        kvmft_transfer_func_userspace,
                        (void *)0,
                        QEMU_THREAD_JOINABLE);
#endif
}

void trans_ram_add(MigrationState *s)
{
    struct trans_ram_conn_descriptor *d = &trans_ram_conn_descriptors[0];

    dirty_pages_userspace_commit();

#ifdef CONFIG_KVMFT_USERSPACE_TRANSFER
    qemu_mutex_lock(&trans_ram_mutex);
    QTAILQ_INSERT_TAIL(&trans_ram_waiting_list, s, node);
    qemu_mutex_unlock(&trans_ram_mutex);
    qemu_cond_signal(&trans_ram_cond);
#else

    qemu_mutex_lock(&d->mutex);
    QTAILQ_INSERT_TAIL(&d->list, s, nodes[0]);
    qemu_mutex_unlock(&d->mutex);
    qemu_cond_signal(&d->cond);
#endif
}

void kvm_shmem_send_dirty_kernel(MigrationState *s)
{
	int cur_off;
	int put_off;
	cur_off = s->cur_off;
	put_off = kvm_vm_ioctl(kvm_state, KVM_GET_PUT_OFF, &cur_off);
	//TODO kvmft_assert_ram_hash_and_dlist function should be moved to kernel space
    //kvmft_assert_ram_hash_and_dlist(dlist->pages, dlist->put_off);
    s->dirty_pfns_len = put_off;

#ifdef CONFIG_KVMFT_USERSPACE_TRANSFER
    s->dirty_pfns = g_malloc(sizeof(s->dirty_pfns[0]) * s->dirty_pfns_len);
    memcpy(s->dirty_pfns, dlist->pages, sizeof(s->dirty_pfns[0]) * s->dirty_pfns_len);
#endif

    trans_ram_add(s);
}


void kvmft_reset_put_off(MigrationState *s)
{
	int cur_off;
	cur_off = s->cur_off;
	kvm_vm_ioctl(kvm_state, KVM_RESET_PUT_OFF, &cur_off);
}

static void load_8x8_page(char *host, char *buf, char *header, int size)
{
    char h;
    int i, j;
    int off = 0;

    h = header[0];

    for (i = 0; i < 4096; i += 512) {
        if (h & (1 << (i/512))) {
            int hoff = 1 + i / 512;
            assert(header[hoff] != 0);
            for (j = 0; j < 512; j += 64) {
                if (header[hoff] & (1 << (j/64))) {
                    memcpy(host+i+j, buf+off, 64);
                    off += 64;
                }
            }
        }
    }
    assert(off == size);
}

static void load_16x8_page_hdr(char *host, char *buf, char *header, int size)
{
    short h;
    int i, j;
    int off = 0;

    ((char *)&h)[0] = header[0];
    ((char *)&h)[1] = header[1];

    for (i = 0; i < 4096; i += 256) {
        if (h & (1 << (i/256))) {
            int hoff = 2 + i / 256;
            assert(header[hoff] != 0);
            for (j = 0; j < 256; j += 32) {
                if (header[hoff] & (1 << (j/32))) {
                    memcpy(host+i+j, buf+off, 32);
                    off += 32;
                }
            }
        }
    }
    assert(off == size);
}

static void load_16x8_page(char *host, char *buf, int size)
{
    int i, j, off = 16;

    for (i = 0; i < 4096; i += 256) {
        char bits = buf[i >> 8];
        if (bits == 0)
            continue;
        for (j = 0; j < 256; j += 32) {
            if (bits & (1 << (j >> 5))) {
                memcpy(host + i + j, buf + off, 32);
                off += 32;
            }
        }
    }

    assert(off == size);
}

void* gpa_to_hva(unsigned long addr)
{
    return gfn_to_hva(addr >> TARGET_PAGE_BITS);
}

void kvm_shmem_load_ram_with_hdr(void *buf, int size, void *hdr_buf, int hdr_size)
{
    unsigned int p_gfn, p_size;
    void *p_page;
    void *p_header;
    int p_off = 0, h_off = 0;


    do {
        memcpy(&p_gfn, hdr_buf + h_off, sizeof(int));
        h_off += sizeof(int);
        if ((p_gfn & 0xfff) == 0) {
            p_page = hdr_buf + h_off;

            memcpy(gpa_to_hva(p_gfn), p_page, 4096);
            h_off += 4096;
        } else if ((p_gfn & 0xfff) == 1) {
            memcpy(&p_size, hdr_buf + h_off, sizeof(int));
            h_off += sizeof(int);
            p_header = hdr_buf + h_off;
            h_off += 18;
            p_page = buf + p_off;
            p_off += p_size;

            load_16x8_page_hdr(gpa_to_hva((p_gfn & ~1)), p_page, p_header, p_size);
        } else {
            assert((p_gfn & 0xfff) == 4);
            memcpy(&p_size, hdr_buf + h_off, sizeof(int));
            h_off += sizeof(int);
            p_header = hdr_buf + h_off;
            h_off += 9;
            p_page = buf + p_off;
            p_off += p_size;

            load_8x8_page(gpa_to_hva((p_gfn & ~4)), p_page, p_header, p_size);
        }
    } while (h_off < hdr_size);
    assert(h_off == hdr_size);
    if (p_off != size)
        printf("%d != %d\n", p_off, size);
    assert(p_off == size);
}

void kvm_shmem_load_ram(void *buf, int size)
{
    int off = 0;
    int gfn_list_off = 0;
    int i;

    struct __attribute__((__packed__)) c16x8_header {
        uint64_t gfn;
        uint32_t size;
        uint8_t h[16];
    } cheader = {0};

    static void *load_bitmap = NULL;
    static struct gfn_list {
        unsigned long gfn;
        void *page;
        int size;
    } *gfn_list = NULL;
    static int gfn_list_size = 0;

    if (!load_bitmap) {
        size_t bitmap_size;
        if (ram_size >= 0xe0000000)
            bitmap_size = (0x100000000ULL + (ram_size-0xe0000000)) /
                TARGET_PAGE_SIZE / 8;
        else
            bitmap_size = ram_size / TARGET_PAGE_SIZE / 8;
        load_bitmap = g_malloc0(bitmap_size);
        gfn_list_size = 1024;
        gfn_list = g_malloc(sizeof(struct gfn_list) * gfn_list_size);
    }

    if (size <= 0)
        return;

    do {
        void *p_page;
        struct gfn_list *rec;

        memcpy(&cheader, buf + off, sizeof(cheader));
        off += sizeof(cheader) - sizeof(cheader.h);
        p_page = buf + off;
        off += cheader.size;

        if (gfn_list_off >= gfn_list_size) {
            gfn_list_size *= 2;
            gfn_list = g_realloc(gfn_list, sizeof(struct gfn_list) * gfn_list_size);
        }

        rec = &gfn_list[gfn_list_off];
        rec->gfn = cheader.gfn;
        rec->page = p_page;
        rec->size = cheader.size;
        gfn_list_off++;
    } while (off < size);

    assert(off == size);

    for (i = gfn_list_off-1; i >= 0; i--) {
        struct gfn_list *rec = &gfn_list[i];
        unsigned long p_gfn = rec->gfn;
        void *p_page = rec->page;
        int p_size = rec->size;
        unsigned long gfn = p_gfn >> TARGET_PAGE_BITS;

        if (test_bit(gfn, load_bitmap))
            continue;
        set_bit(gfn, load_bitmap);

        if (p_gfn & 4) {
            load_8x8_page(gpa_to_hva((p_gfn & ~4)), p_page+9, p_page, p_size-9);
        } else if (p_gfn & 1) {
            load_16x8_page(gpa_to_hva((p_gfn & ~1)), p_page, p_size);
        } else {
            assert(p_size == TARGET_PAGE_SIZE + sizeof(cheader.h));
            memcpy(gpa_to_hva(p_gfn), p_page, TARGET_PAGE_SIZE);
        }
    }

    for (i = gfn_list_off-1; i >= 0; i--) {
        struct gfn_list *rec = &gfn_list[i];
        unsigned long p_gfn = rec->gfn;
        unsigned long gfn = p_gfn >> 12;

        clear_bit(gfn, load_bitmap);
    }
}

int kvmft_set_master_slave_sockets(MigrationState *s, int nsocks)
{
    struct kvmft_set_master_slave_sockets socks;
    int i;

    for (i = 0; i < ft_ram_conn_count; i++)
        socks.socks[i] = s->ram_fds[i];
    socks.trans_index = s->cur_off;
    socks.nsocks = nsocks;

    return kvm_vm_ioctl(kvm_state, KVMFT_SET_MASTER_SLAVE_SOCKETS, &socks);
}

void kvmft_update_epoch_flush_time_linear(double time_s)
{
    const int n = 10;
    // (f, flush_time)
    static double *x = NULL;
    static double *y = NULL;
    // index to put next record
    static int index = 0;
    static double last_f = 1.0f;
    double x1 = 0, x12 = 0, y1 = 0, x1y1 = 0, a1, a0, e;
    double new_f;
    double max_s = 1.0f * EPOCH_TIME_IN_MS / 1000 * 2;
    double tmp;
    int i;

    printf("f = %.2lf flush_time(ms) %.2lf\n", last_f, time_s*1000);

    if (x == NULL) {
        x = g_malloc0(sizeof(double) * n);
        y = g_malloc0(sizeof(double) * n);
    }

    // working well
    tmp = time_s - max_s;
    tmp = tmp < 0 ? tmp < 0: -tmp;
    if (tmp < 0.0005)
        return;

    if (last_f >= 0.99 && time_s < max_s)
        return;

    x[index] = last_f;
    y[index] = time_s;
    index = (index + 1) % n;

    for (i = 0; i < n; ++i) {
        x1 += x[i];
        y1 += y[i];
        x1y1 += x[i] * y[i];
        x12 += x[i] * x[i];
    }

    if (n * x12 - x1 * x1 != 0) {
        a1 = (n * x1y1 - x1 * y1) / (n * x12 - x1 * x1);
        a0 = y1 / n - a1 * x1 / n;
        e = y[0] - a0 - a1 * x[0];
        a0 += e;
        printf("\nY=%.2f+%.2fX\n",a0,a1); 
        new_f = (max_s - a0) / a1;
        if (time_s > max_s)
            new_f -= 0.01;
    } else
        new_f = last_f - 0.01;

    if (new_f < 0.1f)
        new_f = 0.1f;
    else if (new_f > 1.0f)
        new_f = 1.0f;

    printf("new f %.2f\n", new_f);

    if (last_f != new_f) {
		Error *local_err = NULL;
        qmp_cuju_adjust_epoch((unsigned int)(EPOCH_TIME_IN_MS * 1000 * new_f), &local_err);
        last_f = new_f;
    }
}

