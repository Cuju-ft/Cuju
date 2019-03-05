/*
 * QEMU live migration
 *
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "migration/migration.h"
#include "migration/qemu-file.h"
#include "sysemu/sysemu.h"
#include "block/block.h"
#include "qapi/qmp/qerror.h"
#include "qapi/util.h"
#include "qemu/sockets.h"
#include "qemu/rcu.h"
#include "migration/block.h"
#include "migration/postcopy-ram.h"
#include "qemu/thread.h"
#include "qmp-commands.h"
#include "trace.h"
#include "qapi-event.h"
#include "qom/cpu.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "io/channel-buffer.h"
#include "io/channel-tls.h"
#include "migration/colo.h"
#include "migration/cuju-kvm-share-mem.h"
#include "migration/cuju-ft-trans-file.h"
#include <linux/kvm.h>
#include "migration/buffered_file.h"
#include "qemu/main-loop.h"
#include "migration/event-tap.h"
#include "hw/virtio/virtio-blk.h"
#include "migration/group_ft.h"
#include "kvm_blk.h"
//#define DEBUG_MIGRATION 1

#ifdef DEBUG_MIGRATION
#define DPRINTF(fmt, ...) \
    do { printf("migration: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#ifdef ft_debug_mode_enable
#define FTPRINTF(fmt, ...) \
    do { printf(fmt, ## __VA_ARGS__); } while (0)
#else
#define FTPRINTF(fmt, ...) \
    do { } while (0)
#endif

#define MAX_THROTTLE  (32 << 20)      /* Migration transfer speed throttling */

/* Amount of time to allocate to each "chunk" of bandwidth-throttled
 * data. */
#define BUFFER_DELAY     100
#define XFER_LIMIT_RATIO (1000 / BUFFER_DELAY)

/* Time in milliseconds we are allowed to stop the source,
 * for sending the last part */
#define DEFAULT_MIGRATE_SET_DOWNTIME 300

/* Default compression thread count */
#define DEFAULT_MIGRATE_COMPRESS_THREAD_COUNT 8
/* Default decompression thread count, usually decompression is at
 * least 4 times as fast as compression.*/
#define DEFAULT_MIGRATE_DECOMPRESS_THREAD_COUNT 2
/*0: means nocompress, 1: best speed, ... 9: best compress ratio */
#define DEFAULT_MIGRATE_COMPRESS_LEVEL 1
/* Define default autoconverge cpu throttle migration parameters */
#define DEFAULT_MIGRATE_CPU_THROTTLE_INITIAL 20
#define DEFAULT_MIGRATE_CPU_THROTTLE_INCREMENT 10

/* Migration XBZRLE default cache size */
#define DEFAULT_MIGRATE_CACHE_SIZE (64 * 1024 * 1024)

/* The delay time (in ms) between two COLO checkpoints
 * Note: Please change this default value to 10000 when we support hybrid mode.
 */
#define DEFAULT_MIGRATE_X_CHECKPOINT_DELAY 200

#ifdef ft_debug_mode_enable
    #define migrate_set_ft_state(s, state)\
    do {\
        printf("%s(%lf) %d =state=> %d\n", __func__, time_in_double(), s->cur_off, state);\
        migrate_assert_ft_state_change(s->ft_state, state);\
        s->ft_state = state;\
    } while(0)
#else
    #define migrate_set_ft_state(s, state)\
    do {\
        migrate_assert_ft_state_change(s->ft_state, state);\
        s->ft_state = state;\
    } while(0)
#endif
#ifdef ft_debug_mode_enable
#define FTPRINTF(fmt, ...) \
    do { printf(fmt, ## __VA_ARGS__); } while (0)
#else
#define FTPRINTF(fmt, ...) \
    do { } while (0)
#endif

#define GFT_SEND_CMD(file, cmd) do {\
    qemu_put_byte((file), (char)(cmd));\
    qemu_fflush(file);\
} while (0)

static void migrate_assert_ft_state_change(int f, int t)
{
    if (f == CUJU_FT_OFF)
        assert(t == CUJU_FT_INIT);
    if (f == CUJU_FT_INIT)
        assert(t == CUJU_FT_TRANSACTION_PRE_RUN);
    if (f == CUJU_FT_TRANSACTION_PRE_RUN)
        assert(t == CUJU_FT_TRANSACTION_RUN);
    if (f == CUJU_FT_TRANSACTION_RUN)
        assert(t == CUJU_FT_TRANSACTION_SNAPSHOT);
    if (f == CUJU_FT_TRANSACTION_SNAPSHOT)
        assert(t == CUJU_FT_TRANSACTION_TRANSFER);
    if (f == CUJU_FT_TRANSACTION_TRANSFER)
        assert(t == CUJU_FT_TRANSACTION_FLUSH_OUTPUT);
    if (f == CUJU_FT_TRANSACTION_FLUSH_OUTPUT)
        assert(t == CUJU_FT_TRANSACTION_PRE_RUN);
}

enum {
    MIG_STATE_ERROR,
    MIG_STATE_SETUP,
    MIG_STATE_CANCELLED,
    MIG_STATE_ACTIVE,
    MIG_STATE_COMPLETED,
};

static NotifierList migration_state_notifiers =
    NOTIFIER_LIST_INITIALIZER(migration_state_notifiers);

static bool deferred_incoming;

/*
 * Current state of incoming postcopy; note this is not part of
 * MigrationIncomingState since it's state is used during cleanup
 * at the end as MIS is being freed.
 */
static PostcopyState incoming_postcopy_state;

// for CUJU-FT
enum CUJU_FT_MODE cuju_ft_mode = CUJU_FT_OFF;


#define TIMEVAL_TO_DOUBLE(tv)   ((tv).tv_sec + \
                                ((double)(tv).tv_usec) / 1000000)
#define TIMEVAL_TO_US(tv)   ((tv).tv_sec * 1000000 + (tv).tv_usec)

static MigrationState *migrate_token_owner;

/* protect ft_mode */
static QemuMutex ft_mutex;
static QemuCond ft_cond;

static MigrationState **migration_states;
int migration_states_count = 0;
int migrate_get_index(MigrationState *s);
static void migrate_run(MigrationState *s);

// Group FT
#define GROUP_FT_MEMBER_MAX     10
static GroupFTMember group_ft_members[GROUP_FT_MEMBER_MAX];
static int group_ft_members_size;
static bool group_ft_leader_inited = false;
static GroupFTMember group_ft_members_tmp[GROUP_FT_MEMBER_MAX];
static int group_ft_members_size_tmp = 0;
/* sockets of leader and other VMs */
static int group_ft_sockets[GROUP_FT_MEMBER_MAX];
/* socket connecting leader */
static int group_ft_leader_sock = 0;
static int group_ft_master_sock = 0;
/* count of masters that finish migrating */
static int group_ft_members_ready = 0;
static struct group_ft_wait_all {
    QEMUTimer *timer;
    MigrationState *s;
} group_ft_wait_all;

extern int my_gft_id;

int qio_ft_sock_fd = 0;

// At the time setting up FT, current will pointer to 2nd MigrationState.
static int migration_states_current;

static void migrate_fd_get_notify(void *opaque);
static void gft_leader_broadcast_all_migration_done(void);

int cuju_get_fd_from_QIOChannel(QIOChannel *ioc);

MigrationState *migrate_by_index(int index)
{
    assert(index < migration_states_count);
    return migration_states[index];
}

int migrate_get_index(MigrationState *s)
{
    int i;
    for (i = 0; i < migration_states_count; i++) {
        if (s == migration_states[i])
            return i;
    }
    assert(0);
    return -1;
}

static void migrate_schedule(MigrationState *s)
{
    migration_states_current = s->cur_off;
}

/* When we add fault tolerance, we could have several
   migrations at once.  For now we don't need to add
   dynamic creation of migration */

/* For outgoing */
MigrationState *migrate_get_current(void)
{

    return migration_states[migration_states_current];
}

static MigrationState *migrate_get_next(MigrationState *s)
{
    int index = (s->cur_off + 1) % migration_states_count;
    return migration_states[index];
}

static MigrationState *migrate_get_previous(MigrationState *s)
{
    int index = (s->cur_off + migration_states_count - 1)
        % migration_states_count;
    return migration_states[index];
}

static inline double time_in_double(void)
{
   struct timespec ts;
   double ret;
   clock_gettime(CLOCK_MONOTONIC, &ts);
   ret = ts.tv_sec + ((double)ts.tv_nsec) / 1e9L;
   return ret;

   qemu_timeval timeval;
   qemu_gettimeofday(&timeval);
   return TIMEVAL_TO_DOUBLE(timeval);
}

/* For incoming */
static MigrationIncomingState *mis_current;

MigrationIncomingState *migration_incoming_get_current(void)
{
    return mis_current;
}

MigrationIncomingState *migration_incoming_state_new(QEMUFile* f)
{
    mis_current = g_new0(MigrationIncomingState, 1);
    mis_current->from_src_file = f;
    mis_current->state = MIGRATION_STATUS_NONE;
    QLIST_INIT(&mis_current->loadvm_handlers);
    qemu_mutex_init(&mis_current->rp_mutex);
    qemu_event_init(&mis_current->main_thread_load_event, false);

    return mis_current;
}

void migration_incoming_state_destroy(void)
{
    qemu_event_destroy(&mis_current->main_thread_load_event);
    loadvm_free_handlers(mis_current);
    g_free(mis_current);
    mis_current = NULL;
}


typedef struct {
    bool optional;
    uint32_t size;
    uint8_t runstate[100];
    RunState state;
    bool received;
} GlobalState;

static GlobalState global_state;

int global_state_store(void)
{
    if (!runstate_store((char *)global_state.runstate,
                        sizeof(global_state.runstate))) {
        error_report("runstate name too big: %s", global_state.runstate);
        trace_migrate_state_too_big();
        return -EINVAL;
    }
    return 0;
}

void global_state_store_running(void)
{
    const char *state = RunState_lookup[RUN_STATE_RUNNING];
    strncpy((char *)global_state.runstate,
           state, sizeof(global_state.runstate));
}

static bool global_state_received(void)
{
    return global_state.received;
}

static RunState global_state_get_runstate(void)
{
    return global_state.state;
}

void global_state_set_optional(void)
{
    global_state.optional = true;
}

static bool global_state_needed(void *opaque)
{
    GlobalState *s = opaque;
    char *runstate = (char *)s->runstate;

    /* If it is not optional, it is mandatory */

    if (s->optional == false) {
        return true;
    }

    /* If state is running or paused, it is not needed */

    if (strcmp(runstate, "running") == 0 ||
        strcmp(runstate, "paused") == 0) {
        return false;
    }

    /* for any other state it is needed */
    return true;
}

static int global_state_post_load(void *opaque, int version_id)
{
    GlobalState *s = opaque;
    Error *local_err = NULL;
    int r;
    char *runstate = (char *)s->runstate;

    s->received = true;
    trace_migrate_global_state_post_load(runstate);

    r = qapi_enum_parse(RunState_lookup, runstate, RUN_STATE__MAX,
                                -1, &local_err);

    if (r == -1) {
        if (local_err) {
            error_report_err(local_err);
        }
        return -EINVAL;
    }
    s->state = r;

    return 0;
}

static void global_state_pre_save(void *opaque)
{
    GlobalState *s = opaque;

    trace_migrate_global_state_pre_save((char *)s->runstate);
    s->size = strlen((char *)s->runstate) + 1;
}

static const VMStateDescription vmstate_globalstate = {
    .name = "globalstate",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = global_state_post_load,
    .pre_save = global_state_pre_save,
    .needed = global_state_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(size, GlobalState),
        VMSTATE_BUFFER(runstate, GlobalState),
        VMSTATE_END_OF_LIST()
    },
};

void register_global_state(void)
{
    /* We would use it independently that we receive it */
    strcpy((char *)&global_state.runstate, "");
    global_state.received = false;
    vmstate_register(NULL, 0, &vmstate_globalstate, &global_state);
}

static void migrate_generate_event(int new_state)
{
    if (migrate_use_events()) {
        qapi_event_send_migration(new_state, &error_abort);
    }
}

/*
 * Called on -incoming with a defer: uri.
 * The migration can be started later after any parameters have been
 * changed.
 */
static void deferred_incoming_migration(Error **errp)
{
    if (deferred_incoming) {
        error_setg(errp, "Incoming migration already deferred");
    }
    deferred_incoming = true;
}

/* Request a range of pages from the source VM at the given
 * start address.
 *   rbname: Name of the RAMBlock to request the page in, if NULL it's the same
 *           as the last request (a name must have been given previously)
 *   Start: Address offset within the RB
 *   Len: Length in bytes required - must be a multiple of pagesize
 */
void migrate_send_rp_req_pages(MigrationIncomingState *mis, const char *rbname,
                               ram_addr_t start, size_t len)
{
    uint8_t bufc[12 + 1 + 255]; /* start (8), len (4), rbname up to 256 */
    size_t msglen = 12; /* start + len */

    *(uint64_t *)bufc = cpu_to_be64((uint64_t)start);
    *(uint32_t *)(bufc + 8) = cpu_to_be32((uint32_t)len);

    if (rbname) {
        int rbname_len = strlen(rbname);
        assert(rbname_len < 256);

        bufc[msglen++] = rbname_len;
        memcpy(bufc + msglen, rbname, rbname_len);
        msglen += rbname_len;
        migrate_send_rp_message(mis, MIG_RP_MSG_REQ_PAGES_ID, msglen, bufc);
    } else {
        migrate_send_rp_message(mis, MIG_RP_MSG_REQ_PAGES, msglen, bufc);
    }
}

void qemu_start_incoming_migration(const char *uri, Error **errp)
{
    const char *p = uri;

    if ((p = strstr(p, "ft_mode"))) {
        if (!strcmp(p, "ft_mode"))
            cuju_ft_mode = CUJU_FT_INIT;
    }

    qapi_event_send_migration(MIGRATION_STATUS_SETUP, &error_abort);
    if (!strcmp(uri, "defer")) {
        deferred_incoming_migration(errp);
    } else if (strstart(uri, "tcp:", &p)) {
        if (cuju_ft_mode == CUJU_FT_INIT) {
            cuju_tcp_start_incoming_migration(p, errp);
        } else {
            tcp_start_incoming_migration(p, errp);
        }
#ifdef CONFIG_RDMA
    } else if (strstart(uri, "rdma:", &p)) {
        rdma_start_incoming_migration(p, errp);
#endif
    } else if (strstart(uri, "exec:", &p)) {
        exec_start_incoming_migration(p, errp);
    } else if (strstart(uri, "unix:", &p)) {
        unix_start_incoming_migration(p, errp);
    } else if (strstart(uri, "fd:", &p)) {
        fd_start_incoming_migration(p, errp);
    } else {
        error_setg(errp, "unknown migration protocol: %s", uri);
    }
}

static void process_incoming_migration_bh(void *opaque)
{
    Error *local_err = NULL;
    MigrationIncomingState *mis = opaque;

    /* Make sure all file formats flush their mutable metadata */
    bdrv_invalidate_cache_all(&local_err);
    if (local_err) {
        migrate_set_state(&mis->state, MIGRATION_STATUS_ACTIVE,
                          MIGRATION_STATUS_FAILED);
        error_report_err(local_err);
        migrate_decompress_threads_join();
        exit(EXIT_FAILURE);
    }

    /*
     * This must happen after all error conditions are dealt with and
     * we're sure the VM is going to be running on this host.
     */
    qemu_announce_self();

    /* If global state section was not received or we are in running
       state, we need to obey autostart. Any other state is set with
       runstate_set. */

    if (!global_state_received() ||
        global_state_get_runstate() == RUN_STATE_RUNNING) {
        if (autostart) {
            vm_start();
        } else {
            runstate_set(RUN_STATE_PAUSED);
        }
    } else {
        runstate_set(global_state_get_runstate());
    }
    migrate_decompress_threads_join();
    /*
     * This must happen after any state changes since as soon as an external
     * observer sees this event they might start to prod at the VM assuming
     * it's ready to use.
     */
    migrate_set_state(&mis->state, MIGRATION_STATUS_ACTIVE,
                      MIGRATION_STATUS_COMPLETED);
    qemu_bh_delete(mis->bh);
    migration_incoming_state_destroy();
}

static void process_incoming_migration_co(void *opaque)
{
    MigrationIncomingState *mis;
    QEMUFile *f;
    if (cuju_ft_mode == CUJU_FT_INIT) {
        QEMUFile **tmp = opaque;
        f = tmp[0];
        mis = migration_incoming_state_new(f);
        mis->cuju_file = g_malloc(4 * sizeof(QEMUFile*));
        mis->cuju_file[0] = tmp[0];
        mis->cuju_file[1] = tmp[1];
        mis->cuju_file[2] = tmp[2];
        mis->cuju_file[3] = tmp[3];
    }
    else {
        f = opaque;
        mis = migration_incoming_state_new(f);
    }
    PostcopyState ps;
    int ret;

    postcopy_state_set(POSTCOPY_INCOMING_NONE);
    migrate_set_state(&mis->state, MIGRATION_STATUS_NONE,
                      MIGRATION_STATUS_ACTIVE);
    ret = qemu_loadvm_state(f, 0);

    ps = postcopy_state_get();
    trace_process_incoming_migration_co_end(ret, ps);
    if (ps != POSTCOPY_INCOMING_NONE) {
        if (ps == POSTCOPY_INCOMING_ADVISE) {
            /*
             * Where a migration had postcopy enabled (and thus went to advise)
             * but managed to complete within the precopy period, we can use
             * the normal exit.
             */
            postcopy_ram_incoming_cleanup(mis);
        } else if (ret >= 0) {
            /*
             * Postcopy was started, cleanup should happen at the end of the
             * postcopy thread.
             */
            trace_process_incoming_migration_co_postcopy_end_main();
            return;
        }
        /* Else if something went wrong then just fall out of the normal exit */
    }

    /* we get COLO info, and know if we are in COLO mode */
    if (!ret && migration_incoming_enable_colo()) {
        mis->migration_incoming_co = qemu_coroutine_self();
        qemu_thread_create(&mis->colo_incoming_thread, "COLO incoming",
             colo_process_incoming_thread, mis, QEMU_THREAD_JOINABLE);
        mis->have_colo_incoming_thread = true;
        qemu_coroutine_yield();

        /* Wait checkpoint incoming thread exit before free resource */
        qemu_thread_join(&mis->colo_incoming_thread);
    }

    if (!ret && cuju_ft_mode == CUJU_FT_INIT) {
        mis->cuju_incoming_co = qemu_coroutine_self();
        printf("enter cuju FT mode (incoming)\n");
        qemu_thread_create(&mis->cuju_incoming_thread, "CUJU incoming thread",
             cuju_process_incoming_thread, mis, QEMU_THREAD_JOINABLE);

        qemu_coroutine_yield();
		qemu_thread_join(&mis->cuju_incoming_thread);
    }

    qemu_fclose(f);
    free_xbzrle_decoded_buf();

    if (ret < 0) {
        migrate_set_state(&mis->state, MIGRATION_STATUS_ACTIVE,
                          MIGRATION_STATUS_FAILED);
        error_report("load of migration failed: %s", strerror(-ret));
        migrate_decompress_threads_join();
        exit(EXIT_FAILURE);
    }

    mis->bh = qemu_bh_new(process_incoming_migration_bh, mis);
    qemu_bh_schedule(mis->bh);
}

void migration_fd_process_incoming(QEMUFile *f)
{
    Coroutine *co = qemu_coroutine_create(process_incoming_migration_co, f);

    migrate_decompress_threads_create();
    qemu_file_set_blocking(f, false);
    qemu_coroutine_enter(co);
}

void cuju_migration_fd_process_incoming(QEMUFile **f)
{

    Coroutine *co = qemu_coroutine_create(process_incoming_migration_co, f);

    migrate_decompress_threads_create();
    for (int i=0; i<4; i++) {
        qemu_file_set_blocking(f[i], false);
    }
    qemu_coroutine_enter(co);
}


void migration_channel_process_incoming(MigrationState *s,
                                        QIOChannel *ioc)
{
    trace_migration_set_incoming_channel(
        ioc, object_get_typename(OBJECT(ioc)));

    if (s->parameters.tls_creds &&
        !object_dynamic_cast(OBJECT(ioc),
                             TYPE_QIO_CHANNEL_TLS)) {
        Error *local_err = NULL;
        migration_tls_channel_process_incoming(s, ioc, &local_err);
        if (local_err) {
            error_report_err(local_err);
        }
    } else {
        QEMUFile *f = qemu_fopen_channel_input(ioc);
        migration_fd_process_incoming(f);
    }
}

void cuju_migration_channel_process_incoming(MigrationState *s,
                                        QIOChannelSocket **ioc)
{
    for (int i=0; i<4; i++) {
        trace_migration_set_incoming_channel(
            QIO_CHANNEL(ioc[i]), object_get_typename(OBJECT(QIO_CHANNEL(ioc[i]))));
    }

    // CUJU doesn't support TLS now
    if (s->parameters.tls_creds &&
        !object_dynamic_cast(OBJECT(ioc),
                             TYPE_QIO_CHANNEL_TLS)) {
        Error *local_err = NULL;
        migration_tls_channel_process_incoming(s, QIO_CHANNEL(ioc[0]), &local_err);
        if (local_err) {
            error_report_err(local_err);
        }
    } else {
        QEMUFile *f[4];
        for (int i=0; i<4; i++) {
            f[i] = qemu_fopen_channel_input(QIO_CHANNEL(ioc[i]));
        }
        cuju_migration_fd_process_incoming(f);
    }
}

void migration_channel_connect(MigrationState *s,
                               QIOChannel *ioc,
                               const char *hostname)
{
    trace_migration_set_outgoing_channel(
        ioc, object_get_typename(OBJECT(ioc)), hostname);

    if (s->parameters.tls_creds &&
        !object_dynamic_cast(OBJECT(ioc),
                             TYPE_QIO_CHANNEL_TLS)) {
        Error *local_err = NULL;
        migration_tls_channel_connect(s, ioc, hostname, &local_err);
        if (local_err) {
            migrate_fd_error(s, local_err);
            error_free(local_err);
        }
    } else {
        QEMUFile *f = qemu_fopen_channel_output(ioc);

        s->to_dst_file = f;

        migrate_fd_connect(s);
    }
}

extern int ft_ram_conn_count;

void cuju_migration_channel_connect(MigrationState *s,
                               QIOChannelSocket **ioc,
                               const char *hostname)
{
    MigrationState *s2 = migrate_by_index(1);
    for (int i=0; i<4; i++) {
        trace_migration_set_outgoing_channel(
            ioc[i], object_get_typename(OBJECT(ioc[i])), hostname);
    }
    // CUJU doesn't support TLS now
    if (s->parameters.tls_creds &&
        !object_dynamic_cast(OBJECT(ioc),
                             TYPE_QIO_CHANNEL_TLS)) {
        Error *local_err = NULL;
        migration_tls_channel_connect(s, QIO_CHANNEL(ioc[0]), hostname, &local_err);
        if (local_err) {
            migrate_fd_error(s, local_err);
            error_free(local_err);
        }
    } else {
        QEMUFile *f[4];
        for (int i=0; i<4; i++) {
            f[i] = qemu_fopen_channel_output(QIO_CHANNEL(ioc[i]));
        }
        QIOChannelSocket *sioc;
        sioc = QIO_CHANNEL_SOCKET(f[0]->opaque);
        s->fd = sioc->fd;
        sioc = QIO_CHANNEL_SOCKET(f[1]->opaque);
        s2->fd = sioc->fd;
        sioc = QIO_CHANNEL_SOCKET(f[2]->opaque);
        s->ram_fds = g_malloc0(sizeof(int) * ft_ram_conn_count);
        s->ram_fds[0] = sioc->fd;
        sioc = QIO_CHANNEL_SOCKET(f[3]->opaque);
        s2->ram_fds = g_malloc0(sizeof(int) * ft_ram_conn_count);
        s2->ram_fds[0] = sioc->fd;


        s->to_dst_file = f[0];

        s->fs = f;
        migrate_fd_connect(s);
    }
}

/*
 * Send a message on the return channel back to the source
 * of the migration.
 */
void migrate_send_rp_message(MigrationIncomingState *mis,
                             enum mig_rp_message_type message_type,
                             uint16_t len, void *data)
{
    trace_migrate_send_rp_message((int)message_type, len);
    qemu_mutex_lock(&mis->rp_mutex);
    qemu_put_be16(mis->to_src_file, (unsigned int)message_type);
    qemu_put_be16(mis->to_src_file, len);
    qemu_put_buffer(mis->to_src_file, data, len);
    qemu_fflush(mis->to_src_file);
    qemu_mutex_unlock(&mis->rp_mutex);
}

/*
 * Send a 'SHUT' message on the return channel with the given value
 * to indicate that we've finished with the RP.  Non-0 value indicates
 * error.
 */
void migrate_send_rp_shut(MigrationIncomingState *mis,
                          uint32_t value)
{
    uint32_t buf;

    buf = cpu_to_be32(value);
    migrate_send_rp_message(mis, MIG_RP_MSG_SHUT, sizeof(buf), &buf);
}

/*
 * Send a 'PONG' message on the return channel with the given value
 * (normally in response to a 'PING')
 */
void migrate_send_rp_pong(MigrationIncomingState *mis,
                          uint32_t value)
{
    uint32_t buf;

    buf = cpu_to_be32(value);
    migrate_send_rp_message(mis, MIG_RP_MSG_PONG, sizeof(buf), &buf);
}

MigrationCapabilityStatusList *qmp_query_migrate_capabilities(Error **errp)
{
    MigrationCapabilityStatusList *head = NULL;
    MigrationCapabilityStatusList *caps;
    MigrationState *s = migrate_get_current();
    int i;

    caps = NULL; /* silence compiler warning */
    for (i = 0; i < MIGRATION_CAPABILITY__MAX; i++) {
        if (i == MIGRATION_CAPABILITY_X_COLO && !colo_supported()) {
            continue;
        }
        if (i == MIGRATION_CAPABILITY_CUJU_FT && !cuju_supported()) {
            continue;
        }
        if (head == NULL) {
            head = g_malloc0(sizeof(*caps));
            caps = head;
        } else {
            caps->next = g_malloc0(sizeof(*caps));
            caps = caps->next;
        }
        caps->value =
            g_malloc(sizeof(*caps->value));
        caps->value->capability = i;
        caps->value->state = s->enabled_capabilities[i];
    }

    return head;
}

MigrationParameters *qmp_query_migrate_parameters(Error **errp)
{
    MigrationParameters *params;
    MigrationState *s = migrate_get_current();

    params = g_malloc0(sizeof(*params));
    params->has_compress_level = true;
    params->compress_level = s->parameters.compress_level;
    params->has_compress_threads = true;
    params->compress_threads = s->parameters.compress_threads;
    params->has_decompress_threads = true;
    params->decompress_threads = s->parameters.decompress_threads;
    params->has_cpu_throttle_initial = true;
    params->cpu_throttle_initial = s->parameters.cpu_throttle_initial;
    params->has_cpu_throttle_increment = true;
    params->cpu_throttle_increment = s->parameters.cpu_throttle_increment;
    params->has_tls_creds = !!s->parameters.tls_creds;
    params->tls_creds = g_strdup(s->parameters.tls_creds);
    params->has_tls_hostname = !!s->parameters.tls_hostname;
    params->tls_hostname = g_strdup(s->parameters.tls_hostname);
    params->has_max_bandwidth = true;
    params->max_bandwidth = s->parameters.max_bandwidth;
    params->has_downtime_limit = true;
    params->downtime_limit = s->parameters.downtime_limit;
    params->has_x_checkpoint_delay = true;
    params->x_checkpoint_delay = s->parameters.x_checkpoint_delay;

    return params;
}

/*
 * Return true if we're already in the middle of a migration
 * (i.e. any of the active or setup states)
 */
static bool migration_is_setup_or_active(int state)
{
    switch (state) {
    case MIGRATION_STATUS_ACTIVE:
    case MIGRATION_STATUS_POSTCOPY_ACTIVE:
    case MIGRATION_STATUS_SETUP:
        return true;

    default:
        return false;

    }
}

static void get_xbzrle_cache_stats(MigrationInfo *info)
{
    if (migrate_use_xbzrle()) {
        info->has_xbzrle_cache = true;
        info->xbzrle_cache = g_malloc0(sizeof(*info->xbzrle_cache));
        info->xbzrle_cache->cache_size = migrate_xbzrle_cache_size();
        info->xbzrle_cache->bytes = xbzrle_mig_bytes_transferred();
        info->xbzrle_cache->pages = xbzrle_mig_pages_transferred();
        info->xbzrle_cache->cache_miss = xbzrle_mig_pages_cache_miss();
        info->xbzrle_cache->cache_miss_rate = xbzrle_mig_cache_miss_rate();
        info->xbzrle_cache->overflow = xbzrle_mig_pages_overflow();
    }
}

static void populate_ram_info(MigrationInfo *info, MigrationState *s)
{
    info->has_ram = true;
    info->ram = g_malloc0(sizeof(*info->ram));
    info->ram->transferred = ram_bytes_transferred();
    info->ram->total = ram_bytes_total();
    info->ram->duplicate = dup_mig_pages_transferred();
    info->ram->skipped = skipped_mig_pages_transferred();
    info->ram->normal = norm_mig_pages_transferred();
    info->ram->normal_bytes = norm_mig_bytes_transferred();
    info->ram->mbps = s->mbps;
    info->ram->dirty_sync_count = s->dirty_sync_count;
    info->ram->postcopy_requests = s->postcopy_requests;

    if (s->state != MIGRATION_STATUS_COMPLETED) {
        info->ram->remaining = ram_bytes_remaining();
        info->ram->dirty_pages_rate = s->dirty_pages_rate;
    }
}

MigrationInfo *qmp_query_migrate(Error **errp)
{
    MigrationInfo *info = g_malloc0(sizeof(*info));
    MigrationState *s = migrate_get_current();

    switch (s->state) {
    case MIGRATION_STATUS_NONE:
        /* no migration has happened ever */
        break;
    case MIGRATION_STATUS_SETUP:
        info->has_status = true;
        info->has_total_time = false;
        break;
    case MIGRATION_STATUS_ACTIVE:
    case MIGRATION_STATUS_CANCELLING:
        info->has_status = true;
        info->has_total_time = true;
        info->total_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME)
            - s->total_time;
        info->has_expected_downtime = true;
        info->expected_downtime = s->expected_downtime;
        info->has_setup_time = true;
        info->setup_time = s->setup_time;

        populate_ram_info(info, s);

        if (blk_mig_active()) {
            info->has_disk = true;
            info->disk = g_malloc0(sizeof(*info->disk));
            info->disk->transferred = blk_mig_bytes_transferred();
            info->disk->remaining = blk_mig_bytes_remaining();
            info->disk->total = blk_mig_bytes_total();
        }

        if (cpu_throttle_active()) {
            info->has_cpu_throttle_percentage = true;
            info->cpu_throttle_percentage = cpu_throttle_get_percentage();
        }

        get_xbzrle_cache_stats(info);
        break;
    case MIGRATION_STATUS_POSTCOPY_ACTIVE:
        /* Mostly the same as active; TODO add some postcopy stats */
        info->has_status = true;
        info->has_total_time = true;
        info->total_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME)
            - s->total_time;
        info->has_expected_downtime = true;
        info->expected_downtime = s->expected_downtime;
        info->has_setup_time = true;
        info->setup_time = s->setup_time;

        populate_ram_info(info, s);

        if (blk_mig_active()) {
            info->has_disk = true;
            info->disk = g_malloc0(sizeof(*info->disk));
            info->disk->transferred = blk_mig_bytes_transferred();
            info->disk->remaining = blk_mig_bytes_remaining();
            info->disk->total = blk_mig_bytes_total();
        }

        get_xbzrle_cache_stats(info);
        break;
    case MIGRATION_STATUS_COLO:
        info->has_status = true;
        /* TODO: display COLO specific information (checkpoint info etc.) */
        break;
    case MIGRATION_STATUS_COMPLETED:
        get_xbzrle_cache_stats(info);

        info->has_status = true;
        info->has_total_time = true;
        info->total_time = s->total_time;
        info->has_downtime = true;
        info->downtime = s->downtime;
        info->has_setup_time = true;
        info->setup_time = s->setup_time;

        populate_ram_info(info, s);
        break;
    case MIGRATION_STATUS_FAILED:
        info->has_status = true;
        if (s->error) {
            info->has_error_desc = true;
            info->error_desc = g_strdup(error_get_pretty(s->error));
        }
        break;
    case MIGRATION_STATUS_CANCELLED:
        info->has_status = true;
        break;
    }
    info->status = s->state;

    return info;
}

void qmp_migrate_set_capabilities(MigrationCapabilityStatusList *params,
                                  Error **errp)
{
    MigrationState *s = migrate_get_current();
    MigrationCapabilityStatusList *cap;
    bool old_postcopy_cap = migrate_postcopy_ram();

    if (migration_is_setup_or_active(s->state)) {
        error_setg(errp, QERR_MIGRATION_ACTIVE);
        return;
    }

    for (cap = params; cap; cap = cap->next) {
        if (cap->value->capability == MIGRATION_CAPABILITY_X_COLO) {
            if (!colo_supported()) {
                error_setg(errp, "COLO is not currently supported, please"
                             " configure with --enable-colo option in order to"
                             " support COLO feature");
                continue;
            }
        }
        if (cap->value->capability == MIGRATION_CAPABILITY_CUJU_FT) {
            if (!cuju_supported()) {
                error_setg(errp, "CUJU is not currently supported, please"
                             " configure with --enable-cuju option in order to"
                             " support CUJU feature");
                continue;
            }
        }
        s->enabled_capabilities[cap->value->capability] = cap->value->state;
    }

    if (migrate_postcopy_ram()) {
        if (migrate_use_compression()) {
            /* The decompression threads asynchronously write into RAM
             * rather than use the atomic copies needed to avoid
             * userfaulting.  It should be possible to fix the decompression
             * threads for compatibility in future.
             */
            error_report("Postcopy is not currently compatible with "
                         "compression");
            s->enabled_capabilities[MIGRATION_CAPABILITY_POSTCOPY_RAM] =
                false;
        }
        /* This check is reasonably expensive, so only when it's being
         * set the first time, also it's only the destination that needs
         * special support.
         */
        if (!old_postcopy_cap && runstate_check(RUN_STATE_INMIGRATE) &&
            !postcopy_ram_supported_by_host()) {
            /* postcopy_ram_supported_by_host will have emitted a more
             * detailed message
             */
            error_report("Postcopy is not supported");
            s->enabled_capabilities[MIGRATION_CAPABILITY_POSTCOPY_RAM] =
                false;
        }
    }
}

void qmp_migrate_set_parameters(MigrationParameters *params, Error **errp)
{
    MigrationState *s = migrate_get_current();

    if (params->has_compress_level &&
        (params->compress_level < 0 || params->compress_level > 9)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "compress_level",
                   "is invalid, it should be in the range of 0 to 9");
        return;
    }
    if (params->has_compress_threads &&
        (params->compress_threads < 1 || params->compress_threads > 255)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "compress_threads",
                   "is invalid, it should be in the range of 1 to 255");
        return;
    }
    if (params->has_decompress_threads &&
        (params->decompress_threads < 1 || params->decompress_threads > 255)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "decompress_threads",
                   "is invalid, it should be in the range of 1 to 255");
        return;
    }
    if (params->has_cpu_throttle_initial &&
        (params->cpu_throttle_initial < 1 ||
         params->cpu_throttle_initial > 99)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "cpu_throttle_initial",
                   "an integer in the range of 1 to 99");
        return;
    }
    if (params->has_cpu_throttle_increment &&
        (params->cpu_throttle_increment < 1 ||
         params->cpu_throttle_increment > 99)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "cpu_throttle_increment",
                   "an integer in the range of 1 to 99");
        return;
    }
    if (params->has_max_bandwidth &&
        (params->max_bandwidth < 0 || params->max_bandwidth > SIZE_MAX)) {
        error_setg(errp, "Parameter 'max_bandwidth' expects an integer in the"
                         " range of 0 to %zu bytes/second", SIZE_MAX);
        return;
    }
    if (params->has_downtime_limit &&
        (params->downtime_limit < 0 || params->downtime_limit > 2000000)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                   "downtime_limit",
                   "an integer in the range of 0 to 2000000 milliseconds");
        return;
    }
    if (params->has_x_checkpoint_delay && (params->x_checkpoint_delay < 0)) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE,
                    "x_checkpoint_delay",
                    "is invalid, it should be positive");
    }

    if (params->has_compress_level) {
        s->parameters.compress_level = params->compress_level;
    }
    if (params->has_compress_threads) {
        s->parameters.compress_threads = params->compress_threads;
    }
    if (params->has_decompress_threads) {
        s->parameters.decompress_threads = params->decompress_threads;
    }
    if (params->has_cpu_throttle_initial) {
        s->parameters.cpu_throttle_initial = params->cpu_throttle_initial;
    }
    if (params->has_cpu_throttle_increment) {
        s->parameters.cpu_throttle_increment = params->cpu_throttle_increment;
    }
    if (params->has_tls_creds) {
        g_free(s->parameters.tls_creds);
        s->parameters.tls_creds = g_strdup(params->tls_creds);
    }
    if (params->has_tls_hostname) {
        g_free(s->parameters.tls_hostname);
        s->parameters.tls_hostname = g_strdup(params->tls_hostname);
    }
    if (params->has_max_bandwidth) {
        s->parameters.max_bandwidth = params->max_bandwidth;
        if (s->to_dst_file) {
            qemu_file_set_rate_limit(s->to_dst_file,
                                s->parameters.max_bandwidth / XFER_LIMIT_RATIO);
        }
    }
    if (params->has_downtime_limit) {
        s->parameters.downtime_limit = params->downtime_limit;
    }

    if (params->has_x_checkpoint_delay) {
        s->parameters.x_checkpoint_delay = params->x_checkpoint_delay;
    }
}


void qmp_migrate_start_postcopy(Error **errp)
{
    MigrationState *s = migrate_get_current();

    if (!migrate_postcopy_ram()) {
        error_setg(errp, "Enable postcopy with migrate_set_capability before"
                         " the start of migration");
        return;
    }

    if (s->state == MIGRATION_STATUS_NONE) {
        error_setg(errp, "Postcopy must be started after migration has been"
                         " started");
        return;
    }
    /*
     * we don't error if migration has finished since that would be racy
     * with issuing this command.
     */
    atomic_set(&s->start_postcopy, true);
}

/* shared migration helpers */

void migrate_set_state(int *state, int old_state, int new_state)
{
    if (atomic_cmpxchg(state, old_state, new_state) == old_state) {
        trace_migrate_set_state(new_state);
        migrate_generate_event(new_state);
    }
}

static void migrate_fd_cleanup(void *opaque)
{
    MigrationState *s = opaque;

    qemu_bh_delete(s->cleanup_bh);
    s->cleanup_bh = NULL;

    flush_page_queue(s);

    if (s->to_dst_file) {
        trace_migrate_fd_cleanup();
        qemu_mutex_unlock_iothread();
        if (s->migration_thread_running) {
            qemu_thread_join(&s->thread);
            s->migration_thread_running = false;
        }
        qemu_mutex_lock_iothread();

        migrate_compress_threads_join();
        qemu_fclose(s->to_dst_file);
        s->to_dst_file = NULL;
    }

    assert((s->state != MIGRATION_STATUS_ACTIVE) &&
           (s->state != MIGRATION_STATUS_POSTCOPY_ACTIVE));

    if (s->state == MIGRATION_STATUS_CANCELLING) {
        migrate_set_state(&s->state, MIGRATION_STATUS_CANCELLING,
                          MIGRATION_STATUS_CANCELLED);
    }

    notifier_list_notify(&migration_state_notifiers, s);
}

void migrate_fd_error(MigrationState *s, const Error *error)
{
    trace_migrate_fd_error(error_get_pretty(error));
    assert(s->to_dst_file == NULL);
    migrate_set_state(&s->state, MIGRATION_STATUS_SETUP,
                      MIGRATION_STATUS_FAILED);
    if (!s->error) {
        s->error = error_copy(error);
    }
    notifier_list_notify(&migration_state_notifiers, s);
}

static void migrate_fd_cancel(MigrationState *s)
{
    int old_state ;
    QEMUFile *f = migrate_get_current()->to_dst_file;
    trace_migrate_fd_cancel();

    if (s->rp_state.from_dst_file) {
        /* shutdown the rp socket, so causing the rp thread to shutdown */
        qemu_file_shutdown(s->rp_state.from_dst_file);
    }

    do {
        old_state = s->state;
        if (!migration_is_setup_or_active(old_state)) {
            break;
        }
        migrate_set_state(&s->state, old_state, MIGRATION_STATUS_CANCELLING);
    } while (s->state != MIGRATION_STATUS_CANCELLING);

    /*
     * If we're unlucky the migration code might be stuck somewhere in a
     * send/write while the network has failed and is waiting to timeout;
     * if we've got shutdown(2) available then we can force it to quit.
     * The outgoing qemu file gets closed in migrate_fd_cleanup that is
     * called in a bh, so there is no race against this cancel.
     */
    if (s->state == MIGRATION_STATUS_CANCELLING && f) {
        qemu_file_shutdown(f);
    }
}

void add_migration_state_change_notifier(Notifier *notify)
{
    notifier_list_add(&migration_state_notifiers, notify);
}

void remove_migration_state_change_notifier(Notifier *notify)
{
    notifier_remove(notify);
}

bool migration_in_setup(MigrationState *s)
{
    return s->state == MIGRATION_STATUS_SETUP;
}

bool migration_has_finished(MigrationState *s)
{
    return s->state == MIGRATION_STATUS_COMPLETED;
}

bool migration_has_failed(MigrationState *s)
{
    return (s->state == MIGRATION_STATUS_CANCELLED ||
            s->state == MIGRATION_STATUS_FAILED);
}

bool migration_in_postcopy(MigrationState *s)
{
    return (s->state == MIGRATION_STATUS_POSTCOPY_ACTIVE);
}

bool migration_in_postcopy_after_devices(MigrationState *s)
{
    return migration_in_postcopy(s) && s->postcopy_after_devices;
}

static MigrationState* migration_new(void)
{
    MigrationState *s = g_malloc0(sizeof(MigrationState));
    s->state = MIGRATION_STATUS_NONE;
    s->bandwidth_limit = MAX_THROTTLE;

    s->join.bitmaps_snapshot_started = ~0;
    s->join.bitmaps_commit1 = ~0;
    s->join.bitmaps_commit2 = ~0;

    return s;
}

void __migrate_init(void)
{
    int i;
    migration_states = g_malloc0(sizeof(MigrationState*) * KVM_DIRTY_BITMAP_INIT_COUNT);

    for (i = 0; i < KVM_DIRTY_BITMAP_INIT_COUNT; i++) {
        migration_states[i] = migration_new();
    }

    migration_states_current = 0;
    migration_states_count = KVM_DIRTY_BITMAP_INIT_COUNT;
}

MigrationState *migrate_init(const MigrationParams *params)
{
    MigrationState *s, *s2;

    s = migrate_by_index(0);
    s2 = migrate_by_index(1);

    //move from migrate_get_current
    s->state = MIGRATION_STATUS_NONE;
    s->xbzrle_cache_size = DEFAULT_MIGRATE_CACHE_SIZE;
    s->parameters.compress_threads = DEFAULT_MIGRATE_COMPRESS_LEVEL;
    s->parameters.decompress_threads = DEFAULT_MIGRATE_DECOMPRESS_THREAD_COUNT;
    s->parameters.cpu_throttle_initial = DEFAULT_MIGRATE_CPU_THROTTLE_INITIAL;
    s->parameters.cpu_throttle_increment = DEFAULT_MIGRATE_CPU_THROTTLE_INCREMENT;
    s->parameters.max_bandwidth = MAX_THROTTLE;
    s->parameters.downtime_limit = DEFAULT_MIGRATE_SET_DOWNTIME;
    s->parameters.x_checkpoint_delay = DEFAULT_MIGRATE_X_CHECKPOINT_DELAY;
    qemu_mutex_init(&s->src_page_req_mutex);


    s2->state = MIGRATION_STATUS_NONE;
    s2->xbzrle_cache_size = DEFAULT_MIGRATE_CACHE_SIZE;
    s2->parameters.compress_threads = DEFAULT_MIGRATE_COMPRESS_LEVEL;
    s2->parameters.decompress_threads = DEFAULT_MIGRATE_DECOMPRESS_THREAD_COUNT;
    s2->parameters.cpu_throttle_initial = DEFAULT_MIGRATE_CPU_THROTTLE_INITIAL;
    s2->parameters.cpu_throttle_increment = DEFAULT_MIGRATE_CPU_THROTTLE_INCREMENT;
    s2->parameters.max_bandwidth = MAX_THROTTLE;
    s2->parameters.downtime_limit = DEFAULT_MIGRATE_SET_DOWNTIME;
    s2->parameters.x_checkpoint_delay = DEFAULT_MIGRATE_X_CHECKPOINT_DELAY;
    qemu_mutex_init(&s2->src_page_req_mutex);

    //migrate_state_setup
    /*
     * Reinitialise all migration state, except
     * parameters/capabilities that the user set, and
     * locks.
     */
    s->bytes_xfer = 0;
    s->xfer_limit = 0;
    s->cleanup_bh = 0;
    s->to_dst_file = NULL;
    s->state = MIGRATION_STATUS_NONE;
    s->params = *params;
    s->rp_state.from_dst_file = NULL;
    s->rp_state.error = false;
    s->mbps = 0.0;
    s->downtime = 0;
    s->expected_downtime = 0;
    s->dirty_pages_rate = 0;
    s->dirty_bytes_rate = 0;
    s->setup_time = 0;
    s->dirty_sync_count = 0;
    s->start_postcopy = false;
    s->postcopy_after_devices = false;
    s->postcopy_requests = 0;
    s->migration_thread_running = false;
    s->last_req_rb = NULL;
    error_free(s->error);
    s->error = NULL;

    s2->bytes_xfer = 0;
    s2->xfer_limit = 0;
    s2->cleanup_bh = 0;
    s2->to_dst_file = NULL;
    s2->state = MIGRATION_STATUS_NONE;
    s2->params = *params;
    s2->rp_state.from_dst_file = NULL;
    s2->rp_state.error = false;
    s2->mbps = 0.0;
    s2->downtime = 0;
    s2->expected_downtime = 0;
    s2->dirty_pages_rate = 0;
    s2->dirty_bytes_rate = 0;
    s2->setup_time = 0;
    s2->dirty_sync_count = 0;
    s2->start_postcopy = false;
    s2->postcopy_after_devices = false;
    s2->postcopy_requests = 0;
    s2->migration_thread_running = false;
    s2->last_req_rb = NULL;
    error_free(s2->error);
    s2->error = NULL;

    migrate_set_state(&s->state, MIGRATION_STATUS_NONE, MIGRATION_STATUS_SETUP);
    migrate_set_state(&s2->state, MIGRATION_STATUS_NONE, MIGRATION_STATUS_SETUP);

    QSIMPLEQ_INIT(&s->src_page_requests);
    QSIMPLEQ_INIT(&s2->src_page_requests);

    s->total_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    s2->total_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

    migrate_set_ft_state(s, CUJU_FT_INIT);
    migrate_set_ft_state(s2, CUJU_FT_INIT);

    alloc_ft_dev(s);
    alloc_ft_dev(s2);

    migrate_set_ft_state(s2, CUJU_FT_TRANSACTION_PRE_RUN);

    return s;
}

static GSList *migration_blockers;

void migrate_add_blocker(Error *reason)
{
    migration_blockers = g_slist_prepend(migration_blockers, reason);
}

void migrate_del_blocker(Error *reason)
{
    migration_blockers = g_slist_remove(migration_blockers, reason);
}

void qmp_migrate_incoming(const char *uri, Error **errp)
{
    Error *local_err = NULL;
    static bool once = true;

    if (!deferred_incoming) {
        error_setg(errp, "For use with '-incoming defer'");
        return;
    }
    if (!once) {
        error_setg(errp, "The incoming migration has already been started");
    }

    qemu_start_incoming_migration(uri, &local_err);

    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    once = false;
}

bool migration_is_blocked(Error **errp)
{
    if (qemu_savevm_state_blocked(errp)) {
        return true;
    }

    if (migration_blockers) {
        *errp = error_copy(migration_blockers->data);
        return true;
    }

    return false;
}

void qmp_migrate(const char *uri, bool has_blk, bool blk,
                 bool has_inc, bool inc, bool has_detach, bool detach, bool has_cuju, bool cuju,
                 Error **errp)
{
    Error *local_err = NULL;
    MigrationState *s = migrate_get_current();
    MigrationParams params;
    const char *p;

    params.blk = has_blk && blk;
    params.shared = has_inc && inc;

    if(cuju)
        printf("Enter FT mode\n");

    if (migration_is_setup_or_active(s->state) ||
        s->state == MIGRATION_STATUS_CANCELLING ||
        s->state == MIGRATION_STATUS_COLO) {
        error_setg(errp, QERR_MIGRATION_ACTIVE);
        return;
    }
    if (runstate_check(RUN_STATE_INMIGRATE)) {
        error_setg(errp, "Guest is waiting for an incoming migration");
        return;
    }

    if (migration_is_blocked(errp)) {
        return;
    }

    s = migrate_init(&params);

    if (strstart(uri, "tcp:", &p)) {
        if (cuju) {
            cuju_tcp_start_outgoing_migration(s, p, &local_err);
        }
        else {
            tcp_start_outgoing_migration(s, p, &local_err);
        }
#ifdef CONFIG_RDMA
    } else if (strstart(uri, "rdma:", &p)) {
        rdma_start_outgoing_migration(s, p, &local_err);
#endif
    } else if (strstart(uri, "exec:", &p)) {
        exec_start_outgoing_migration(s, p, &local_err);
    } else if (strstart(uri, "unix:", &p)) {
        unix_start_outgoing_migration(s, p, &local_err);
    } else if (strstart(uri, "fd:", &p)) {
        fd_start_outgoing_migration(s, p, &local_err);
    } else {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "uri",
                   "a valid migration protocol");
        migrate_set_state(&s->state, MIGRATION_STATUS_SETUP,
                          MIGRATION_STATUS_FAILED);
        return;
    }

    if (local_err) {
        migrate_fd_error(s, local_err);
        error_propagate(errp, local_err);
        return;
    }
}

void qmp_migrate_cancel(Error **errp)
{
    migrate_fd_cancel(migrate_get_current());
}

void qmp_migrate_set_cache_size(int64_t value, Error **errp)
{
    MigrationState *s = migrate_get_current();
    int64_t new_size;

    /* Check for truncation */
    if (value != (size_t)value) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "cache size",
                   "exceeding address space");
        return;
    }

    /* Cache should not be larger than guest ram size */
    if (value > ram_bytes_total()) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "cache size",
                   "exceeds guest ram size ");
        return;
    }

    new_size = xbzrle_cache_resize(value);
    if (new_size < 0) {
        error_setg(errp, QERR_INVALID_PARAMETER_VALUE, "cache size",
                   "is smaller than page size");
        return;
    }

    s->xbzrle_cache_size = new_size;
}

int64_t qmp_query_migrate_cache_size(Error **errp)
{
    return migrate_xbzrle_cache_size();
}

void qmp_migrate_set_speed(int64_t value, Error **errp)
{
    MigrationParameters p = {
        .has_max_bandwidth = true,
        .max_bandwidth = value,
    };

    qmp_migrate_set_parameters(&p, errp);
}

void qmp_migrate_set_downtime(double value, Error **errp)
{
    value *= 1000; /* Convert to milliseconds */
    value = MAX(0, MIN(INT64_MAX, value));

    MigrationParameters p = {
        .has_downtime_limit = true,
        .downtime_limit = value,
    };

    qmp_migrate_set_parameters(&p, errp);
}

bool migrate_postcopy_ram(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_POSTCOPY_RAM];
}

bool migrate_auto_converge(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_AUTO_CONVERGE];
}

bool migrate_zero_blocks(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_ZERO_BLOCKS];
}

bool migrate_use_compression(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_COMPRESS];
}

int migrate_compress_level(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.compress_level;
}

int migrate_compress_threads(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.compress_threads;
}

int migrate_decompress_threads(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->parameters.decompress_threads;
}

bool migrate_use_events(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_EVENTS];
}

int migrate_use_xbzrle(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_XBZRLE];
}

int64_t migrate_xbzrle_cache_size(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->xbzrle_cache_size;
}

/* migration thread support */
/*
 * Something bad happened to the RP stream, mark an error
 * The caller shall print or trace something to indicate why
 */
static void mark_source_rp_bad(MigrationState *s)
{
    s->rp_state.error = true;
}

static struct rp_cmd_args {
    ssize_t     len; /* -1 = variable */
    const char *name;
} rp_cmd_args[] = {
    [MIG_RP_MSG_INVALID]        = { .len = -1, .name = "INVALID" },
    [MIG_RP_MSG_SHUT]           = { .len =  4, .name = "SHUT" },
    [MIG_RP_MSG_PONG]           = { .len =  4, .name = "PONG" },
    [MIG_RP_MSG_REQ_PAGES]      = { .len = 12, .name = "REQ_PAGES" },
    [MIG_RP_MSG_REQ_PAGES_ID]   = { .len = -1, .name = "REQ_PAGES_ID" },
    [MIG_RP_MSG_MAX]            = { .len = -1, .name = "MAX" },
};

/*
 * Process a request for pages received on the return path,
 * We're allowed to send more than requested (e.g. to round to our page size)
 * and we don't need to send pages that have already been sent.
 */
static void migrate_handle_rp_req_pages(MigrationState *ms, const char* rbname,
                                       ram_addr_t start, size_t len)
{
    long our_host_ps = getpagesize();

    trace_migrate_handle_rp_req_pages(rbname, start, len);

    /*
     * Since we currently insist on matching page sizes, just sanity check
     * we're being asked for whole host pages.
     */
    if (start & (our_host_ps-1) ||
       (len & (our_host_ps-1))) {
        error_report("%s: Misaligned page request, start: " RAM_ADDR_FMT
                     " len: %zd", __func__, start, len);
        mark_source_rp_bad(ms);
        return;
    }

    if (ram_save_queue_pages(ms, rbname, start, len)) {
        mark_source_rp_bad(ms);
    }
}

/*
 * Handles messages sent on the return path towards the source VM
 *
 */
static void *source_return_path_thread(void *opaque)
{
    MigrationState *ms = opaque;
    QEMUFile *rp = ms->rp_state.from_dst_file;
    uint16_t header_len, header_type;
    uint8_t buf[512];
    uint32_t tmp32, sibling_error;
    ram_addr_t start = 0; /* =0 to silence warning */
    size_t  len = 0, expected_len;
    int res;

    trace_source_return_path_thread_entry();
    while (!ms->rp_state.error && !qemu_file_get_error(rp) &&
           migration_is_setup_or_active(ms->state)) {
        trace_source_return_path_thread_loop_top();
        header_type = qemu_get_be16(rp);
        header_len = qemu_get_be16(rp);

        if (header_type >= MIG_RP_MSG_MAX ||
            header_type == MIG_RP_MSG_INVALID) {
            error_report("RP: Received invalid message 0x%04x length 0x%04x",
                    header_type, header_len);
            mark_source_rp_bad(ms);
            goto out;
        }

        if ((rp_cmd_args[header_type].len != -1 &&
            header_len != rp_cmd_args[header_type].len) ||
            header_len > sizeof(buf)) {
            error_report("RP: Received '%s' message (0x%04x) with"
                    "incorrect length %d expecting %zu",
                    rp_cmd_args[header_type].name, header_type, header_len,
                    (size_t)rp_cmd_args[header_type].len);
            mark_source_rp_bad(ms);
            goto out;
        }

        /* We know we've got a valid header by this point */
        res = qemu_get_buffer(rp, buf, header_len);
        if (res != header_len) {
            error_report("RP: Failed reading data for message 0x%04x"
                         " read %d expected %d",
                         header_type, res, header_len);
            mark_source_rp_bad(ms);
            goto out;
        }

        /* OK, we have the message and the data */
        switch (header_type) {
        case MIG_RP_MSG_SHUT:
            sibling_error = ldl_be_p(buf);
            trace_source_return_path_thread_shut(sibling_error);
            if (sibling_error) {
                error_report("RP: Sibling indicated error %d", sibling_error);
                mark_source_rp_bad(ms);
            }
            /*
             * We'll let the main thread deal with closing the RP
             * we could do a shutdown(2) on it, but we're the only user
             * anyway, so there's nothing gained.
             */
            goto out;

        case MIG_RP_MSG_PONG:
            tmp32 = ldl_be_p(buf);
            trace_source_return_path_thread_pong(tmp32);
            break;

        case MIG_RP_MSG_REQ_PAGES:
            start = ldq_be_p(buf);
            len = ldl_be_p(buf + 8);
            migrate_handle_rp_req_pages(ms, NULL, start, len);
            break;

        case MIG_RP_MSG_REQ_PAGES_ID:
            expected_len = 12 + 1; /* header + termination */

            if (header_len >= expected_len) {
                start = ldq_be_p(buf);
                len = ldl_be_p(buf + 8);
                /* Now we expect an idstr */
                tmp32 = buf[12]; /* Length of the following idstr */
                buf[13 + tmp32] = '\0';
                expected_len += tmp32;
            }
            if (header_len != expected_len) {
                error_report("RP: Req_Page_id with length %d expecting %zd",
                        header_len, expected_len);
                mark_source_rp_bad(ms);
                goto out;
            }
            migrate_handle_rp_req_pages(ms, (char *)&buf[13], start, len);
            break;

        default:
            break;
        }
    }
    if (qemu_file_get_error(rp)) {
        trace_source_return_path_thread_bad_end();
        mark_source_rp_bad(ms);
    }

    trace_source_return_path_thread_end();
out:
    ms->rp_state.from_dst_file = NULL;
    qemu_fclose(rp);
    return NULL;
}

static int open_return_path_on_source(MigrationState *ms)
{

    ms->rp_state.from_dst_file = qemu_file_get_return_path(ms->to_dst_file);
    if (!ms->rp_state.from_dst_file) {
        return -1;
    }

    trace_open_return_path_on_source();
    qemu_thread_create(&ms->rp_state.rp_thread, "return path",
                       source_return_path_thread, ms, QEMU_THREAD_JOINABLE);

    trace_open_return_path_on_source_continue();

    return 0;
}

/* Returns 0 if the RP was ok, otherwise there was an error on the RP */
static int await_return_path_close_on_source(MigrationState *ms)
{
    /*
     * If this is a normal exit then the destination will send a SHUT and the
     * rp_thread will exit, however if there's an error we need to cause
     * it to exit.
     */
    if (qemu_file_get_error(ms->to_dst_file) && ms->rp_state.from_dst_file) {
        /*
         * shutdown(2), if we have it, will cause it to unblock if it's stuck
         * waiting for the destination.
         */
        qemu_file_shutdown(ms->rp_state.from_dst_file);
        mark_source_rp_bad(ms);
    }
    trace_await_return_path_close_on_source_joining();
    qemu_thread_join(&ms->rp_state.rp_thread);
    trace_await_return_path_close_on_source_close();
    return ms->rp_state.error;
}

/*
 * Switch from normal iteration to postcopy
 * Returns non-0 on error
 */
static int postcopy_start(MigrationState *ms, bool *old_vm_running)
{
    int ret;
    QIOChannelBuffer *bioc;
    QEMUFile *fb;
    int64_t time_at_stop = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    migrate_set_state(&ms->state, MIGRATION_STATUS_ACTIVE,
                      MIGRATION_STATUS_POSTCOPY_ACTIVE);

    trace_postcopy_start();
    qemu_mutex_lock_iothread();
    trace_postcopy_start_set_run();

    qemu_system_wakeup_request(QEMU_WAKEUP_REASON_OTHER);
    *old_vm_running = runstate_is_running();
    global_state_store();
    ret = vm_stop_force_state(RUN_STATE_FINISH_MIGRATE);
    if (ret < 0) {
        goto fail;
    }

    ret = bdrv_inactivate_all();
    if (ret < 0) {
        goto fail;
    }

    /*
     * Cause any non-postcopiable, but iterative devices to
     * send out their final data.
     */
    qemu_savevm_state_complete_precopy(ms->to_dst_file, true);

    /*
     * in Finish migrate and with the io-lock held everything should
     * be quiet, but we've potentially still got dirty pages and we
     * need to tell the destination to throw any pages it's already received
     * that are dirty
     */
    if (ram_postcopy_send_discard_bitmap(ms)) {
        error_report("postcopy send discard bitmap failed");
        goto fail;
    }

    /*
     * send rest of state - note things that are doing postcopy
     * will notice we're in POSTCOPY_ACTIVE and not actually
     * wrap their state up here
     */
    qemu_file_set_rate_limit(ms->to_dst_file, INT64_MAX);
    /* Ping just for debugging, helps line traces up */
    qemu_savevm_send_ping(ms->to_dst_file, 2);

    /*
     * While loading the device state we may trigger page transfer
     * requests and the fd must be free to process those, and thus
     * the destination must read the whole device state off the fd before
     * it starts processing it.  Unfortunately the ad-hoc migration format
     * doesn't allow the destination to know the size to read without fully
     * parsing it through each devices load-state code (especially the open
     * coded devices that use get/put).
     * So we wrap the device state up in a package with a length at the start;
     * to do this we use a qemu_buf to hold the whole of the device state.
     */
    bioc = qio_channel_buffer_new(4096);
    qio_channel_set_name(QIO_CHANNEL(bioc), "migration-postcopy-buffer");
    fb = qemu_fopen_channel_output(QIO_CHANNEL(bioc));
    object_unref(OBJECT(bioc));

    /*
     * Make sure the receiver can get incoming pages before we send the rest
     * of the state
     */
    qemu_savevm_send_postcopy_listen(fb);

    qemu_savevm_state_complete_precopy(fb, false);
    qemu_savevm_send_ping(fb, 3);

    qemu_savevm_send_postcopy_run(fb);

    /* <><> end of stuff going into the package */

    /* Now send that blob */
    if (qemu_savevm_send_packaged(ms->to_dst_file, bioc->data, bioc->usage)) {
        goto fail_closefb;
    }
    qemu_fclose(fb);

    /* Send a notify to give a chance for anything that needs to happen
     * at the transition to postcopy and after the device state; in particular
     * spice needs to trigger a transition now
     */
    ms->postcopy_after_devices = true;
    notifier_list_notify(&migration_state_notifiers, ms);

    ms->downtime =  qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - time_at_stop;

    qemu_mutex_unlock_iothread();

    /*
     * Although this ping is just for debug, it could potentially be
     * used for getting a better measurement of downtime at the source.
     */
    qemu_savevm_send_ping(ms->to_dst_file, 4);

    ret = qemu_file_get_error(ms->to_dst_file);
    if (ret) {
        error_report("postcopy_start: Migration stream errored");
        migrate_set_state(&ms->state, MIGRATION_STATUS_POSTCOPY_ACTIVE,
                              MIGRATION_STATUS_FAILED);
    }

    return ret;

fail_closefb:
    qemu_fclose(fb);
fail:
    migrate_set_state(&ms->state, MIGRATION_STATUS_POSTCOPY_ACTIVE,
                          MIGRATION_STATUS_FAILED);
    qemu_mutex_unlock_iothread();
    return -1;
}

/**
 * migration_completion: Used by migration_thread when there's not much left.
 *   The caller 'breaks' the loop when this returns.
 *
 * @s: Current migration state
 * @current_active_state: The migration state we expect to be in
 * @*old_vm_running: Pointer to old_vm_running flag
 * @*start_time: Pointer to time to update
 */
static void migration_completion(MigrationState *s, int current_active_state,
                                 bool *old_vm_running,
                                 int64_t *start_time)
{
    int ret;

    if (s->state == MIGRATION_STATUS_ACTIVE) {
        qemu_mutex_lock_iothread();
        *start_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
        qemu_system_wakeup_request(QEMU_WAKEUP_REASON_OTHER);
        *old_vm_running = runstate_is_running();
        ret = global_state_store();

        if (!ret) {
            ret = vm_stop_force_state(RUN_STATE_FINISH_MIGRATE);
            /*
             * Don't mark the image with BDRV_O_INACTIVE flag if
             * we will go into COLO stage later.
             */
            if (ret >= 0 && !migrate_colo_enabled() && !migrate_cuju_enabled()) {
                ret = bdrv_inactivate_all();
            }
            if (ret >= 0) {
                qemu_file_set_rate_limit(s->to_dst_file, INT64_MAX);
                qemu_savevm_state_complete_precopy(s->to_dst_file, false);
            }
        }
        qemu_mutex_unlock_iothread();

        if (ret < 0) {
            goto fail;
        }
    } else if (s->state == MIGRATION_STATUS_POSTCOPY_ACTIVE) {
        trace_migration_completion_postcopy_end();

        qemu_savevm_state_complete_postcopy(s->to_dst_file);
        trace_migration_completion_postcopy_end_after_complete();
    }

    /*
     * If rp was opened we must clean up the thread before
     * cleaning everything else up (since if there are no failures
     * it will wait for the destination to send it's status in
     * a SHUT command).
     * Postcopy opens rp if enabled (even if it's not avtivated)
     */
    if (migrate_postcopy_ram()) {
        int rp_error;
        trace_migration_completion_postcopy_end_before_rp();
        rp_error = await_return_path_close_on_source(s);
        trace_migration_completion_postcopy_end_after_rp(rp_error);
        if (rp_error) {
            goto fail_invalidate;
        }
    }

    if (qemu_file_get_error(s->to_dst_file)) {
        trace_migration_completion_file_err();
        goto fail_invalidate;
    }

    if (!migrate_colo_enabled()) {
        migrate_set_state(&s->state, current_active_state,
                          MIGRATION_STATUS_COMPLETED);
    }

    return;

fail_invalidate:
    /* If not doing postcopy, vm_start() will be called: let's regain
     * control on images.
     */
    if (s->state == MIGRATION_STATUS_ACTIVE) {
        Error *local_err = NULL;

        bdrv_invalidate_cache_all(&local_err);
        if (local_err) {
            error_report_err(local_err);
        }
    }

fail:
    migrate_set_state(&s->state, current_active_state,
                      MIGRATION_STATUS_FAILED);
}

bool migrate_colo_enabled(void)
{
    MigrationState *s = migrate_get_current();
    return s->enabled_capabilities[MIGRATION_CAPABILITY_X_COLO];
}

bool migrate_cuju_enabled(void)
{
    MigrationState *s = migrate_get_current();
    return s->enabled_capabilities[MIGRATION_CAPABILITY_CUJU_FT];
}

static void migrate_fd_get_notify(void *opaque)
{
    MigrationState *s = opaque;
    Error *local_err = NULL;

    qemu_file_get_notify(s->file);

    if (qemu_file_get_error(s->file) && qemu_file_get_error(s->file) != -EAGAIN) {
        qemu_set_fd_handler(s->fd, NULL, NULL, NULL);
        cuju_ft_mode = CUJU_FT_ERROR;
        qemu_savevm_state_cancel(s->file);
        migrate_fd_error(s, local_err);
        event_tap_unregister();
    }
}

static void migrate_fd_put_notify(void *opaque)
{
    MigrationState *s = opaque;

    qemu_set_fd_handler(s->fd, CUJU_IO_HANDLER_KEEP, NULL, s);

    Error *local_err = NULL;
    qemu_file_put_notify(s->file);
    if (s->file && qemu_file_get_error(s->file)) {
        if (qemu_file_get_error(s->file) != -EAGAIN)
            migrate_fd_error(s, local_err);
    }
}

static ssize_t migrate_fd_put_buffer(void *opaque, const void *data,
                                     size_t size)
{
    MigrationState *s = opaque;
    ssize_t ret;

    if (s->state != MIG_STATE_ACTIVE) {
        fprintf(stderr, "%s state = %d\n", __func__, s->state);
        assert(s->state == MIG_STATE_ACTIVE);
        return -EIO;
    }

    do {
        ret = s->write(s, data, size);
    } while (ret == -1 && ((s->get_error(s)) == EINTR));

    if (ret == -1)
        ret = -(s->get_error(s));

    if (ret == -EAGAIN && cuju_ft_mode != CUJU_FT_TRANSACTION_SPECULATIVE) {
        qemu_set_fd_handler(s->fd, CUJU_IO_HANDLER_KEEP, migrate_fd_put_notify, s);
    }

    return ret;
}

int migrate_fd_get_buffer(void *opaque, uint8_t *data, int64_t pos, size_t size)
{
    MigrationState *s = opaque;
    int ret;
    ret = s->read(s, data, size);

    if (ret == -1)
        ret = -(s->get_error(s));

    if (ret == -EAGAIN)
        qemu_set_fd_handler(s->fd, migrate_fd_get_notify, CUJU_IO_HANDLER_KEEP, s);

    return ret;
}

static void send_commit1(MigrationState *s)
{
    // TODO what if snapshot stage isn't finished yet?
    assert(qemu_ft_trans_commit1(s->file, s->ram_len, s->trans_serial) > 0);

    s->transfer_finish_time = time_in_double();

    s->time_buf_off += sprintf(s->time_buf+s->time_buf_off, "\t%.4lf\tsnf%.4lf\t%.4lf", s->snapshot_start_time, s->snapshot_finish_time, (s->snapshot_finish_time-s->snapshot_start_time)*1000);
    s->time_buf_off += sprintf(s->time_buf+s->time_buf_off, "\t%.4lf", (s->transfer_real_finish_time-s->transfer_real_start_time) * 1000);
    s->time_buf_off += sprintf(s->time_buf+s->time_buf_off, "\ttrntm\t%.4lf", (s->transfer_finish_time-s->transfer_start_time)*1000);
    s->time_buf_off += sprintf(s->time_buf+s->time_buf_off, "\t%4d\n", s->dirty_pfns_len);
    //printf("%s",s->time_buf);
    s->time_buf_off = 0;

    FTPRINTF("\n%s %d (%lf) send commmit1\n", __func__, migrate_get_index(s), time_in_double());
}

static void migrate_join_close_socks(MigrationJoinConn *conn)
{
    MigrationState *s1, *s2;
    MigrationJoinConn *brother;

    if (conn->r_sock == 0)
        return;

    printf("%s", __func__);

    brother = conn->brother;

    s1 = (MigrationState *)conn->migrate;
    s2 = (MigrationState *)brother->migrate;

    qemu_fclose(conn->r_file);
    qemu_fclose(conn->w_file);
    qemu_fclose(brother->r_file);
    qemu_fclose(brother->w_file);

    conn->r_sock = 0;
    conn->w_sock = 0;
    brother->r_sock = 0;
    brother->w_sock = 0;

    s1->join.number--;
    s2->join.number--;
}

static void gft_reset_bitmaps_commit1(MigrationState *s)
{
    MigrationJoinConn *conn;
    int i;
    FTPRINTF("%s(%lf) %d\n", __func__, time_in_double(), migrate_get_index(s));
    for (i = 0; i < MIG_MAX_JOIN; ++i) {
        conn = &s->join.conn[i];
        if (conn->r_sock) {
            clear_bit(conn->gft_id, &s->join.bitmaps_commit1);
        }
    }
}

static void gft_broadcast_commit2(MigrationState *s)
{
    MigrationJoin *join = &s->join;
    MigrationJoinConn *conn;
    int i;

    if (join->number == 0)
        return;

    for (i = 0; i < MIG_MAX_JOIN; ++i) {
        conn = &join->conn[i];
        if (conn->w_sock) {
            FTPRINTF("%s migrationState %d sending commit2\n", __func__, migrate_get_index(s));
            GFT_SEND_CMD(conn->w_file, MIG_JOIN_EPOCH_COMMIT2);
        }
    }
}

/*
 *  the following can happen at the same time.
 *
 *  send out GFT_SNAPSHOT_START
 *  recv multiple MIG_JOIN_EPOCH_STARTs
 *  recv multiple MIG_JOIN_EPOCH_COMMIT1
 *
 */
static void gft_broadcast_snapshot_start(MigrationState *s)
{
    MigrationJoin *join = &s->join;
    MigrationJoinConn *conn;
    int i;

    if (join->number == 0)
        return;

    for (i = 0; i < MIG_MAX_JOIN; ++i) {
        conn = &join->conn[i];
        if (conn->r_sock) {
            FTPRINTF("%s(%lf) migrationState %d sending start\n", __func__, time_in_double(), migrate_get_index(s));
            GFT_SEND_CMD(conn->w_file, GFT_SNAPSHOT_START);
        }
    }
}

static void flush_dev(void *opaque)
{
    MigrationState *s = opaque;

    qemu_fflush(s->file);
    cuju_ft_trans_flush_buf_desc(s->file);

    if (s->flush_vs_commit1)
        send_commit1(s);
    else
        s->flush_vs_commit1 = true;
}

// we need this bh because only main-io-thread can send/recv
// control messages to/from slave.
void kvm_shmem_trans_ram_bh(void *opaque)
{
    MigrationState *s = opaque;

    if (s->flush_vs_commit1)
        send_commit1(s);
    else
        s->flush_vs_commit1 = true;
}

static int migrate_ft_trans_put_ready(void)
{
    return 0;
}

// called when all outputs were flushed out
static void migrate_ft_trans_flush_cb(void *opaque)
{
    MigrationState *s = opaque;

    FTPRINTF("%s(%lf) %d\n", __func__, time_in_double(), migrate_get_index(s));

    migrate_set_ft_state(s, CUJU_FT_TRANSACTION_PRE_RUN);
    migrate_run(s);
}

static void kvmft_flush_output(MigrationState *s)
{
	//TODO blk server
    if (kvm_blk_session)
        kvm_blk_epoch_commit(kvm_blk_session);
	

    virtio_blk_commit_temp_list(s->virtio_blk_temp_list);
    s->virtio_blk_temp_list = NULL;
    s->net_list_empty = event_tap_net_list_empty(s->ft_event_tap_net_list);
    event_tap_flush_net_list(s->ft_event_tap_net_list, migrate_ft_trans_flush_cb, s);
    s->ft_event_tap_net_list = event_tap_net_list_new();
}

static void gft_master_read_master(void *opaque)
{
    MigrationJoinConn *conn = opaque;
    MigrationState *s = conn->migrate;
    MigrationJoin *join = &s->join;
    int cmd, len;

    len = qemu_fill_buffer(conn->r_file);
    if (len == -EAGAIN || len == -EWOULDBLOCK)
        return;
    else if (len <= 0) {
        migrate_join_close_socks(conn);
        printf("**** %s close\n", __func__);
        qemu_set_fd_handler(conn->r_sock, NULL, NULL, NULL);
        exit(-1);
        return;
    }

    while (len-- > 0) {
        cmd = qemu_get_byte(conn->r_file);
        conn->last_recv = cmd;
        FTPRINTF("%s(%lf) migrationState %d recv %d from %d\n", __func__,
            time_in_double(), migrate_get_index(s), cmd, conn->gft_id);
        switch (cmd) {
            case GFT_SNAPSHOT_START:
                FTPRINTF("%s owner is %d\n", __func__, migrate_token_owner ? migrate_token_owner->cur_off : -1);
                if (s == migrate_token_owner) {
                    if (s->ft_state == CUJU_FT_TRANSACTION_RUN)
                        kvmft_fire_timer(s->cur_off);
                    else
                        s->epoch_timer_pending = true;
                }
                if(join->bitmaps_snapshot_started == ~0) {
                    printf("!!%s Get duplicated command snapshot %d!!\n", __func__, cmd);
                    break;
                }
                assert(join->bitmaps_snapshot_started != ~0);
                if (test_and_set_bit(conn->gft_id, &join->bitmaps_snapshot_started))
                    abort();
                if (join->bitmaps_snapshot_started == ~0) {
                    MigrationState *n = migrate_get_next(s);
                    if (n->join.wait_group_snapshot_start) {
                        n->join.wait_group_snapshot_start = false;
                        migrate_run(n);
                    }
                }
                break;
            case MIG_JOIN_EPOCH_COMMIT1:
                assert(join->bitmaps_commit1 != ~0);
                if (test_and_set_bit(conn->gft_id, &join->bitmaps_commit1))
                    abort();
                if (join->bitmaps_commit1 == ~0) {
                    FTPRINTF("%s %d broadcast commit2\n", __func__, migrate_get_index(s));
                    gft_broadcast_commit2(s);
                    if (join->wait_group_transfer_done) {
                        join->wait_group_transfer_done = false;
                        FTPRINTF("%s(%lf) %d flush output\n", __func__, time_in_double(), migrate_get_index(s));
                        gft_reset_bitmaps_commit1(s);
                        kvmft_flush_output(s);
                    }
                }
                break;
            case MIG_JOIN_EPOCH_COMMIT2:
                if(join->bitmaps_commit2 == ~0) {
                    printf("!!%s Get duplicated command commit2 %d!!\n", __func__, cmd);
                    break;
                }
                assert(join->bitmaps_commit2 != ~0);
                if (test_and_set_bit(conn->gft_id, &join->bitmaps_commit2))
                    abort();
                if (join->bitmaps_commit2 == ~0 && join->wait_group_commit2) {
                    join->wait_group_commit2 = false;
                    migrate_run(s);
                }
                break;
            default:
                break;
        }
    }
}

static void gft_master_try_get_notify(MigrationState *s)
{
    MigrationJoin *join = &s->join;
    MigrationJoinConn *conn;
    int i;

    if (join->number == 0)
        return;

    for (i = 0; i < MIG_MAX_JOIN; ++i) {
        conn = &join->conn[i];
        if (conn->r_sock)
            gft_master_read_master(conn);
    }
}

static struct MigrationJoinConn* gft_master_connect_other_master(
                MigrationState *s, int target_gft_id)
{
    struct MigrationJoinConn *conn = NULL;
    int i, sd, cmd, index = s->cur_off;
    Error *err = NULL;
    char host_port[32];
    QEMUFile *f;
    GroupFTMember *gft_member;

    assert(target_gft_id >= 0 && target_gft_id < GROUP_FT_MEMBER_MAX);

    gft_member = &group_ft_members[target_gft_id];

    sprintf(host_port, "%s:%d", gft_member->master_host_ip,
            gft_member->master_host_gft_port);

    for (i = 0; i < MIG_MAX_JOIN; ++i) {
        if (s->join.conn[i].r_sock == 0) {
            conn = &s->join.conn[i];
            break;
        }
    }
    if (i == MIG_MAX_JOIN) {
        printf("%s can't find spare conn.\n", __func__);
        goto out;
    }

    /* read first, write second. */
    sd = inet_connect(host_port, &err);
    if (err || sd == -1) {
        printf("%s error connect to %s.\n", __func__, host_port);
        goto out;
    }

    f = qemu_fopen_socket(sd);
    if (f == NULL) {
        printf("%s can't open qemu_fopen_socket.\n", __func__);
        goto out;
    }
    conn->r_file = f;
    conn->r_sock = sd;

    assert(send(sd, &index, sizeof(index), 0) == sizeof(index));
    assert(recv(sd, &index, sizeof(index), 0) == sizeof(index));
    assert(index == s->cur_off);

    sd = inet_connect(host_port, &err);
    if (err || sd == -1) {
        printf("%s error connect to %s.\n", __func__, host_port);
        goto out;
    }

    f = qemu_fopen_socket(sd);
    if (f == NULL) {
        printf("%s can't open qemu_fopen_socket.\n", __func__);
        goto out;
    }
    conn->w_file = f;
    conn->w_sock = sd;

    assert(send(sd, &index, sizeof(index), 0) == sizeof(index));
    assert(recv(sd, &index, sizeof(index), 0) == sizeof(index));
    assert(index == s->cur_off);

    conn->migrate = s;
    conn->gft_id = target_gft_id;

    socket_set_nodelay(conn->w_sock);
    qemu_set_nonblock(conn->w_sock);
    qemu_set_nonblock(conn->r_sock);

    //qemu_set_fd_survive_ft_pause(conn->r_sock, true);
    //qemu_set_fd_survive_ft_pause(conn->w_sock, true);

    // send MIG_JOIN_GFT_NEW and my gft_id
    cmd = MIG_JOIN_GFT_NEW;
    assert(send(conn->w_sock, &cmd, sizeof(cmd), 0) == sizeof(cmd));
    assert(send(conn->w_sock, &my_gft_id, sizeof(my_gft_id), 0) == sizeof(my_gft_id));

    return conn;
out:
    if (conn)
        migrate_join_close_socks(conn);
    return NULL;
}

static void gft_connect_internal(void)
{
    MigrationState *s1, *s2;
    struct MigrationJoinConn *conn1, *conn2;
    int i;

    s1 = migrate_by_index(0);
    s2 = migrate_by_index(1);

    for (i = 0; i < group_ft_members_size; ++i) {
        GroupFTMember *m = &group_ft_members[i];
        if (m->gft_id > my_gft_id) {
            conn1 = gft_master_connect_other_master(s1, m->gft_id);
            if (!conn1)
                return;
            conn2 = gft_master_connect_other_master(s2, m->gft_id);
            if (!conn2)
                return;

            conn1->brother = conn2;
            conn2->brother = conn1;

            clear_bit(conn1->gft_id, &s1->join.bitmaps_snapshot_started);
            clear_bit(conn1->gft_id, &s1->join.bitmaps_commit1);
            clear_bit(conn2->gft_id, &s2->join.bitmaps_snapshot_started);
            clear_bit(conn2->gft_id, &s2->join.bitmaps_commit1);

            s1->join.number++;
            s2->join.number++;

            printf("%s connection built with %d\n", __func__, m->gft_id);
            printf("%s join.number %d %d\n", __func__, s1->join.number, s2->join.number);
        }
    }
}

static void gft_master_notify_leader_migration_done(void)
{
    int send;
    if (!group_ft_members_size)
        return;
    if (group_ft_leader_sock) {
        send = MIG_JOIN_GFT_MIGRATION_DONE;
        assert(write(group_ft_leader_sock, &send, sizeof(send)) == sizeof(send));
    } else if (++group_ft_members_ready == group_ft_members_size)
        gft_leader_broadcast_all_migration_done();
    printf("%s leader_sock = %d\n", __func__, group_ft_leader_sock);
}

static void gft_prepare_snapshot_bitmap(void)
{
    MigrationState *s = migrate_by_index(0);
    int i;
    s = migrate_get_previous(s);
    for (i = 0; i < group_ft_members_size; i++) {
        struct MigrationJoinConn *c = &s->join.conn[i];
        set_bit(c->gft_id, &s->join.bitmaps_snapshot_started);
    }
}

static void gft_master_start_listen_other_masters(void)
{
    int i, j;
    for (i = 0; i < migration_states_count; i++) {
        MigrationState *s = migrate_by_index(i);
        for (j = 0; j < group_ft_members_size; j++) {
            struct MigrationJoinConn *c = &s->join.conn[j];
            if (c->r_sock) {
                qemu_set_fd_handler(c->r_sock, NULL, NULL, NULL);
                qemu_set_fd_handler(c->r_sock, gft_master_read_master, NULL, c);
                qemu_set_fd_survive_ft_pause(c->r_sock, true);
            }
        }
    }
}

static void gft_master_wait_all_migration_done(void *opaque)
{
    MigrationState *s = group_ft_wait_all.s;
    if (!group_ft_members_size ||
        group_ft_members_size == group_ft_members_ready) {
        gft_prepare_snapshot_bitmap();
        gft_master_start_listen_other_masters();
        printf("%s ok, run %d!\n", __func__, s->cur_off);
        if (group_ft_wait_all.timer)
            timer_del(group_ft_wait_all.timer);
        migrate_run(s);
        vm_start();
    } else {
        if (!group_ft_wait_all.timer)
            group_ft_wait_all.timer = timer_new_ms(QEMU_CLOCK_REALTIME,
                gft_master_wait_all_migration_done, NULL);
        printf("wait for other migrations..\n");
        timer_mod(group_ft_wait_all.timer, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + 1000);
    }
}

static void gft_broadcast_backup_done(MigrationState *s)
{
    MigrationJoin *join = &s->join;
    MigrationJoinConn *conn;
    int i;

    if (join->number == 0)
        return;

    for (i = 0; i < MIG_MAX_JOIN; ++i) {
        conn = &join->conn[i];
        if (conn->w_sock) {
            FTPRINTF("%s migrationState %d sending commit1\n", __func__, migrate_get_index(s));
            GFT_SEND_CMD(conn->w_file, MIG_JOIN_EPOCH_COMMIT1);
        }
    }
}

// NOTE: don't send content in this function
static int migrate_ft_trans_get_ready(void *opaque)
{
    MigrationState *s = opaque;
    static bool kvmft_first_ack = true;
    int ret = -1;

    if (!qemu_ft_trans_is_sender(s->file))
        return 0;

    switch (s->ft_state) {

    case CUJU_FT_INIT:
        printf("%s recv ack, index %d\n", __func__, s->cur_off);
        if ((ret = qemu_ft_trans_recv_ack(s->file)) < 0) {
            printf("%s sender receive ACK failed.\n", __func__);
            goto error_out;
        }
        migrate_set_ft_state(s, CUJU_FT_TRANSACTION_PRE_RUN);

        assert(kvmft_first_ack);
        kvmft_first_ack = false;

        kvmft_calc_ram_hash();

        assert(s == migrate_token_owner);
        gft_connect_internal();
        gft_master_notify_leader_migration_done();
        group_ft_wait_all.s = s;
        gft_master_wait_all_migration_done(NULL);

        break;

    case CUJU_FT_TRANSACTION_TRANSFER:
        if ((ret = qemu_ft_trans_recv_ack1(s->file)) < 0) {
            printf("%s sender receive ACK1 failed.\n", __func__);
            goto error_out;
        }

        FTPRINTF("%s slave ack1 time %lf\n", __func__,
            time_in_double() - s->transfer_finish_time);

        dirty_page_tracking_logs_start_flush_output(s);
        migrate_set_ft_state(s, CUJU_FT_TRANSACTION_FLUSH_OUTPUT);

        gft_broadcast_backup_done(s);

        if (s->join.bitmaps_commit1 == ~0) {
            gft_reset_bitmaps_commit1(s);
            kvmft_flush_output(s);
        } else
            s->join.wait_group_transfer_done = true;
        break;

		kvmft_flush_output(s);
        break;

    default:
        printf("%s unexpected (%d) state %d\n", __func__, migrate_get_index(s), s->ft_state);
        goto error_out;
    }

    ret = 0;
    goto out;

error_out:
    cuju_ft_mode = CUJU_FT_ERROR;
    qemu_savevm_state_cancel(s->file);
    Error *local_err = NULL;
    migrate_fd_error(s, local_err);
    event_tap_unregister();

out:
    return ret;
}

void migrate_fd_wait_for_unfreeze(void *opaque)
{
    MigrationState *s = opaque;
    int ret;

    if (s->state != MIG_STATE_ACTIVE)
        return;

    do {
        fd_set wfds;

        FD_ZERO(&wfds);
        FD_SET(s->fd, &wfds);

        ret = select(s->fd + 1, NULL, &wfds, NULL, NULL);
    } while (ret == -1 && (s->get_error(s)) == EINTR);

    if (ret == -1) {
        qemu_file_set_error(s->file, -s->get_error(s));
    }
}

static int migrate_fd_close(void *opaque)
{
    MigrationState *s = opaque;

    /* not close socket if in ft mode */
    if (cuju_ft_mode != CUJU_FT_OFF && cuju_ft_mode != CUJU_FT_ERROR) {
        printf("%s skip close socket %d in ft mode\n", __func__, s->fd);
        return 0;
    }

    qemu_set_fd_handler(s->fd, NULL, NULL, NULL);
    return s->close(s);
}

static void ft_setup_migrate_state(MigrationState *s, int index)
{
    s->file = cuju_qemu_fopen_ops_ft_trans(s,
                                      migrate_fd_put_buffer,
                                      migrate_fd_get_buffer,
                                      migrate_ft_trans_put_ready,
                                      migrate_ft_trans_get_ready,
                                      migrate_fd_wait_for_unfreeze,
                                      migrate_fd_close,
                                      1, -1, -1);

    s->file->free_buf_on_flush = true;
    s->file->free_buf_on_flush = true;
    cuju_qemu_set_last_cmd(s->file, CUJU_QEMU_VM_TRANSACTION_BEGIN);

    s->state = MIG_STATE_ACTIVE;

    socket_set_nodelay(s->fd);
    s->cur_off = index;

    s->ft_event_tap_net_list = event_tap_net_list_new(); //event_tap_get_list(index, 0);
    s->ft_event_tap_list = event_tap_get_list(index, 1);

    s->bh = qemu_bh_new(kvm_shmem_trans_ram_bh, s);
    qemu_bh_set_mig_survive(s->bh, true);

    s->flush_bh = qemu_bh_new(flush_dev, s);
    qemu_bh_set_mig_survive(s->flush_bh, true);

    qemu_set_fd_handler(s->fd, migrate_fd_get_notify, NULL, s);
    qemu_set_fd_survive_ft_pause(s->fd, true);
}

/*
 * Master migration thread on the source VM.
 * It drives the migration and pumps the data down the outgoing channel.
 */
static void *migration_thread(void *opaque)
{
    MigrationState *s = opaque;
    MigrationState *s2 = migrate_by_index(1);
    /* Used by the bandwidth calcs, updated later */
    int64_t initial_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    int64_t setup_start = qemu_clock_get_ms(QEMU_CLOCK_HOST);
    int64_t initial_bytes = 0;
    int64_t max_size = 0;
    int64_t start_time = initial_time;
    int64_t end_time;
    bool old_vm_running = false;
    bool entered_postcopy = false;
    /* The active state we expect to be in; ACTIVE or POSTCOPY_ACTIVE */
    enum MigrationStatus current_active_state = MIGRATION_STATUS_ACTIVE;
    bool enable_colo = migrate_colo_enabled();
    bool enable_cuju = migrate_cuju_enabled();

    rcu_register_thread();

    qemu_savevm_state_header(s->to_dst_file);

    if (migrate_postcopy_ram()) {
        /* Now tell the dest that it should open its end so it can reply */
        qemu_savevm_send_open_return_path(s->to_dst_file);

        /* And do a ping that will make stuff easier to debug */
        qemu_savevm_send_ping(s->to_dst_file, 1);

        /*
         * Tell the destination that we *might* want to do postcopy later;
         * if the other end can't do postcopy it should fail now, nice and
         * early.
         */
        qemu_savevm_send_postcopy_advise(s->to_dst_file);
    }

    qemu_savevm_state_begin(s->to_dst_file, &s->params);

    s->setup_time = qemu_clock_get_ms(QEMU_CLOCK_HOST) - setup_start;
    current_active_state = MIGRATION_STATUS_ACTIVE;
    migrate_set_state(&s->state, MIGRATION_STATUS_SETUP,
                      MIGRATION_STATUS_ACTIVE);

    trace_migration_thread_setup_complete();

	printf("Start live migration iterate backup\n");
    while (s->state == MIGRATION_STATUS_ACTIVE ||
           s->state == MIGRATION_STATUS_POSTCOPY_ACTIVE) {
        int64_t current_time;
        uint64_t pending_size;

        if (!qemu_file_rate_limit(s->to_dst_file)) {
            uint64_t pend_post, pend_nonpost;

            qemu_savevm_state_pending(s->to_dst_file, max_size, &pend_nonpost,
                                      &pend_post);
            pending_size = pend_nonpost + pend_post;
            trace_migrate_pending(pending_size, max_size,
                                  pend_post, pend_nonpost);
            if (pending_size && pending_size >= max_size) {
                /* Still a significant amount to transfer */

                if (migrate_postcopy_ram() &&
                    s->state != MIGRATION_STATUS_POSTCOPY_ACTIVE &&
                    pend_nonpost <= max_size &&
                    atomic_read(&s->start_postcopy)) {

                    if (!postcopy_start(s, &old_vm_running)) {
                        current_active_state = MIGRATION_STATUS_POSTCOPY_ACTIVE;
                        entered_postcopy = true;
                    }

                    continue;
                }
                /* Just another iteration step */
                qemu_savevm_state_iterate(s->to_dst_file, entered_postcopy);
            } else {
                trace_migration_thread_low_pending(pending_size);
                migration_completion(s, current_active_state,
                                     &old_vm_running, &start_time);
                break;
            }
        }

        if (qemu_file_get_error(s->to_dst_file)) {
            migrate_set_state(&s->state, current_active_state,
                              MIGRATION_STATUS_FAILED);
            trace_migration_thread_file_err();
            break;
        }
        current_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
        if (current_time >= initial_time + BUFFER_DELAY) {
            uint64_t transferred_bytes = qemu_ftell(s->to_dst_file) -
                                         initial_bytes;
            uint64_t time_spent = current_time - initial_time;
            double bandwidth = (double)transferred_bytes / time_spent;
            max_size = bandwidth * s->parameters.downtime_limit;

            s->mbps = (((double) transferred_bytes * 8.0) /
                    ((double) time_spent / 1000.0)) / 1000.0 / 1000.0;

            trace_migrate_transferred(transferred_bytes, time_spent,
                                      bandwidth, max_size);
            /* if we haven't sent anything, we don't want to recalculate
               10000 is a small enough number for our purposes */
            if (s->dirty_bytes_rate && transferred_bytes > 10000) {
                s->expected_downtime = s->dirty_bytes_rate / bandwidth;
            }

            qemu_file_reset_rate_limit(s->to_dst_file);
            initial_time = current_time;
            initial_bytes = qemu_ftell(s->to_dst_file);
        }
        if (qemu_file_rate_limit(s->to_dst_file)) {
            /* usleep expects microseconds */
            g_usleep((initial_time + BUFFER_DELAY - current_time)*1000);
        }
    }

    trace_migration_thread_after_loop();
    /* If we enabled cpu throttling for auto-converge, turn it off. */
    cpu_throttle_stop();
    end_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);

    printf("%s migrate done and cuju = %d\n", __func__, enable_cuju);
    if(enable_cuju) {

		printf("start cuju process\n");
		ft_setup_migrate_state(s, 0);
        ft_setup_migrate_state(s2, 1);

		event_tap_register(NULL);

		kvm_shmem_sortup_trackable();

		assert(!kvm_shmem_report_trackable());

        qemu_mutex_init(&ft_mutex);
        qemu_cond_init(&ft_cond);
        cuju_ft_trans_init_buf_desc(&ft_mutex, &ft_cond);
        cuju_ft_trans_set_buffer_mode(1);

		//TODO blk_server support
        if (kvm_blk_session)
        	kvm_blk_notify_ft(kvm_blk_session);

		//memory_global_dirty_log_start();  //For debug
        kvm_shmem_start_ft();

		migrate_token_owner = migrate_by_index(0);

		//TODO find io thread fd
		//extern int io_thread_fd;
        //qemu_set_fd_survive_ft_pause(io_thread_fd, true);

		assert(!runstate_is_running());

        assert(!kvmft_set_master_slave_sockets(s, ft_ram_conn_count));
        assert(!kvmft_set_master_slave_sockets(s2, ft_ram_conn_count));

		return NULL;
    }
    else {
		qemu_mutex_lock_iothread();
        /*
         * The resource has been allocated by migration will be reused in COLO
         * process, so don't release them.
         */
        if (!enable_colo) {
            qemu_savevm_state_cleanup();
        }
        if (s->state == MIGRATION_STATUS_COMPLETED) {
            uint64_t transferred_bytes = qemu_ftell(s->to_dst_file);
            s->total_time = end_time - s->total_time;
            if (!entered_postcopy) {
                s->downtime = end_time - start_time;
            }
            if (s->total_time) {
                s->mbps = (((double) transferred_bytes * 8.0) /
                           ((double) s->total_time)) / 1000;
            }
            runstate_set(RUN_STATE_POSTMIGRATE);
        } else {
            if (s->state == MIGRATION_STATUS_ACTIVE && enable_colo) {
                migrate_start_colo_process(s);
                qemu_savevm_state_cleanup();
                /*
                * Fixme: we will run VM in COLO no matter its old running state.
                * After exited COLO, we will keep running.
                */
                old_vm_running = true;
            }
            if (old_vm_running && !entered_postcopy) {
                vm_start();
            } else {
                if (runstate_check(RUN_STATE_FINISH_MIGRATE)) {
                    runstate_set(RUN_STATE_POSTMIGRATE);
                }
            }
        }
	    qemu_bh_schedule(s->cleanup_bh);
	    qemu_mutex_unlock_iothread();

    	rcu_unregister_thread();
    }

    return NULL;
}

void migrate_fd_connect(MigrationState *s)
{
    s->expected_downtime = s->parameters.downtime_limit;
    s->cleanup_bh = qemu_bh_new(migrate_fd_cleanup, s);

    qemu_file_set_blocking(s->to_dst_file, true);
    qemu_file_set_rate_limit(s->to_dst_file,
                             s->parameters.max_bandwidth / XFER_LIMIT_RATIO);

    /* Notify before starting migration thread */
    notifier_list_notify(&migration_state_notifiers, s);

    /*
     * Open the return path; currently for postcopy but other things might
     * also want it.
     */
    if (migrate_postcopy_ram()) {
        if (open_return_path_on_source(s)) {
            error_report("Unable to open return-path for postcopy");
            migrate_set_state(&s->state, MIGRATION_STATUS_SETUP,
                              MIGRATION_STATUS_FAILED);
            migrate_fd_cleanup(s);
            return;
        }
    }

    migrate_compress_threads_create();
    qemu_thread_create(&s->thread, "migration", migration_thread, s,
                       QEMU_THREAD_JOINABLE);
    s->migration_thread_running = true;
}

PostcopyState  postcopy_state_get(void)
{
    return atomic_mb_read(&incoming_postcopy_state);
}

/* Set the state and return the old state */
PostcopyState postcopy_state_set(PostcopyState new_state)
{
    return atomic_xchg(&incoming_postcopy_state, new_state);
}

// called when qemu_file buffer is full
/*
static int cuju_ft_dev_put_buffer(void *opaque, uint8_t *data, int64_t pos, int size)
{
    MigrationState *s = opaque;

    assert((size + s->ft_dev->ft_dev_put_off) <= CUJU_FT_DEV_INIT_BUF);

    memcpy(s->ft_dev->ft_dev_buf + s->ft_dev->ft_dev_put_off, data, size);
    s->ft_dev->ft_dev_put_off += size;

    printf("%s put %d now %d\n", __func__, (int)size, (int)s->ft_dev->ft_dev_put_off);

    if (s->ft_dev->ft_dev_file->free_buf_on_flush)
        g_free((void *)data);

    return size;
}
*/

static ssize_t cuju_ft_dev_writev_buffer(void *opaque, struct iovec *iov, int iovcnt,
                                   int64_t pos)
{
    MigrationState *s = opaque;
    ssize_t done = 0;

    for(int i = 0; i < iovcnt; i++) {
        size_t len = iov[i].iov_len;
        uint8_t *data = iov[i].iov_base;

        assert((len + s->ft_dev->ft_dev_put_off) <= CUJU_FT_DEV_INIT_BUF);

        memcpy(s->ft_dev->ft_dev_buf + s->ft_dev->ft_dev_put_off, data, len);
        s->ft_dev->ft_dev_put_off += len;

        if (s->ft_dev->ft_dev_file->free_buf_on_flush)
            g_free((void *)data);

        done += len;
    }
    return done;
}

static const QEMUFileOps cuju_ft_dev_output_ops = {
    //.put_buffer = cuju_ft_dev_put_buffer,
    .writev_buffer = cuju_ft_dev_writev_buffer,
};

void alloc_ft_dev(MigrationState *s)
{
    s->ft_dev = g_malloc0(sizeof (struct CUJUFTDev));
    assert(s->ft_dev);

    s->ft_dev->ft_dev_file = qemu_fopen_ops(s,
                                    &cuju_ft_dev_output_ops);
    s->ft_dev->ft_dev_buf = g_malloc(CUJU_FT_DEV_INIT_BUF);
    assert(s->ft_dev->ft_dev_buf);
    s->ft_dev->ft_dev_put_off = 0;
    s->ft_dev->ft_dev_file->free_buf_on_flush = true;
}

int migrate_save_device_states_to_memory_advanced(void *opaque, int more)
{
    MigrationState *s = opaque;
    int ret = -1;

    do {
        if ((ret = qemu_savevm_trans_complete_precopy_advanced(s->ft_dev, more)) < 0) {
            fprintf(stderr, "qemu_savevm_trans_complete_advanced failed %d\n", ret);
            abort();
            goto out;
        }

        if (ret == 0) {
          goto out;
        }

        if (ret) {
            /* don't proceed until if fd isn't ready */
            ret = 1;
            goto out;
        }
    } while (1);

out:
    if (ret == 0) {
        // make sure all go to memory.
        qemu_fflush(s->ft_dev->ft_dev_file);
    }
    return ret;
}

static void cuju_ft_trans_incoming(void *opaque)
{
    QEMUFile *f = opaque;

    qemu_file_get_notify(f);
    if (qemu_file_get_error(f)) {
        cuju_ft_mode = CUJU_FT_ERROR;
        qemu_fclose(f);
    }
}

int cuju_get_fd_from_QIOChannel(QIOChannel *ioc) {
    QIOChannelSocket *sioc = QIO_CHANNEL_SOCKET(ioc);
    return sioc->fd;
}

static QEMUFile *cuju_setup_slave_receiver(int s, QEMUFile *devf, QEMUFile *ramf)
{
    QEMUFile *f;
    int dev_fd = cuju_get_fd_from_QIOChannel(devf->opaque);
    int ram_fd = cuju_get_fd_from_QIOChannel(ramf->opaque);

    f = cuju_qemu_fopen_ft_trans(s, dev_fd, ram_fd, -1);
    assert(f != NULL);

    qemu_set_nonblock(dev_fd);
    qemu_set_fd_handler(dev_fd, cuju_ft_trans_incoming, NULL, f);

    qemu_set_nonblock(ram_fd);
    qemu_set_fd_handler(ram_fd, cuju_ft_trans_read_pages, NULL, f->opaque);

    return f;
}

void *cuju_process_incoming_thread(void *opaque)
{
    MigrationIncomingState *mis = opaque;
    QEMUFile **fs = mis->cuju_file;
   	QEMUFile *f, *f2;
	int s = qio_ft_sock_fd;

    cuju_ft_trans_init();

	f = cuju_setup_slave_receiver(s, fs[0], fs[2]);
	f2 = cuju_setup_slave_receiver(s, fs[1], fs[3]);

	// need to wait sender to setup
	// send ack
    int ret;
    do {
        ret = qemu_ft_trans_begin(f);
    } while (ret == -EAGAIN);
    printf("%s qemu_ft_trans_begin returns %d\n", __func__, ret);
    if (ret < 0)
        goto out;

    cuju_ft_mode = CUJU_FT_TRANSACTION_RECV;

    qemu_mutex_init(&cuju_load_mutex);
    qemu_cond_init(&cuju_load_cond);

    cuju_ft_trans_set(0, f->opaque);
    cuju_ft_trans_set(1, f2->opaque);

	return NULL;

out:
	qemu_coroutine_enter(mis->cuju_incoming_co);
    return NULL;
}

static void gft_reset_bitmaps_commit2(MigrationState *s)
{
    MigrationJoinConn *conn;
    int i;
    FTPRINTF("%s(%lf) %d\n", __func__, time_in_double(), migrate_get_index(s));
    for (i = 0; i < MIG_MAX_JOIN; ++i) {
        conn = &s->join.conn[i];
        if (conn->r_sock) {
            clear_bit(conn->gft_id, &s->join.bitmaps_commit2);
        }
    }
}

static void gft_reset_bitmaps_snapshot(MigrationState *s)
{
    MigrationJoinConn *conn;
    int i;
    FTPRINTF("%s(%lf) %d\n", __func__, time_in_double(), migrate_get_index(s));
    for (i = 0; i < MIG_MAX_JOIN; ++i) {
        conn = &s->join.conn[i];
        if (conn->r_sock) {
            clear_bit(conn->gft_id, &s->join.bitmaps_snapshot_started);
        }
    }
}

static bool gft_can_run(MigrationState *s)
{
    MigrationState *p = migrate_get_previous(s);
    if (p->join.bitmaps_snapshot_started != ~0) {
        s->join.wait_group_snapshot_start = true;
        FTPRINTF("%s(%lf) %d can't run, has to wait pre-snap %lx\n", __func__, time_in_double(), s->cur_off, p->join.bitmaps_snapshot_started);
        return false;
    }
    if (s->join.bitmaps_commit2 != ~0) {
        s->join.wait_group_commit2 = true;
        FTPRINTF("%s(%lf) %d can't run, has to wait commit2 %lx\n", __func__, time_in_double(), s->cur_off, s->join.bitmaps_commit2);
        return false;
    }
    gft_reset_bitmaps_snapshot(p);
    gft_reset_bitmaps_commit2(s);
    FTPRINTF("%s(%lf) %d run\n", __func__, time_in_double(), s->cur_off);
    return true;
}

static void migrate_run(MigrationState *s)
{
    static unsigned long run_serial = 0;

    FTPRINTF("%s %d\n", __func__, s->cur_off);

    if (migrate_token_owner != s || s->ft_state != CUJU_FT_TRANSACTION_PRE_RUN) {
        FTPRINTF("%s cant run own != s ? %d ft_state == %d\n", __func__,
            migrate_token_owner != s, s->ft_state);
        return;
    }

    if (!gft_can_run(s))
        return;

    migrate_set_ft_state(s, CUJU_FT_TRANSACTION_RUN);
    s->run_serial = ++run_serial;

    kvmft_reset_put_off(s);
    assert(!kvm_shmem_flip_sharing(s->cur_off));

    migrate_schedule(s);

    event_tap_start_epoch(s->ft_event_tap_net_list,
        s->ft_event_tap_list, NULL, NULL);

    cuju_qemu_set_last_cmd(s->file, CUJU_QEMU_VM_TRANSACTION_BEGIN);

    qemu_iohandler_ft_pause(false);
    vm_start_mig();

    s->run_real_start_time = time_in_double();
    s->join.state = GFT_EPOCH_COMMIT;

#ifdef CONFIG_EPOCH_OUTPUT_TRIGGER
    kvmft_output_notified = 0;
#else
    kvm_shmem_start_timer();
    if (s->epoch_timer_pending) {
        s->epoch_timer_pending = false;
        kvmft_fire_timer(s->cur_off);
        // FTPRINTF("%s fire timer %d\n", __func__, r);
    }
#endif
}

static void migrate_timer(void *opaque)
{
    static unsigned long trans_serial = 0;
    MigrationState *s = opaque;

    assert(s == migrate_get_current());

#ifndef ft_debug_mode_enable
    if ((trans_serial & 0x03f) == 0) {
        printf("\n%s tick %lu\n", __func__, trans_serial);
    }
#else
    printf("\n%s %p(%d) runstage(ms) %d\n", __func__, s, migrate_get_index(s),
        (int)((s->snapshot_start_time - s->run_real_start_time) * 1000));
#endif

    migrate_token_owner = NULL;

    s->trans_serial = ++trans_serial;

    qemu_mutex_lock_iothread();
    vm_stop_mig();
    qemu_iohandler_ft_pause(true);
    if (kvm_blk_session)
        kvm_blk_epoch_timer(kvm_blk_session);

    s->flush_vs_commit1 = false;
    s->transfer_start_time = time_in_double();
    s->ram_len = 0;
    kvm_shmem_send_dirty_kernel(s);

    dirty_page_tracking_logs_start_transfer(s);

    assert(!kvmft_write_protect_dirty_pages(s->cur_off));
    assert(!kvm_shm_clear_dirty_bitmap(s->cur_off));

    s->time_buf_off = sprintf(s->time_buf, "%p", s);
    s->time_buf_off += sprintf(s->time_buf+s->time_buf_off, "\t%.4lf\t%.4lf", s->run_real_start_time, (s->run_real_start_time-s->run_sched_time)*1000);
    s->time_buf_off += sprintf(s->time_buf+s->time_buf_off, "\t%.4lf", (s->snapshot_start_time-s->run_real_start_time)*1000);

    assert(kvm_shmem_collect_trackable_dirty() >= 0);
    assert(!migrate_save_device_states_to_memory_advanced(s, 0));
    s->virtio_blk_temp_list = virtio_blk_get_temp_list();       //temp_list
    kvm_shmem_trackable_dirty_reset();
    migrate_ft_trans_send_device_state_header(s->ft_dev, s->file);
    qemu_put_buffer(s->file, s->ft_dev->ft_dev_buf, s->ft_dev->ft_dev_put_off);
#ifdef ft_debug_mode_enable
    printf("device len: %d\n", s->ft_dev->ft_dev_put_off);
#endif

    s->ft_dev->ft_dev_put_off = 0;

    //qemu_fflush(s->file);
    //ft_trans_flush_buf_desc(s->file);

    migrate_set_ft_state(s, CUJU_FT_TRANSACTION_TRANSFER);

    gft_master_try_get_notify(s);

    qemu_bh_schedule(s->flush_bh);
    s->snapshot_finish_time = time_in_double();

    migrate_token_owner = migrate_get_next(s);
    migrate_token_owner->run_sched_time = time_in_double();
    FTPRINTF("%s invoke migrate_run\n", __func__);
    migrate_run(migrate_token_owner);
    qemu_mutex_unlock_iothread();
}

static void ft_tick_func(void)
{
    MigrationState *s;

    if (!migrate_token_owner)
        return;

    s = migrate_token_owner;
    if (s->ft_state != CUJU_FT_TRANSACTION_RUN)
        return;

    migrate_set_ft_state(s, CUJU_FT_TRANSACTION_SNAPSHOT);
    s->snapshot_start_time = time_in_double();

    gft_broadcast_snapshot_start(s);

    migrate_timer(s);
}

void kvmft_tick_func(void)
{
    FTPRINTF("\n\n%s %d\n", __func__, migrate_token_owner ?
        migrate_token_owner->cur_off : -1);

    if (!migrate_token_owner)
        return;

    ft_tick_func();
}

static int migrate_join_mac_to_array(const char *mac, char array[])
{
    int a[6];
    int read, i;

    read = sscanf(mac, "%x:%x:%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]);
    if (read != 6)
        return -1;
    for (i = 0; i < 6; ++i)
        array[i] = (char)a[i];

    return 0;
}

static MigrationJoinConn* gft_master_accept_other_master_one(MigrationState *s, int sd)
{
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int c, i, cmd, index = s->cur_off;
    QEMUFile *f;
    struct MigrationJoinConn *conn = NULL;

    printf("%s begin\n", __func__);

    // find spare one.
    for (i = 0; i < MIG_MAX_JOIN; ++i) {
        if (!s->join.conn[i].r_sock) {
            conn = &s->join.conn[i];
            break;
        }
    }
    if (i == MIG_MAX_JOIN) {
        printf("%s can't find free conn.\n", __func__);
        goto out;
    }

    /* their read first, write second. */
    do {
        c = qemu_accept(sd, (struct sockaddr *)&addr, &addrlen);
    } while (c == -1 && socket_error() == EINTR);

    if (c == -1) {
        printf("%s accept error.\n", __func__);
        goto out;
    }

    f = qemu_fopen_socket(c);
    if (f == NULL) {
        printf("%s can't open qemu_fopen_socket.\n", __func__);
        goto out;
    }
    conn->w_sock = c;
    conn->w_file = f;

    assert(recv(c, &index, sizeof(index), 0) == sizeof(index));
    assert(index == s->cur_off);
    index = s->cur_off;
    assert(send(c, &index, sizeof(index), 0) == sizeof(index));

    do {
        c = qemu_accept(sd, (struct sockaddr *)&addr, &addrlen);
    } while (c == -1 && socket_error() == EINTR);

    if (c == -1) {
        printf("%s accept error.\n", __func__);
        goto out;
    }

    f = qemu_fopen_socket(c);
    if (f == NULL) {
        printf("%s can't open qemu_fopen_socket.\n", __func__);
        goto out;
    }
    conn->r_sock = c;
    conn->r_file = f;

    assert(recv(c, &index, sizeof(index), 0) == sizeof(index));
    assert(index == s->cur_off);
    index = s->cur_off;
    assert(send(c, &index, sizeof(index), 0) == sizeof(index));

    conn->migrate = s;

    printf("%s accepted\n", __func__);

    // receive MIG_JOIN_GFT_NEW and gft_id
    assert(recv(conn->r_sock, &cmd, sizeof(cmd), 0) == sizeof(cmd));
    assert(cmd == MIG_JOIN_GFT_NEW);
    assert(recv(conn->r_sock, &conn->gft_id, sizeof(conn->gft_id), 0) == sizeof(conn->gft_id));

    printf("%s build connection between gft_id %d and %d\n",
            __func__, my_gft_id, conn->gft_id);

    clear_bit(conn->gft_id, &s->join.bitmaps_snapshot_started);
    clear_bit(conn->gft_id, &s->join.bitmaps_commit1);

    socket_set_nodelay(conn->w_sock);
    qemu_set_nonblock(conn->w_sock);
    qemu_set_nonblock(conn->r_sock);
    //qemu_set_fd_survive_ft_pause(conn->w_sock, true);

    printf("%s done\n", __func__);
    return conn;
out:
    printf("%s error.\n", __func__);
    if (conn) {
        conn->r_sock = 0;
        conn->w_sock = 0;
        // TODO..
    }
    return NULL;
}

static void gft_master_accept_other_master(void *opaque)
{
    MigrationState *s1 = migrate_by_index(0);
    MigrationState *s2 = migrate_by_index(1);
    MigrationJoinConn *conn1, *conn2;
    int sd = (int)(intptr_t)opaque;

    s1->cur_off = 0;
    s2->cur_off = 1;
    conn1 = gft_master_accept_other_master_one(s1, sd);
    conn2 = gft_master_accept_other_master_one(s2, sd);
    conn1->brother = conn2;
    conn2->brother = conn1;
    s1->join.number++;
    s2->join.number++;

    s1->join.state = GFT_EPOCH_COMMIT;
    s2->join.state = GFT_EPOCH_COMMIT;

    printf("%s accept %d.\n", __func__, s1->join.number);
}

static void gft_master_read_leader(void *opaque)
{
    int cmd, fd = (uintptr_t)opaque;
    assert(read(fd, &cmd, sizeof(cmd)) == sizeof(cmd));
    assert(cmd == MIG_JOIN_GFT_MIGRATION_ALL);
    qemu_set_fd_handler(fd, NULL, NULL, NULL);
    close(fd);
    group_ft_members_ready = group_ft_members_size;
    printf("%s %d\n", __func__, group_ft_members_ready);
}

static void gft_start_migration(void)
{
    int i;
    GroupFTMember *gm;
    char url[128];
    Error *err = NULL;

    for (i = 0; i < group_ft_members_size; ++i) {
        gm = &group_ft_members[i];
        if (my_gft_id == gm->gft_id)
            break;
    }
    assert(i < group_ft_members_size);

    cuju_ft_mode = CUJU_FT_INIT;
    sprintf(url, "tcp:%s:%d,ft_mode", gm->slave_host_ip,
            gm->slave_host_ft_port);
    qmp_migrate(url, false, false, false, false, false, false, true, true, &err);
}

// groupft leader sends out gft_add_host and gft_init,
// this function receives them on other group VMs.
static void gft_master_accept_leader(void *opaque)
{
    int server_fd = (uintptr_t) opaque;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int fd, i, j;
    int received, send;

    fd = qemu_accept(server_fd, (struct sockaddr *)&addr, &addr_len);
    if (fd == -1) {
        printf("%s accept error.\n", __func__);
        return;
    }
    printf("%s accepted GFT_INIT connection.\n", __func__);

    assert(read(fd, &received, sizeof(received)) == sizeof(received));
    if (received != MIG_JOIN_GFT_ADD_HOST) {
        printf("%s error command, expect MIG_JOIN_GFT_ADD_HOST.\n", __func__);
        goto err;
    }

    assert(read(fd, &received, sizeof(received)) == sizeof(received));
    if (received >= GROUP_FT_MEMBER_MAX || received <= 0) {
        printf("%s bad group_ft_members_size: %d\n", __func__, received);
        goto err;
    }
    group_ft_members_size = received;
    printf("%s group_ft_members_size = %d\n", __func__, group_ft_members_size);

    assert(read(fd, group_ft_members,
                sizeof(GroupFTMember)*group_ft_members_size)
            == sizeof(GroupFTMember)*group_ft_members_size);

    for (i = 0; i < group_ft_members_size; i++) {
        printf("%s GFT member: gft_id %d %s:%d\n", __func__,
            group_ft_members[i].gft_id,
            group_ft_members[i].master_host_ip,
            group_ft_members[i].master_host_gft_port);
        for (j = 0; j < MAC_LEN; j++)
            printf("%s MAC %02x\n", __func__, group_ft_members[i].master_mac[j]);
    }

    assert(read(fd, &received, sizeof(received)) == sizeof(received));
    if (received != MIG_JOIN_GFT_INIT) {
        printf("%s error command, expect MIG_JOIN_GFT_INIT.\n", __func__);
        goto err;
    }

    qemu_set_fd_handler(server_fd, NULL, NULL, NULL);
    qemu_set_fd_handler(server_fd,
                         gft_master_accept_other_master,
                         NULL,
                         (void *)(uintptr_t)server_fd);
    qemu_set_fd_survive_ft_pause(server_fd, true);

    send = MIG_JOIN_GFT_INIT_ACK;
    assert(write(fd, &send, sizeof(send)) == sizeof(send));

    group_ft_leader_sock = fd;
    qemu_set_nonblock(fd);
    qemu_set_fd_handler(fd, NULL, NULL, NULL);
    qemu_set_fd_handler(fd, gft_master_read_leader, NULL, (void *)(uintptr_t)fd);

    gft_start_migration();

    return;
err:
    close(fd);
    qemu_set_fd_handler(server_fd, NULL, NULL, NULL);
    close(server_fd);
}

int gft_init(int port)
{
    char host_port[32]; // format will be 0:4445
    Error *err = NULL;

    sprintf(host_port, "0:%d", port);
    SocketAddress* sa = socket_parse(host_port, &err);
    
    if (err) {
        error_report_err(err);
    }
    group_ft_master_sock = socket_listen(sa, &err);
    if (err) {
        error_report_err(err);
    }
    // group_ft_master_sock = inet_listen(host_port, NULL, 256, SOCK_STREAM, 0, &err);
    if (group_ft_master_sock <= 0)
        return -1;

    qemu_set_fd_handler(group_ft_master_sock,
                        gft_master_accept_leader,
                        NULL,
                        (void *)(uintptr_t)group_ft_master_sock);
    qemu_set_fd_survive_ft_pause(group_ft_master_sock, true);
    return 0;
}

static void gft_leader_broadcast_all_migration_done(void)
{
    int cmd, fd, i;
    cmd = MIG_JOIN_GFT_MIGRATION_ALL;
    for (i = 0; i < group_ft_members_size; i++) {
        fd = group_ft_sockets[i];
        if (fd) {
            assert(write(fd, &cmd, sizeof(cmd)) == sizeof(cmd));
            qemu_set_fd_handler(fd, NULL, NULL, NULL);
            close(fd);
            group_ft_sockets[i] = 0;
        }
    }
    FTPRINTF("%s\n", __func__);
}

static void gft_leader_read_master(void *opaque)
{
    int cmd, fd;
    fd = (uintptr_t)opaque;
    assert(read(fd, &cmd, sizeof(cmd)) == sizeof(cmd));
    assert(cmd == MIG_JOIN_GFT_MIGRATION_DONE);
    if (++group_ft_members_ready == group_ft_members_size)
        gft_leader_broadcast_all_migration_done();
    FTPRINTF("%s ready member %d total member %d\n", __func__, group_ft_members_ready, group_ft_members_size);
}

void qmp_gft_add_host(int gft_id,
                      const char *master_host_ip,
                      int master_host_gft_port,
                      const char *master_mac,
                      const char *slave_host_ip,
                      int slave_host_ft_port,
                      Error **errp)
{
    GroupFTMember *m = &group_ft_members_tmp[group_ft_members_size_tmp];
    if (group_ft_leader_inited) {
        printf("%s failed since gft already started.\n", __func__);
        return;
    }
    m->gft_id = gft_id;
    memcpy(m->master_host_ip, master_host_ip, IP_LEN);
    m->master_host_gft_port = master_host_gft_port;
    if (migrate_join_mac_to_array(master_mac, m->master_mac)) {
        printf("%s bad mac.\n", __func__);
        return;
    }
    memcpy(m->slave_host_ip, slave_host_ip, IP_LEN);
    m->slave_host_ft_port = slave_host_ft_port;
    group_ft_members_size_tmp++;
}

void qmp_gft_leader_init(Error **errp)
{
    Error *err = NULL;
    char host_port[32];
    int i;

    if (group_ft_leader_inited)
        return;
    group_ft_leader_inited = true;

    qemu_set_fd_handler(group_ft_master_sock, NULL, NULL, NULL);
    qemu_set_fd_handler(group_ft_master_sock,
                         gft_master_accept_other_master,
                         NULL,
                         (void *)(uintptr_t)group_ft_master_sock);

    // distribute group info to members
    for (i = 0; i < group_ft_members_size_tmp; ++i) {
        // connect to all master:gft_port and broadcase GroupFTMember list
        GroupFTMember *m = &group_ft_members_tmp[i];
        int sd, send;

        sprintf(host_port, "%s:%d", m->master_host_ip, m->master_host_gft_port);

        if (m->gft_id == my_gft_id) {
            group_ft_members_size = group_ft_members_size_tmp;
            memcpy(group_ft_members, group_ft_members_tmp,
                    sizeof(GroupFTMember) * group_ft_members_size);
            group_ft_sockets[i] = 0;
            continue;
        }

        sd = inet_connect(host_port, &err);
        if (err || sd == -1) {
            printf("%s error connect to %s.\n", __func__, host_port);
            return;
        }

        send = MIG_JOIN_GFT_ADD_HOST;
        assert(write(sd, &send, sizeof(send)) == sizeof(send));

        send = group_ft_members_size_tmp;
        assert(write(sd, &send, sizeof(send)) == sizeof(send));

        assert(write(sd, (const void *)group_ft_members_tmp,
                    sizeof(GroupFTMember)*group_ft_members_size_tmp)
                == sizeof(GroupFTMember)*group_ft_members_size_tmp);

        send = MIG_JOIN_GFT_INIT;
        assert(write(sd, &send, sizeof(send)) == sizeof(send));

        assert(read(sd, &send, sizeof(send)) == sizeof(send));
        if (send != MIG_JOIN_GFT_INIT_ACK) {
            printf("%s failed to receive MIG_JOIN_GFT_INIT_ACK from %s.\n",
                    __func__, host_port);
            return;
        }

        qemu_set_nonblock(sd);
        qemu_set_fd_handler(sd, NULL, NULL, NULL);
        qemu_set_fd_handler(sd, gft_leader_read_master, NULL, (void *)(uintptr_t)sd);

        group_ft_sockets[i] = sd;
    }

    gft_start_migration();
}

int gft_packet_can_send(const uint8_t *buf, int size)
{
    char *p = (char *)buf;
    MigrationState *s;
    MigrationJoin *join;
    MigrationJoinConn *conn;
    int i;
    GroupFTMember *gft_member;

    if (size < 14)
        return 0;

    //printf("%02x %02x %02x %02x %02x %02x\n", p[0], p[1], p[2], p[3], p[4], p[5]);

    if (p[0] == (char)0xff &&
        p[1] == (char)0xff &&
        p[2] == (char)0xff &&
        p[3] == (char)0xff &&
        p[4] == (char)0xff &&
        p[5] == (char)0xff &&
        p[12] == (char)0x08 &&
        p[13] == (char)0x06) {
        return 1;
    }

    s = migrate_get_current();
    join = &s->join;

    if (join->number == 0)
        return 0;

    for (i = 0; i < MIG_MAX_JOIN; ++i) {
        conn = &join->conn[i];
        if (conn->r_sock) {
            gft_member = &group_ft_members[conn->gft_id];
            char *pp = gft_member->master_mac;
            if (!memcmp(pp, p, 6))
                return 1;
        }
    }

    return 0;
}
