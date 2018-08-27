/*
 * QEMU live migration via socket
 *
 * Copyright Red Hat, Inc. 2009-2016
 *
 * Authors:
 *  Chris Lalancette <clalance@redhat.com>
 *  Daniel P. Berrange <berrange@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu/osdep.h"

#include "qemu-common.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "migration/migration.h"
#include "migration/qemu-file.h"
#include "migration/cuju-ft-trans-file.h"
#include "io/channel-socket.h"
#include "trace.h"
#include "sysemu/sysemu.h"

//#define DEBUG_MIGRATION_TCP

#ifdef DEBUG_MIGRATION_TCP
#define DPRINTF(fmt, ...) \
    do { printf("migration-tcp: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

static char* slave_host_port;
extern enum GFT_STATUS gft_status ;

static void backup_slave_host_port(const char *host_port)
{
    int len = strlen(host_port);

    slave_host_port = g_malloc0(len);
    memcpy(slave_host_port, host_port, len);
}

//static char* get_slave_host_port(void)
//{
//    return slave_host_port;
//}

static int socket_errno(MigrationState *s)
{
    return socket_error();
}

static int socket_write(MigrationState *s, const void * buf, size_t size)
{
    //printf("%s %d\n", __func__, size);
    return send(s->fd, buf, size, 0);
}

static int socket_read(MigrationState *s, const void * buf, size_t size)
{
    ssize_t len;

    do {
        len = recv(s->fd, (void *)buf, size, 0);
    } while (len == -1 && socket_error() == EINTR);
    if (len == -1) {
        len = -socket_error();
    }

    return len;
}

static int tcp_close(MigrationState *s)
{
    int r = 0;
    DPRINTF("tcp_close\n");
    /* FIX ME: accessing ft_mode here isn't clean */
    if (s->fd != -1 && cuju_ft_mode != CUJU_FT_INIT) {
        if (close(s->fd) < 0) {
            r = -errno;
        }
        s->fd = -1;
    }
    return r;
}

static SocketAddress *tcp_build_address(const char *host_port, Error **errp)
{
    InetSocketAddress *iaddr = inet_parse(host_port, errp);
    SocketAddress *saddr;

    if (!iaddr) {
        return NULL;
    }

    saddr = g_new0(SocketAddress, 1);
    saddr->type = SOCKET_ADDRESS_KIND_INET;
    saddr->u.inet.data = iaddr;

    return saddr;
}


static SocketAddress *unix_build_address(const char *path)
{
    SocketAddress *saddr;

    saddr = g_new0(SocketAddress, 1);
    saddr->type = SOCKET_ADDRESS_KIND_UNIX;
    saddr->u.q_unix.data = g_new0(UnixSocketAddress, 1);
    saddr->u.q_unix.data->path = g_strdup(path);

    return saddr;
}


struct SocketConnectData {
    MigrationState *s;
    char *hostname;
};

static void socket_connect_data_free(void *opaque)
{
    struct SocketConnectData *data = opaque;
    if (!data) {
        return;
    }
    g_free(data->hostname);
    g_free(data);
}

static void socket_outgoing_migration(Object *src,
                                      Error *err,
                                      gpointer opaque)
{
    struct SocketConnectData *data = opaque;
    QIOChannel *sioc = QIO_CHANNEL(src);

    if (err) {
        trace_migration_socket_outgoing_error(error_get_pretty(err));
        data->s->to_dst_file = NULL;
        migrate_fd_error(data->s, err);
    } else {
        trace_migration_socket_outgoing_connected(data->hostname);
        migration_channel_connect(data->s, sioc, data->hostname);
    }
    object_unref(src);
}

static void socket_start_outgoing_migration(MigrationState *s,
                                            SocketAddress *saddr,
                                            Error **errp)
{
    QIOChannelSocket *sioc = qio_channel_socket_new();
    struct SocketConnectData *data = g_new0(struct SocketConnectData, 1);

    data->s = s;
    if (saddr->type == SOCKET_ADDRESS_KIND_INET) {
        data->hostname = g_strdup(saddr->u.inet.data->host);
    }

    qio_channel_set_name(QIO_CHANNEL(sioc), "migration-socket-outgoing");
    qio_channel_socket_connect_async(sioc,
                                     saddr,
                                     socket_outgoing_migration,
                                     data,
                                     socket_connect_data_free);
    qapi_free_SocketAddress(saddr);
}

static void cuju_socket_start_outgoing_migration(MigrationState *s,
                                            SocketAddress *saddr,
                                            Error **errp)
{
    MigrationState *s2 = migrate_by_index(1);
    QIOChannelSocket *sioc[4];
    const char *channel_name[4] = {"cuju-dev-outgoing1", "cuju-ram-outgoing1", "cuju-dev-outgoing2", "cuju-ram-outgoing2"};
    struct SocketConnectData *data[4];
    for (int i=0; i<4; i++) {
        sioc[i] = qio_channel_socket_new();
        data[i] = g_new0(struct SocketConnectData, 1);
        data[i]->s = s;
        if (saddr->type == SOCKET_ADDRESS_KIND_INET) {
            data[i]->hostname = g_strdup(saddr->u.inet.data->host);
        }
        qio_channel_set_name(QIO_CHANNEL(sioc[i]), channel_name[i]);
        //use qio_channel_socket_connect_sync instead of qio_channel_socket_connect_async here
        Error *local_err = NULL;
        qio_channel_socket_connect_sync(sioc[i], saddr, &local_err);
        if (local_err) {
            trace_migration_socket_outgoing_error(error_get_pretty(local_err));
            data[i]->s->to_dst_file = NULL;
            migrate_fd_error(data[i]->s, local_err);
            error_propagate(errp, local_err);
            goto out;
        }
        trace_migration_socket_outgoing_connected(data[i]->hostname);
		#ifdef ft_debug_mode_enable
        printf("%s connected\n", channel_name[i]);
		#endif
    }

    s->get_error = socket_errno;
    s->write = socket_write;
    s->read = socket_read;
    s->close = tcp_close;
    s2->get_error = socket_errno;
    s2->write = socket_write;
    s2->read = socket_read;
    s2->close = tcp_close;

    cuju_migration_channel_connect(data[0]->s, sioc, data[0]->hostname);
out:
    for (int i=0; i<4; i++) {
        object_unref(OBJECT(sioc[i]));
        socket_connect_data_free(data[i]);
    }
    qapi_free_SocketAddress(saddr);
}

void tcp_start_outgoing_migration(MigrationState *s,
                                  const char *host_port,
                                  Error **errp)
{
    Error *err = NULL;
    SocketAddress *saddr = tcp_build_address(host_port, &err);
    if (!err) {
        socket_start_outgoing_migration(s, saddr, &err);
    }
    error_propagate(errp, err);
}

void cuju_tcp_start_outgoing_migration(MigrationState *s,
                                  const char *host_port,
                                  Error **errp)
{
    backup_slave_host_port(host_port);

    if(gft_status != GFT_WAIT){
        Error *err = NULL;
        SocketAddress *saddr = tcp_build_address(host_port, &err);
        if (!err) {
            cuju_socket_start_outgoing_migration(s, saddr, &err);
        }
        error_propagate(errp, err);
    }
}
void unix_start_outgoing_migration(MigrationState *s,
                                   const char *path,
                                   Error **errp)
{
    SocketAddress *saddr = unix_build_address(path);
    socket_start_outgoing_migration(s, saddr, errp);
}


static gboolean socket_accept_incoming_migration(QIOChannel *ioc,
                                                 GIOCondition condition,
                                                 gpointer opaque)
{
    QIOChannelSocket *sioc;
    Error *err = NULL;

    sioc = qio_channel_socket_accept(QIO_CHANNEL_SOCKET(ioc),
                                     &err);
    if (!sioc) {
        error_report("could not accept migration connection (%s)",
                     error_get_pretty(err));
        goto out;
    }

    trace_migration_socket_incoming_accepted();

    qio_channel_set_name(QIO_CHANNEL(sioc), "migration-socket-incoming");
    migration_channel_process_incoming(migrate_get_current(),
                                       QIO_CHANNEL(sioc));
    object_unref(OBJECT(sioc));

out:
    /* Close listening socket as its no longer needed */
    qio_channel_close(ioc, NULL);
    return FALSE; /* unregister */
}


static void socket_start_incoming_migration(SocketAddress *saddr,
                                            Error **errp)
{
    QIOChannelSocket *listen_ioc = qio_channel_socket_new();

    qio_channel_set_name(QIO_CHANNEL(listen_ioc),
                         "migration-socket-listener");

    if (qio_channel_socket_listen_sync(listen_ioc, saddr, errp) < 0) {
        object_unref(OBJECT(listen_ioc));
        qapi_free_SocketAddress(saddr);
        return;
    }

    qio_channel_add_watch(QIO_CHANNEL(listen_ioc),
                          G_IO_IN,
                          socket_accept_incoming_migration,
                          listen_ioc,
                          (GDestroyNotify)object_unref);
    qapi_free_SocketAddress(saddr);
}

void tcp_start_incoming_migration(const char *host_port, Error **errp)
{
    Error *err = NULL;
    SocketAddress *saddr = tcp_build_address(host_port, &err);
    if (!err) {
        socket_start_incoming_migration(saddr, &err);
    }
    error_propagate(errp, err);
}

void unix_start_incoming_migration(const char *path, Error **errp)
{
    SocketAddress *saddr = unix_build_address(path);
    socket_start_incoming_migration(saddr, errp);
}

static gboolean cuju_socket_accept_incoming_migration(QIOChannel *ioc,
                                                 GIOCondition condition,
                                                 gpointer opaque)
{
    QIOChannelSocket *sioc[4];
    Error *err = NULL;
    const char *channel_name[4] = {"cuju-dev-incoming1", "cuju-ram-incoming1",
                                "cuju-dev-incoming2", "cuju-ram-incoming2"};

    for (int i=0; i<4; i++) {
        sioc[i] = qio_channel_socket_accept(QIO_CHANNEL_SOCKET(ioc),
                                     &err);
        if (!sioc[i]) {
            error_report("could not accept migration connection (%s)",
                        error_get_pretty(err));
            goto out;
        }
        trace_cuju_migration_socket_incoming_accepted(i);

        qio_channel_set_name(QIO_CHANNEL(sioc[i]), channel_name[i]);
		#ifdef ft_debug_mode_enable
        printf("socket %d connected\n", i);
		#endif
    }

    cuju_migration_channel_process_incoming(migrate_get_current(),
                                       sioc);
    object_unref(OBJECT(sioc));

out:
    // Close listening socket as its no longer needed
    qio_channel_close(ioc, NULL);
    return FALSE; // unregister
}

static void cuju_socket_start_incoming_migration(SocketAddress *saddr,
                                            Error **errp)
{
    QIOChannelSocket *listen_ioc = qio_channel_socket_new();

    qio_channel_set_name(QIO_CHANNEL(listen_ioc),
                         "cuju-socket-listener");

    if (qio_channel_socket_listen_sync(listen_ioc, saddr, errp) < 0) {
        object_unref(OBJECT(listen_ioc));
        qapi_free_SocketAddress(saddr);
        return;
    }

	qio_ft_sock_fd = listen_ioc->fd;

    qio_channel_add_watch(QIO_CHANNEL(listen_ioc),
                          G_IO_IN,
                          cuju_socket_accept_incoming_migration,
                          listen_ioc,
                          (GDestroyNotify)object_unref);
    qapi_free_SocketAddress(saddr);
}


void cuju_tcp_start_incoming_migration(const char *host_port, Error **errp)
{
    Error *err = NULL;
    SocketAddress *saddr = tcp_build_address(host_port, &err);
    if (!err) {
        cuju_socket_start_incoming_migration(saddr, &err);
    }
    error_propagate(errp, err);
}
