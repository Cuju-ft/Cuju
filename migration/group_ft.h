#ifndef GROUP_FT_H
#define GROUP_FT_H

#include "qemu-common.h"

#define MIG_MAX_JOIN    5
#define IP_LEN          16
#define MAC_LEN         6

#define MIG_JOIN_NOT_READY              0x01
#define GFT_SNAPSHOT_START              0x02
#define MIG_JOIN_EPOCH_COMMIT1          0x03
#define GFT_EPOCH_COMMIT                0x04
#define MIG_JOIN_EPOCH_SNAPSHOT_DONE    0x05
#define MIG_JOIN_INIT                   0x06
#define MIG_JOIN_GFT_ADD_HOST           0x07
#define MIG_JOIN_GFT_INIT               0x08
#define MIG_JOIN_GFT_INIT_ACK           0x09
#define MIG_JOIN_GFT_NEW                0x0a
#define MIG_JOIN_GFT_MIGRATION_DONE     0x0b
#define MIG_JOIN_GFT_MIGRATION_ALL      0x0c
#define MIG_JOIN_EPOCH_COMMIT2          0x0d

typedef struct
{
    int32_t gft_id;
    char master_host_ip[IP_LEN];
    int32_t master_host_gft_port;
    char master_mac[MAC_LEN];
    char slave_host_ip[IP_LEN];
    int32_t slave_host_ft_port;
} GroupFTMember;

typedef struct MigrationJoinConn
{
    int gft_id;
    int r_sock;   // this conn is invalid if zero.
    int w_sock;   // this conn is invalid if zero.
    int last_sent;  // if we already sent epoch, avoid duplicate sending.
    int last_recv;
    void *migrate;
    QEMUFile *r_file;
    QEMUFile *w_file;
    void *brother;
} MigrationJoinConn;

typedef struct MigrationJoin
{
    unsigned long bitmaps_snapshot_started;
    unsigned long bitmaps_commit1;
    unsigned long bitmaps_commit2;
    unsigned int number;
    unsigned int state;
    bool wait_group_snapshot_start;
    bool wait_group_transfer_done;
    bool wait_group_commit2;
    QemuMutex mutex;
    QemuCond cond;
    struct MigrationJoinConn conn[MIG_MAX_JOIN];
} MigrationJoin;

#endif
