#ifndef GROUP_FT_H
#define GROUP_FT_H

#include "qemu-common.h"
#define GROUP_FT_MEMBER_MAX     100
#define MIG_MAX_JOIN    100
#define IP_LEN          16
#define MAC_LEN         6

enum GFT_STATUS{
    GFT_PRE = 0,
    GFT_START,
    GFT_WAIT,
};

/// This is the enum for GFT status, stored in MigrationState->join.state
enum MIG_JOIN_GFT_STATE{
 MIG_JOIN_GFT_ZERO               , ///< Simply used to maintain same numbering
 MIG_JOIN_GFT_NOT_READY              , ///< Unused
  /**
  * \enum MIG_JOIN_GFT_STATE :: MIG_JOINGFT_SNAPSHOT_START
  * \brief CMD send to before start of snapshot stage
  * broadcasted in ft_tick_func
  *
  * upon recv
  * set bit for bitmap_snapshot_started
  * if all started snapshot, if next MigrationState is ready to run,
  * set wait to false, and run next MigrationState
  */
 MIG_JOIN_GFT_SNAPSHOT_START              ,
 /**
  * \enum MIG_JOIN_GFT_STATE :: MIG_JOIN_GFT_EPOCH_COMMIT1
  * \brief CMD sent after end of transfer stage
  *  upon recving the cmd, bitmaps_commit1 == ~0,
  *  broadcast MIG_JOIN_GFT_EPOCH_COMMIT2
  */
 MIG_JOIN_GFT_EPOCH_COMMIT1          ,
 /**
  * \enum MIG_JOIN_GFT_STATE::MIG_JOIN_GFT_EPOCH_COMMIT
  * \breif MIG_JOIN_GFT_STATE block before start of next snapshot
  * set in migrate_run / gft_master_accept_other_master,
  *
  */
 MIG_JOIN_GFT_EPOCH_COMMIT                ,
 MIG_JOIN_GFT_EPOCH_SNAPSHOT_DONE, ///< Unused
 MIG_JOIN_GFT_INIT_UNUSED        , ///<Unused
 MIG_JOIN_GFT_ADD_HOST           , ///< CMD used to addhost, should be followed by group info
 MIG_JOIN_GFT_INIT               , ///< Paired with INIT_ACK, check connection
 MIG_JOIN_GFT_INIT_ACK           , ///< Paired with INIT, check connection
 MIG_JOIN_GFT_NEW                ,
 MIG_JOIN_GFT_MIGRATION_DONE     , ///< send to leader when ft_state is FT_INIT
 MIG_JOIN_GFT_MIGRATION_ALL      , ///< The final message from leader after recving MIGRATION_DONE from all members
 MIG_JOIN_GFT_EPOCH_COMMIT2      ,  ///< CMD bcast after recv COMMIT1 from all members, will run current MigrationState
 MIG_JOIN_GFT_ADDING_MEMBER      ,
 MIG_JOIN_GFT_READY_TO_RESYNC
};

typedef struct
{
    int32_t gft_id;
    char master_host_ip[IP_LEN];
    int32_t master_host_gft_port;
    char master_mac[MAC_LEN];
    char slave_host_ip[IP_LEN];
    int32_t slave_host_ft_port;
    int32_t slave_host_join_port;
} GroupFTMember;

typedef struct
{
    char slave_host_ip[IP_LEN];
    int32_t slave_host_gft_port;
    int32_t slave_incoming_port;
} GroupFTBackup;

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
