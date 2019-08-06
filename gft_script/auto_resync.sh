#!/bin/bash
BACKUP_MONITOR=vm3r.monitor
SLAVEIP=10.1.1.1
incomingPORT=4444

sudo echo "migrate_set_capability cuju-ft on" | sudo nc -U $BACKUP_MONITOR
sudo echo "gft_add_backup $SLAVEIP $incomingPORT" | sudo nc -U $BACKUP_MONITOR

