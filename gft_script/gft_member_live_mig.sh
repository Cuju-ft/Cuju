#!/bin/bash
MONITOR=/mnt/nfs/vm3.monitor
SLAVEIP=10.1.1.1
incomingPORT=4443

sudo echo "migrate_set_capability cuju-ft on" | sudo nc -U $MONITOR
sudo echo "gft_member_live_mig -d -c tcp:$SLAVEIP:$incomingPORT," | sudo nc -U $MONITOR
