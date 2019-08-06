#!/bin/bash
MONITOR=/mnt/nfs/vm1.monitor
SLAVEIP=10.1.1.1
incomingPORT=4441

sudo echo "migrate_set_capability cuju-ft on" | sudo nc -U $MONITOR
sudo echo "migrate -d -c tcp:$SLAVEIP:$incomingPORT," | sudo nc -U $MONITOR
