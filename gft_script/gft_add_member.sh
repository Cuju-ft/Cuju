#!/bin/sh
HOSTAIP=10.1.1.1
SLAVEIP=10.1.1.1
GFTPORT2=5004
SLAVEPORT=5005
MAC2=ae:ae:00:00:00:23
incomingPORT2=4443
FIRSTVMMon=/mnt/nfs/vm1.monitor

sudo echo "gft_add_member $HOSTAIP $GFTPORT2 $MAC2 $SLAVEIP $incomingPORT2" | sudo nc -U $FIRSTVMMon
