#!/bin/sh
HOSTAIP=10.1.1.1
#HOSTBIP=10.1.1.15
SLAVEIP=10.1.2.101
#SLAVEIP=10.1.1.101
GFTPORT0=5000 #-ft-join-port
GFTPORT1=5002
GFTPORT2=5004
GFTPORT3=5006
MAC0=ae:ae:00:00:00:21
MAC1=ae:ae:00:00:00:22
MAC2=ae:ae:00:00:00:23
MAC3=ae:ae:00:00:00:24
incomingPORT0=4441
incomingPORT1=4442
incomingPORT2=4443
incomingPORT3=4444
FIRSTVMMon=/mnt/nfs/vm1.monitor
sudo echo "gft_add_host 0 $HOSTAIP $GFTPORT0 $MAC0 $SLAVEIP $incomingPORT0" | sudo nc -U $FIRSTVMMon
#sudo echo "gft_add_host 0 $SLAVEIP $GFTPORT0 $MAC0 $HOSTAIP $incomingPORT0" | sudo nc -U $FIRSTVMMon
sudo echo "gft_add_host 1 $HOSTAIP $GFTPORT1 $MAC1 $SLAVEIP $incomingPORT1" | sudo nc -U $FIRSTVMMon
sudo echo "gft_add_host 2 $HOSTAIP $GFTPORT2 $MAC2 $SLAVEIP $incomingPORT2" | sudo nc -U $FIRSTVMMon
#sudo echo "gft_add_host 3 $HOSTAIP $GFTPORT3 $MAC3 $SLAVEIP $incomingPORT3" | sudo nc -U $FIRSTVMMon
#sudo echo "gft_add_backup $SLAVEIP $incomingPORT3" | sudo nc -U $FIRSTVMMon
