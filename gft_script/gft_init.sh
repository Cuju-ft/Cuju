#!/bin/sh
FIRSTVMMon=/mnt/nfs/vm1.monitor
SENVMMon=/mnt/nfs/vm2.monitor
THIRDVMMon=/mnt/nfs/vm3.monitor
FOURTHVMMon=/mnt/nfs/vm4.monitor
sudo echo "migrate_set_capability cuju-ft on" | sudo nc -U $FIRSTVMMon
sudo echo "migrate_set_capability cuju-ft on" | sudo nc -U $SENVMMon
sudo echo "migrate_set_capability cuju-ft on" | sudo nc -U $THIRDVMMon
sudo echo "migrate_set_capability cuju-ft on" | sudo nc -U $FOURTHVMMon
sudo echo "gft_init" | sudo nc -U $FIRSTVMMon
