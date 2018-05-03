# Cuju: An Open Source Project for Virtualization-Based Fault Tolerance

================================================================

Summary
-------
Virtualization technology could provide a unique benefit to protect any legacy application systems from hardware failures. The reliability of virtual machines running on virtualized servers is not only threatened by hardware failures beneath the whole virtual infrastructure, but also nosy hypervisors that essentially support virtual machines cannot be trusted.

We develop the opensource tool, Cuju, which is a virtualization based fault tolerance technique with epoch-based synchronization. There are several performance optimization technologies are applied by Cuju, including a non-stop/pipelined, continuously migration, dirty tracking for guest virtual memory/virtual device status, and eliminate data transfer between QEMU and KVM.

Cuju shows that these optimizations have greatly saved the processor usage, synchronization bandwidth and have significantly improved VM network throughput and latency at the same time.

For more information see: https://cuju-ft.github.io/cuju-web/home.html

Setup Execution Environment
-------

You can follow this document to setup the execution environment

https://cuju-ft.github.io/cuju-web/support.html


Build Cuju
-------

* Configure & Compile Cuju-ft

```
# cd Cuju
# ./configure --enable-cuju --enable-kvm --disable-pie --target-list=x86_64-softmmu
# make -j8

```

* Configure, Compile & insmod Cuju-kvm module

```
# cd Cuju/kvm
# ./configure
# make -j8
# ./reinsmodkvm.sh

```

Execute Cuju
-------

* Boot VM (on Primary Host)

```
# sudo ./x86_64-softmmu/qemu-system-x86_64 -drive if=none,id=drive0,cache=none,format=raw,file=/mnt/nfs/Ubuntu20G-1604.img -device virtio-blk,drive=drive0,scsi=off \
-m 1G -enable-kvm -net tap,ifname=tap0 -net nic,model=virtio,vlan=0,macaddr=ae:ae:00:00:00:25 -vga std \
-chardev socket,id=mon,path=/home/cujuft/vm1.monitor,server,nowait -mon chardev=mon,id=monitor,mode=readline

```

You need to change the guest image path (file=/mnt/nfs/Ubuntu20G-1604.img) and monitor path (path=/home/cujuft/vm1.monitor) for your environment


* Use VNC to see the console

```
# vncviewer :5900 &

```

The default account/password is root/root if you use we provide guest image

* Start Receiver (on Backup Host)

```
# sudo x86_64-softmmu/qemu-system-x86_64 -drive if=none,id=drive0,cache=none,format=raw,file=/mnt/nfs/Ubuntu20G-1604.img -device virtio-blk,drive=drive0,scsi=off \
-m 1G -enable-kvm -net tap,ifname=tap1 -net nic,model=virtio,vlan=0,macaddr=ae:ae:00:00:00:25 -vga std \
-chardev socket,id=mon,path=/home/cujuft/vm1r.monitor,server,nowait -mon chardev=mon,id=monitor,mode=readline -incoming tcp:0:4441,ft_mode

```

You need to follow Boot VM script to change the related parameter

or you can use following script to replace Receiver start script (if your VM start script is runvm.sh)

```
sed -e 's/mode=readline/mode=readline -incoming tcp\:0\:4441,ft_mode/g' -e 's/vm1.monitor/vm1r.monitor/g' -e 's/tap0/tap1/g' ./runvm.sh > tmp.sh
chmod +x ./tmp.sh
./tmp.sh

```

After VM boot and Receiver ready, you can execute following script to enter FT mode

```
# sudo echo "migrate_set_capability cuju-ft on" | sudo nc -U /home/cujuft/vm1.monitor
# sudo echo "migrate -d -c tcp:127.0.0.1:4441" | sudo nc -U /home/cujuft/vm1.monitor

```
You need to change the ip address and port (tcp:127.0.0.1:4441) for your environment, this is Backup Host's IP
And change the monitor path (/home/cujuft/vm1.monitor) for your environment


