# Cuju: An Open Source Project for Virtualization-Based Fault Tolerance

================================================================

Summary
-------
Virtualization technology could provide a unique benefit to protect any legacy application systems from hardware failures. The reliability of virtual machines running on virtualized servers is not only threatened by hardware failures beneath the whole virtual infrastructure, but also nosy hypervisors that essentially support virtual machines cannot be trusted.

We develop the opensource tool, Cuju, which is a virtualization based fault tolerance technique with epoch-based synchronization. There are several performance optimization technologies are applied by Cuju, including a non-stop/pipelined, continuously migration, dirty tracking for guest virtual memory/virtual device status, and eliminate data transfer between QEMU and KVM.

Cuju shows that these optimizations have greatly saved the processor usage, synchronization bandwidth and have significantly improved VM network throughput and latency at the same time.

For more information see: https://cuju-ft.github.io/cuju-web/home.html

# Cuju Install Guide
## The environment prepare
---
### All Node Install
* Assume you have already builded Primary, Backup and NFS node.  
*A recommended topology below:*
![](https://i.imgur.com/DuKZweZ.png)

* If you only have one or two machine, you can reference this setting. 
*Another recommended topology below:*
![](https://i.imgur.com/38d0kzJ.png)

- Open the Intel virtualization support (VT-x) in your bios.
- Install OS in all nodes: [Ubuntu-16.04-desktop-amd64.iso (Ubuntu 16.04.0)](https://drive.google.com/file/d/0B9au9R9FzSWKUjRZclBXbXB0eEk/view)
- Install related packages in all nodes
```
 $ sudo apt-get update
 $ sudo apt-get install ssh vim gcc make gdb fakeroot build-essential \
kernel-package libncurses5 libncurses5-dev zlib1g-dev \
libglib2.0-dev qemu xorg bridge-utils openvpn vncviewer \
libssl-dev libpixman-1-dev nfs-common git
```
- Set up the bridge and network environment 
    - You can follow our recommended topology to set up the network environment 
    - The example of network interfaces set up below (edit your /etc/network/interfaces):
- NFS node
```
auto lo
iface lo inet loopback
auto eth0
iface eth0 inet static
address 192.168.11.1
netmask 255.255.255.0
gateway 192.168.11.254
dns-nameservers 8.8.8.8 
```

- Primary node

```
auto lo
iface lo inet loopback
auto br0
iface br0 inet static
bridge_ports eth0
bridge_maxwait 0
address 192.168.11.2
netmask 255.255.255.0
gateway 192.168.11.254
dns-nameservers 8.8.8.8
auto eth0
iface eth0 inet static
address 0.0.0.0
auto eth1
iface eth1 inet static
address 192.168.111.1
netmask 255.255.255.0
```
- Backup node
```
auto lo
iface lo inet loopback
auto br0
iface br0 inet static
bridge_ports eth0
bridge_maxwait 0
address 192.168.11.3
netmask 255.255.255.0
gateway 192.168.11.254
dns-nameservers 8.8.8.8
auto eth0
iface eth0 inet static
address 0.0.0.0
auto eth1
iface eth1 inet static
address 192.168.111.2
netmask 255.255.255.0 

```

- Build the high-speed connections (ex. 10G NIC) with Primary and Backup nodes by the eth1

- After editing these network interfaces, type "/etc/init.d/networking restart" or reboot

### NFS Node Setup

- Install the NFS service (Network FileSystem) in NFS node; then create a NFS folder placing the VM image
```
 $ sudo apt-get install nfs-kernel-server
```
- Insert this line in "/etc/exports" to add your NFS folder: 
```
 /home/[your username]/nfsfolder *(rw,no_root_squash,no_subtree_check) 
```
- After editing /etc/exports, type "/etc/init.d/nfs-kernel-server restart" or reboot

- Go to your nfs folder, then download [Cuju](https://github.com/Cuju-ft/Cuju) and build a VM image file (or download our [Ubuntu-16.04 VM image](https://drive.google.com/file/d/0B9au9R9FzSWKNjZpWUNlNDZLcEU/view?usp=sharing) file, the account/password is root/root), they will be synced with Primary and Backup node.

### Primary and Backup Node Setup
- Mount the NFS folder
```
$ mkdir /mnt/nfs
$ mount -t nfs 192.168.11.1:/home/[your username]/nfsfolder /mnt/nfs
```
## Build Cuju
---
* Clone Cuju on your NFS folder from Github
```
$ cd /mnt/nfs
$ git clone https://github.com/Cuju-ft/Cuju.git
```
* Configure & Compile Cuju-ft

```
$ cd Cuju
$ ./configure --enable-cuju --enable-kvm --disable-pie --target-list=x86_64-softmmu
$ make -j8

```

* Configure, Compile & insmod Cuju-kvm module

```
$ cd Cuju/kvm
$ ./configure
$ make -j8
$ ./reinsmodkvm.sh

```

Execute Cuju
-------
* Before launching your VM, you should update kvm module in Primary and Backup nodes: 
```
$ cd /mnt/nfs/Cuju/kvm
$ ./reinsmodkvm.sh
```

* Boot VM (on Primary Host)

```rumvm.sh```

```
sudo ./x86_64-softmmu/qemu-system-x86_64 \
-drive if=none,id=drive0,cache=none,format=raw,file=/mnt/nfs/Ubuntu20G-1604.img \
-device virtio-blk,drive=drive0 \
-m 1G -enable-kvm \
-net tap,ifname=tap0 -net nic,model=virtio,vlan=0,macaddr=ae:ae:00:00:00:25 \
-vga std -chardev socket,id=mon,path=/home/cujuft/vm1.monitor,server,nowait -mon chardev=mon,id=monitor,mode=readline

```

You need to change the guest image path (file=/mnt/nfs/Ubuntu20G-1604.img) and monitor path (path=/home/cujuft/vm1.monitor) for your environment


* Use VNC to see the console

```
$ vncviewer :5900 &

```

The default account/password is root/root if you use we provide guest image

* Start Receiver (on Backup Host)
```recv.sh```
```
sudo x86_64-softmmu/qemu-system-x86_64 \
-drive if=none,id=drive0,cache=none,format=raw,file=/mnt/nfs/Ubuntu20G-1604.img \
-device virtio-blk,drive=drive0 \
-m 1G -enable-kvm \
-net tap,ifname=tap1 -net nic,model=virtio,vlan=0,macaddr=ae:ae:00:00:00:25 \
-vga std -chardev socket,id=mon,path=/home/cujuft/vm1r.monitor,server,nowait -mon chardev=mon,id=monitor,mode=readline \
-incoming tcp:0:4441,ft_mode

```

You need to follow Boot VM script to change the related parameter
or you can use following script to replace Receiver start script (if your VM start script is runvm.sh)
```recv.sh```

```
sed -e 's/mode=readline/mode=readline -incoming tcp\:0\:4441,ft_mode/g' -e 's/vm1.monitor/vm1r.monitor/g' -e 's/tap0/tap1/g' ./runvm.sh > tmp.sh
chmod +x ./tmp.sh
./tmp.sh

```

After VM boot and Receiver ready, you can execute following script to enter FT mode
```ftmode.sh```
```
sudo echo "migrate_set_capability cuju-ft on" | sudo nc -U /home/cujuft/vm1.monitor
sudo echo "migrate -d -c tcp:127.0.0.1:4441" | sudo nc -U /home/cujuft/vm1.monitor

```
You need to change the ip address and port (tcp:127.0.0.1:4441) for your environment, this is Backup Host's IP
And change the monitor path (/home/cujuft/vm1.monitor) for your environment

* If you successfully start Cuju, you will see the following message show on Primary side:
![](https://i.imgur.com/nUdwKkB.jpg)

