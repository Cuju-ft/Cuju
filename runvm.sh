sudo ./x86_64-softmmu/qemu-system-x86_64 \
-drive if=none,id=drive0,cache=none,format=raw,file=/home/howard/Downloads/Ubuntu20G-1604.img \
-device virtio-blk,drive=drive0 \
-m 1G -enable-kvm \
-net tap,ifname=tap0 -net nic,model=virtio,vlan=0,macaddr=ae:ae:00:00:00:25 \
-cpu host \
-vga std -chardev socket,id=mon,path=/home/howard/vm1.monitor,server,nowait -mon chardev=mon,id=monitor,mode=readline
