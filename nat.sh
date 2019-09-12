#sudo iptables --flush
#sudo iptables --table nat --delete-chain
sudo sysctl -w net.ipv4.ip_forward=1
#sudo iptables -t nat -A POSTROUTING -d 192.168.123.0/24 -o bridge0 -s 140.96.29.0/24 -j MASQUERADE
sudo iptables -t nat -A PREROUTING -i bridge0
sudo iptables -t nat -A POSTROUTING -o enp2s0 -j MASQUERADE
#sudo iptables -A FORWARD -i 192.168.123.5 -j ACCEPT
echo "1" | sudo tee /proc/sys/net/ipv4/ip_forward
sudo ifconfig bridge0:0 192.168.123.5
#sudo iptables -A FORWARD -i 192.168.123.5 -j ACCEPT
sudo service networking restart
