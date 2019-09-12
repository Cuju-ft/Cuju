sudo echo "migrate_set_capability cuju-ft on" | sudo nc -U /home/howard/vm1.monitor
sudo echo "migrate -c tcp:localhost:4441" | sudo nc -U /home/howard/vm1.monitor
