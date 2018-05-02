INF=wlp2s0
systemctl stop NetworkManager.service
ifconfig $INF down
iwconfig $INF mode monitor
ifconfig $INF up
