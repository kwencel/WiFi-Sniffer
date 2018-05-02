INF=wlp2s0
ifconfig $INF down
iwconfig $INF mode managed
ifconfig $INF up
systemctl restart NetworkManager.service
