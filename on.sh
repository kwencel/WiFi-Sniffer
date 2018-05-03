if [ ! -z "$1" ]; then
    service NetworkManager stop
    ifconfig $1 down
    iwconfig $1 mode monitor
    ifconfig $1 up
fi