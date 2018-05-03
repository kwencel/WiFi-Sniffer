if [ ! -z "$1" ]; then
    ifconfig $1 down
    iwconfig $1 mode managed
    ifconfig $1 up
    service NetworkManager start
fi
