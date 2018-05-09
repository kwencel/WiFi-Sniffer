if [ ! -z "$1" ]; then
    ifconfig $1 down
    iwconfig $1 mode managed
    ifconfig $1 up
    service NetworkManager start > /dev/null 2>&1 || systemctl start NetworkManager
else
    echo "Usage: $0 <interface_name>"
fi
