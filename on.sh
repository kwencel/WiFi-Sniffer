if [ ! -z "$1" ]; then
    service NetworkManager stop > /dev/null 2>&1 || systemctl stop NetworkManager
    ifconfig $1 down
    iwconfig $1 mode monitor
    ifconfig $1 up
else
    echo "Usage: $0 <interface_name>"
fi