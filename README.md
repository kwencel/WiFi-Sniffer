# WiFi Sniffer

This project analyses IEEE 802.11 frame headers to establish a sender, recipient and an intermediary
[access point (AP)](https://en.wikipedia.org/wiki/Wireless_access_point).

The program periodically outputs the information it gathered so far about:
* [stations (STA)](https://en.wikipedia.org/wiki/Station_(networking)) that communicate with each other
* access points and stations serviced by them
* packets count between every STA-STA pair. Packets with wrong checksum are ignored.

## Build prerequisites
    CMake 3.9 (it will probably compile using older versions too, see the last paragraph)
    C++17 compliant compiler
    libpcap

## Build instructions
```
git clone https://github.com/kwencel/WiFi-Sniffer
cd WiFi-Sniffer
cmake .
make
```

## How to use
```
sudo sh on.sh <wireless_interface_name>
sudo WiFiSniffer <wireless_interface_name>
sudo sh off.sh <wireless_interface_name>
```

*on.sh* and *off.sh* scripts enable and disable the **monitor mode** accordingly, which prevents conversion of
IEEE 802.11 frames to Ethernet frames. This behavior is essential for the program to function.
