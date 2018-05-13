#ifndef WIFISNIFFER_MACADDRESS_H
#define WIFISNIFFER_MACADDRESS_H

#include <array>
#include <iomanip>
#include <ostream>
#include "Define.h"

class MacAddress {
    friend struct std::hash<MacAddress>;

    std::array<uint8_t, 6> mac;

public:
    MacAddress(const uint8_t (&address)[6]) {
        std::copy(std::begin(address), std::end(address), std::begin(mac));
    }

    std::string toString() const {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 5; ++i) {
            ss << std::setw(2) << static_cast<unsigned>(mac[i]) << ':';
        }
        ss << std::setw(2) << static_cast<unsigned>(mac[5]);
        return ss.str();
    }

    bool operator == (const MacAddress &rhs) const {
        return mac == rhs.mac;
    }

    bool operator != (const MacAddress &rhs) const {
        return not (rhs == *this);
    }

    bool isOnBlackList() const {
        return (std::equal(mac.begin(), mac.begin() + 3, stp.begin()) or
               (std::equal(mac.begin(), mac.begin() + 3, ipv4Multicast.begin())) or
               (std::equal(mac.begin(), mac.begin() + 2, ipv6Multicast.begin())));
    }

};

namespace std {
    template<>
    struct hash<MacAddress> {
        inline std::size_t operator()(const MacAddress& macAddress) const {
            std::size_t hash = 0;
            const auto& mac = macAddress.mac;
            hash_combine(hash, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return hash;
        }
    };
}

using ApMac = MacAddress;
using StationMac = MacAddress;

#endif //WIFISNIFFER_MACADDRESS_H
