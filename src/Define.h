#ifndef WIFISNIFFER_DEFINE_H
#define WIFISNIFFER_DEFINE_H

#include <cstdint>
#include <linux/types.h>
#include "Util.h"

#define ETH_ALEN 6

// First bytes of destination field in specific packets
std::array<uint8_t, 3> ipv4Multicast = {0x01, 0x00, 0x5e}; // IPv4 multicast packets
std::array<uint8_t, 2> ipv6Multicast = {0x33, 0x33};       // IPv6 multicast packets
std::array<uint8_t, 3> stp = {0x01, 0x80, 0xc2};           // Spanning Tree Protocol

struct ieee80211_hdr {
    enum FrameType { MANAGEMENT, CONTROL, DATA, RESERVED };

    __le16 frameControl;
    __le16 durationId;
    uint8_t addr1[ETH_ALEN];
    uint8_t addr2[ETH_ALEN];
    uint8_t addr3[ETH_ALEN];
    __le16 seqCtrl;
    uint8_t addr4[ETH_ALEN];

    bool isToDistributionSystem() const {
        return static_cast<bool>(extractBits(frameControl, 8));
    }

    bool isFromDistributionSystem() const {
        return static_cast<bool>(extractBits(frameControl, 9));
    }

    FrameType getFrameType() const {
        return static_cast<FrameType>(extractBits(frameControl,2,3) >> 2);
    }

    bool isDataFrame() const {
        return getFrameType() == DATA;
    }

};

#endif //WIFISNIFFER_DEFINE_H
