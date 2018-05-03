#ifndef WIFISNIFFER_DEFINE_H
#define WIFISNIFFER_DEFINE_H

#include <cstdint>
#include <linux/types.h>
#include "Util.h"

#define ETH_ALEN	6
#define RADIOTAP_HDR_SIZE 56

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
};

#endif //WIFISNIFFER_DEFINE_H
