#ifndef WIFISNIFFER_TRAFFICANALYZER_H
#define WIFISNIFFER_TRAFFICANALYZER_H


#include <pcap.h>
#include <unordered_set>
#include <map>
#include <mutex>
#include <functional>
#include "Define.h"
#include "MacAddress.h"
#include "Communication.h"

class TrafficAnalyzer {

    std::unordered_set<Communication> communications;
    std::mutex communicationsMutex;

public:

    void add(const ieee80211_hdr* header) {
        bool toDS = header->isToDistributionSystem();
        bool fromDS = header->isFromDistributionSystem();
        if (not toDS) {
            if (not fromDS) {  // 0 0
                addToContainer(header->addr2, header->addr1, [&](Communication* c) {             // Source, Destination
                    c->addAp(header->addr3);                                                     // BSSID
                });
                auto [iterator, success] = communications.emplace(header->addr2, header->addr1);
            } else {           // 0 1
                addToContainer(header->addr3, header->addr1, [&](Communication* c) {             // Source, Destination
                    c->addAp(header->addr2);                                                     // AP
                });
            }
        } else {
            if (not fromDS) {  // 1 0
                addToContainer(header->addr2, header->addr3, [&](Communication* c) {             // Source, Destinatio
                    c->addAp(header->addr1);                                                     // AP
                });
            } else {           // 1 1
                addToContainer(header->addr4, header->addr3, [&](Communication* c) {
                    c->addAp(header->addr2);                                                     // Source AP
                    c->addAp(header->addr1);                                                     // Destination AP
                });
            }
        }
    }

    std::string getStats() {
        std::unordered_set<Communication> localCommunications = getCommunications();
        std::string message;
        for (const auto& communication : localCommunications) {
            message.append(communication.getSource() + " -> " + communication.getDestination() + " via APs " +
                           communication.getRoute() + " Count: " + std::to_string(communication.getCapturesCount()) + "\n");
        }

        using Ap = std::string;
        using Station = std::string;
        std::map<Ap, std::unordered_set<Station>> apBindings;
        for (const auto& communication : localCommunications) {
            for (const auto& ap : communication.getAccessPoints()) {
                const std::string& accessPoint = ap.toString();
                apBindings[accessPoint].insert(communication.getSource());
                apBindings[accessPoint].insert(communication.getDestination());
            }
        }

        for (const auto& [ap, stations] : apBindings) {
            message.append("AP " + ap + " handled communications of " + printContainer(stations) + "\n");
        }

        return message;
    }

private:

    void addToContainer(const StationMac& source, const StationMac& destination, const std::function<void (Communication*)>& processor) {
        std::lock_guard<std::mutex> guard(communicationsMutex);
        auto [iterator, success] = communications.emplace(source, destination);
        auto writablePointer = const_cast<Communication*>(&(*iterator));
        processor(writablePointer);
        writablePointer->incrementCaptures();
    }

    std::unordered_set<Communication> getCommunications() {
        std::lock_guard<std::mutex> guard(communicationsMutex);
        return communications;
    }

};


#endif //WIFISNIFFER_TRAFFICANALYZER_H
