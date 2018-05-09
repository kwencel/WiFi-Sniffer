#ifndef WIFISNIFFER_COMMUNICATION_H
#define WIFISNIFFER_COMMUNICATION_H

#include <list>
#include <vector>
#include <algorithm>
#include "TrafficAnalyzer.h"

class Communication {
    friend struct std::hash<Communication>;

    StationMac source;

    StationMac destination;

    std::unordered_set<ApMac> route;

    std::size_t packetsCaptures = 0;

public:

    Communication(const StationMac& source, const StationMac& destination) : source(source), destination(destination) { }

    void addAp(const ApMac& mac) {
        route.insert(mac);
    }

    std::string getSource() const {
        return source.toString();
    }

    std::string getDestination() const {
        return destination.toString();
    }

    std::string getRoute() const {
        std::vector<std::string> strings;
        std::transform(route.begin(), route.end(), std::back_inserter(strings), [](const MacAddress& mac) { return mac.toString(); });
        return printContainer(strings);
    }

    std::size_t getCapturesCount() const {
        return packetsCaptures;
    }

    const std::unordered_set<ApMac>& getAccessPoints() const {
        return route;
    }

    void incrementCaptures() {
        ++packetsCaptures;
    }

    bool operator == (const Communication &rhs) const {
        return source == rhs.source &&
               destination == rhs.destination;
    }

    bool operator != (const Communication &rhs) const {
        return not (rhs == *this);
    }
};

namespace std {
    template<>
    struct hash<Communication> {
        inline std::size_t operator()(const Communication& connection) const {
            std::size_t hash = 0;
            hash_combine(hash, connection.source, connection.destination);
            return hash;
        }
    };

    template<>
    struct hash<std::list<MacAddress>> {
        inline std::size_t operator()(const std::list<MacAddress>& list) const {
            std::size_t hash = 0;
            for (auto&& item : list) {
                hash_combine(hash, item);
            }
            return hash;
        }
    };
}

#endif //WIFISNIFFER_COMMUNICATION_H
