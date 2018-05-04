#include <iostream>
#include <pcap.h>

#include <csignal>
#include <thread>
#include "ErrorCheckUtils.h"
#include "Define.h"
#include "TrafficAnalyzer.h"


char errorBuffer[PCAP_ERRBUF_SIZE];
pcap_t* handle;
TrafficAnalyzer analyzer;

void trap(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
    __le16 radiotap_hdr_size = bytes[2];
    auto* frameHead = (ieee80211_hdr*) (bytes + radiotap_hdr_size);
    char* payload = (char*) bytes + sizeof(ieee80211_hdr) + radiotap_hdr_size;
    analyzer.add(frameHead);
}

void cleanup(int i) {
    pcap_close(handle);
}

int main(int argc, char** argv) {
    handle = pcap_create(argv[1], errorBuffer);
    if (handle == nullptr) {
        std::cerr << "Error in pcap_create: " << errorBuffer << std::endl;
        return -1;
    }

    CHK(pcap_set_promisc(handle, 1));
    auto canSetMonitorMode = static_cast<bool>(pcap_can_set_rfmon(handle));
    if (not canSetMonitorMode) {
        std::cerr << "Monitor mode is not supported on this wireless card. Cannot proceed." << std::endl;
        return 1;
    }

    CHK(pcap_set_rfmon(handle, 1));
    CHK(pcap_set_snaplen(handle, 65535));
    CHK(pcap_activate(handle));

    signal(SIGINT, cleanup);
    signal(SIGABRT, cleanup);
    signal(SIGTERM, cleanup);
    signal(SIGTSTP, cleanup);

    std::thread([&]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            const std::string& stats = analyzer.getStats();
            if (stats.empty()) {
                std::cout << "Still gathering data..." << std::endl;
            } else {
                std::cout << stats << "==================================================================" << std::endl;
            }
        }
    }).detach();

    pcap_loop(handle, -1, trap, nullptr);
}
