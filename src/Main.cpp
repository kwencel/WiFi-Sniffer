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

void trap(u_char* user, const struct pcap_pkthdr* pcapHeader, const u_char* bytes) {
    __le16 radiotapHeaderSize = bytes[2];
    const auto* frameHead = reinterpret_cast<const ieee80211_hdr*>(bytes + radiotapHeaderSize);

    int frameSize = pcapHeader->caplen - radiotapHeaderSize - FCS_SIZE;
    if (frameSize < 0 or frameSize > pcapHeader->caplen - FCS_SIZE) {
        // Packet is malformed
        return;
    }

    uint32_t calculatedChecksum = crc32(reinterpret_cast<const unsigned char*>(frameHead), static_cast<size_t>(frameSize));
    uint32_t packetChecksum = *((uint32_t*) (bytes + pcapHeader->caplen - FCS_SIZE));

    if (frameHead->isDataFrame() and calculatedChecksum == packetChecksum) {
        analyzer.add(frameHead);
    }
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

    /** Enable this to sniff only on the packets addressed to the interface provided as an argument.
     *  Use "on.sh" to sniff on all packets that reach the provided interface */
//    CHK(pcap_set_rfmon(handle, 1));

    CHK(pcap_set_snaplen(handle, 65535));
    CHK(pcap_activate(handle));

    signal(SIGINT, cleanup);
    signal(SIGABRT, cleanup);
    signal(SIGTERM, cleanup);
    signal(SIGTSTP, cleanup);

    std::thread([&]() {
        std::string line = "========================================================================================\n";
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            const std::string& stats = analyzer.getStats();
            if (stats.empty()) {
                std::cout << "Still gathering data..." << std::endl;
            } else {
                std::cout << line << stats << line << std::endl;
            }
        }
    }).detach();

    pcap_loop(handle, -1, trap, nullptr);
}
