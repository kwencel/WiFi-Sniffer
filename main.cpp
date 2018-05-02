#include <iostream>
#include <pcap.h>

#include <linux/if_ether.h>
#include <x86emu.h>
#include <bitset>
//#include "ieee80211.h"


char* errbuf;
pcap_t* handle;
int ip,arp,tcp,udp,others;
using namespace std;

const int RADIOTAP_HDR_SIZE = 56;

struct ieee80211_hdr {
    __le16 frame_control;
    __le16 duration_id;
    u8 addr1[ETH_ALEN];
    u8 addr2[ETH_ALEN];
    u8 addr3[ETH_ALEN];
    __le16 seq_ctrl;
    u8 addr4[ETH_ALEN];
} ;

void printMAC(u8 address[], string name){
    cout<<name<<" : ";
    for(int i=0;i<6;i++){
        printf("%02X:",address[i]);
    }
    cout<<endl;
}


void trap(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {

    u8 destinationAddress[ETH_ALEN];
    u8 sourceAddress[ETH_ALEN];
    u8 accessPointAddress[ETH_ALEN];
    u8 destinationAccessPointAddress[ETH_ALEN];
    u8 sourceAccessPointAddress[ETH_ALEN];
    struct ieee80211_hdr *fhead = (struct ieee80211_hdr *) (bytes + RADIOTAP_HDR_SIZE);
    char *payload = (char*) bytes + sizeof(struct ieee80211_hdr) + RADIOTAP_HDR_SIZE;
    bool toDS = (fhead->frame_control & ( 1 << 8 )) >> 8;
    bool fromDS = (fhead->frame_control & ( 1 << 9 )) >> 9;
    if(!toDS){
        copy(begin(fhead->addr1),end(fhead->addr1),destinationAddress);
        if(fromDS){
            copy(begin(fhead->addr2),end(fhead->addr2),accessPointAddress);
            copy(begin(fhead->addr3),end(fhead->addr3),sourceAddress);
        }else{
            copy(begin(fhead->addr3),end(fhead->addr3),accessPointAddress);
        }
    }else{
        copy(begin(fhead->addr3),end(fhead->addr3),destinationAddress);
        if(fromDS){
            copy(begin(fhead->addr4),end(fhead->addr4),accessPointAddress);
            copy(begin(fhead->addr2),end(fhead->addr2),sourceAccessPointAddress);
            copy(begin(fhead->addr1),end(fhead->addr1),destinationAccessPointAddress);
        }else{
            copy(begin(fhead->addr1),end(fhead->addr1),accessPointAddress);
        }
    }

    if(!fromDS){
        copy(begin(fhead->addr2),end(fhead->addr2),sourceAddress);
    }
    cout<<"============================"<<endl;
    cout<<"to DS: "<<toDS<<endl;
    cout<<"from DS: "<<fromDS<<endl;
    printMAC(sourceAddress,"SOURCE");
    printMAC(destinationAddress,"DESTINATION");
    printMAC(accessPointAddress,"AP");
    printMAC(destinationAccessPointAddress,"DESTINATION AP");
    printMAC(sourceAccessPointAddress,"SOURCE AP");
    cout<<std::bitset<8>(bytes[RADIOTAP_HDR_SIZE])<<endl;
    cout<<std::bitset<8>(bytes[1+RADIOTAP_HDR_SIZE])<<endl;

//    for(int y = 0; y < sizeof(char) * 8; y++)
//        printf("%c ", ( bytes[RADIOTAP_HDR_SIZE] & (1 << y) ) ? '1' : '0' );
//    cout<<endl;
//    for(int y = 0; y < sizeof(char) * 8; y++)
//        printf("%c ", ( bytes[1+RADIOTAP_HDR_SIZE] & (1 << y) ) ? '1' : '0' );
//    cout<<endl;

    for(int i=0;i<sizeof (ieee80211_hdr) ;i++){
        if(i==4||i==2) cout<<" ";
        if(i>4&&(i-10)%6==0) cout<<" ";
        printf("%02X",bytes[i+RADIOTAP_HDR_SIZE]);
    }
    std::fill(destinationAddress, destinationAddress+6, 0);
    std::fill(sourceAddress, sourceAddress+6, 0);
    std::fill(destinationAccessPointAddress, destinationAccessPointAddress+6, 0);
    std::fill(sourceAccessPointAddress, sourceAccessPointAddress+6, 0);
    std::fill(accessPointAddress, accessPointAddress+6, 0);
    cout<<endl<<"============================";
    cout<<endl;
}



int main(int argc, char** argv) {
    errbuf = new char[PCAP_ERRBUF_SIZE];
    handle = pcap_create(argv[1], errbuf);
    pcap_set_promisc(handle, 1);
    pcap_set_snaplen(handle, 65535);
    pcap_activate(handle);
    pcap_loop(handle, -1, trap, NULL);
}
