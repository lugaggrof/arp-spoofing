#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <iostream>

Mac get_current_mac(char* dev);
Ip get_current_ip(char* dev);
Mac get_mac_by_ip(pcap_t* pcap_handle, Mac my_mac, Ip my_ip, Ip ip);
void send_arp(pcap_t* pcap_handle, Mac eth_smac, Mac eth_dmac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip, uint16_t type);
