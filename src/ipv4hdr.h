#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "ip.h"

// reference: https://stackoverflow.com/questions/19346128/create-ip-header-in-c

#pragma pack(push, 1)
struct Ipv4Hdr final {
  uint8_t ip_v:4, ip_hl:4;/* this means that each member is 4 bits */
  uint8_t ip_tos;       //1 Byte
  uint16_t ip_len;  //2 Byte
  uint16_t ip_id;   //2 Byte
  uint16_t ip_off;  //2 Byte
  uint8_t ip_ttl;       //1 Byte
  uint8_t ip_p;         //1 Byte
  uint16_t ip_sum;  //2 Byte
	
  Ip sip_; // 4byte
	Ip tip_; // 4byte

	Ip sip() { return ntohl(sip_); }
	Ip tip() { return ntohl(tip_); }
};
#pragma pack(pop)

