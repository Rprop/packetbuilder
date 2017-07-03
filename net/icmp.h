#pragma once
#include <stdint.h>

#pragma pack(1)
struct icmp_hdr
{
	uint8_t  icmptype;
	uint8_t  code;
	uint16_t checksum;
	uint32_t body;
};
#pragma pack()

typedef icmp_hdr icmpv4_hdr; 
typedef icmp_hdr icmpv6_hdr;