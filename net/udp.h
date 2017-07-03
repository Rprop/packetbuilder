#pragma once
#include <stdint.h>

#pragma pack(1)
struct udp_hdr
{
	uint16_t srcport;
	uint16_t dstport;
	uint16_t len;
	uint16_t checksum;
};
#pragma pack()