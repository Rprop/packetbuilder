#pragma once
#include <stdint.h>

#pragma pack(1)
struct tcp_hdr
{
	uint16_t srcport;
	uint16_t dstport;
	uint32_t seqnum;
	uint32_t acknum;
	uint16_t reserved1 : 4;
	uint16_t hdrlen : 4;
	uint16_t fin : 1;
	uint16_t syn : 1;
	uint16_t rst : 1;
	uint16_t psh : 1;
	uint16_t ack : 1;
	uint16_t urg : 1;
	uint16_t reserved2 : 2;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgptr;
};
#pragma pack()