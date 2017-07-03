#pragma once
#include <stdint.h>

#ifndef ETHERTYPE_IP
# define ETHERTYPE_IP            0x0800
#endif
#ifndef ETHERTYPE_IPV4
# define ETHERTYPE_IPV4          ETHERTYPE_IP
#endif
#ifndef ETHERTYPE_IPV6
# define ETHERTYPE_IPV6          0x86DD
#endif
#ifndef ETHERTYPE_IP_PACKET
# define ETHERTYPE_IP_PACKET     0x0021 /* IP Packet */
#endif
#ifndef ETHERTYPE_UNKNOWN
# define ETHERTYPE_UNKNOWN       0xFFFF
#endif

#define RETHERTYPE_IP            0x0008
#define RETHERTYPE_IPV4          RETHERTYPE_IP
#define RETHERTYPE_IPV6          0xDD86
#define RETHERTYPE_IP_PACKET     0x2100 /* IP Packet */
#define RETHERTYPE_UNKNOWN       0xFFFF

/*
* Ipv4 address length
*/
#define IPV4_ADDR_LEN            4

/*
 * Some assigned IP protocol numbers
 */
#ifndef _WS2DEF_
# ifndef IPPROTO_ICMP
#  define IPPROTO_ICMP	1
# endif
# ifndef IPPROTO_IGMP
#  define IPPROTO_IGMP	2
# endif
# ifndef IPPROTO_TCP
#  define IPPROTO_TCP	6
# endif
# ifndef IPPROTO_UDP
#  define IPPROTO_UDP	17
# endif
# ifndef IPPROTO_IPV6
#  define IPPROTO_IPV6	41
# endif
# ifndef IPPROTO_ICMPV6
#  define IPPROTO_ICMPV6	58
# endif
#endif // !_WS2DEF_

/*
 * IPv4 header definitions.
 */
#pragma pack(1)
struct ip_hdr
{
	uint8_t  hdrlen : 4;
	uint8_t  version : 4;
    uint8_t  TOS; // differentiated services field
    uint16_t len;
    uint16_t identifier;
	uint16_t fragoffset;
    uint8_t  TTL;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t srcaddr;
    uint32_t dstaddr;
};
#pragma pack()
typedef ip_hdr ipv4_hdr;

#define IPHDR_GET_FRAGOFF(hdr)                    \
    (((hdr)->fragoffset) & 0xFF1F)
#define IPHDR_GET_MF(hdr)                         \
    ((((hdr)->fragoffset) & 0x0020) != 0)
#define IPHDR_GET_DF(hdr)                         \
    ((((hdr)->fragoffset) & 0x0040) != 0)
#define IPHDR_GET_RESERVED(hdr)                   \
    ((((hdr)->fragoffset) & 0x0080) != 0)

#define IPHDR_SET_FRAGOFF(hdr, val)                           \
    do                                                        \
    {                                                         \
        (hdr)->fragoffset = (((hdr)->fragoffset) & 0x00E0) |  \
            ((val) & 0xFF1F);                                 \
    } while (FALSE)
#define IPHDR_SET_MF(hdr, val)                                \
    do                                                        \
    {                                                         \
        (hdr)->fragoffset = (((hdr)->fragoffset) & 0xFFDF) |  \
            (((val) & 0x0001) << 5);                          \
    } while (FALSE)
#define IPHDR_SET_DF(hdr, val)                                \
    do                                                        \
    {                                                         \
        (hdr)->fragoffset = (((hdr)->fragoffset) & 0xFFBF) |  \
            (((val) & 0x0001) << 6);                          \
    } while (FALSE)
#define IPHDR_SET_RESERVED(hdr, val)                          \
    do                                                        \
    {                                                         \
        (hdr)->fragoffset = (((hdr)->fragoffset) & 0xFF7F) |  \
            (((val) & 0x0001) << 7);                          \
    } while (FALSE)

/*
 * IPv6 header definitions.
 */
#pragma pack(1)
struct ipv6_hdr
{
	uint8_t   tracls0 : 4; // traffic class
	uint8_t   version : 4;
	uint8_t   flowlabel0 : 4;
	uint8_t   tracls1 : 4;
    uint16_t  flowlabel1;
    uint16_t  length;
    uint8_t   nexthdr;
    uint8_t   hoplimit;
    uint32_t  srcaddr[4];
    uint32_t  dstaddr[4];
};
#pragma pack()

#define IPV6HDR_GET_TRAFFICCLASS(hdr)               \
    ((((hdr)->tracls0) << 4) | ((hdr)->tracls1))
#define IPV6HDR_GET_FLOWLABEL(hdr)                  \
    ((((uint32_t)(hdr)->flowlabel0) << 16) | ((uint32_t)(hdr)->flowlabel1))

#define IPV6HDR_SET_TRAFFICCLASS(hdr, val)          \
    do                                              \
    {                                               \
        (hdr)->tracls0 = ((uint8_t)(val) >> 4);     \
        (hdr)->tracls1 = (uint8_t)(val);            \
    } while (FALSE)
#define IPV6HDR_SET_FLOWLABEL(hdr, val)             \
    do                                              \
    {                                               \
        (hdr)->flowlabel0 = (uint8_t)((val) >> 16); \
        (hdr)->flowlabel1 = (uint16_t)(val);        \
    } while (FALSE)

/*
 * Reserved ip address 
 */
#define IP_BCAST_ADDR  0xFFFFFFFFU
#define IP_THIS_ADDR   0x00000000U