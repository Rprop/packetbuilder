#pragma once
#include <stdint.h>

#ifndef ETHERTYPE_IP
# define ETHERTYPE_IP            0x0800
#endif
#ifndef ETHERTYPE_IPV6
# define ETHERTYPE_IPV6          0x86DD  /* IPv6 protocol */
#endif
#ifndef ETHERTYPE_IP_PACKET
# define ETHERTYPE_IP_PACKET     0x0021  /* IP Packet */
#endif
#ifndef ETHERTYPE_TRAIL
# define ETHERTYPE_TRAIL         0x1000
#endif
#ifndef ETHERTYPE_8021Q
#define ETHERTYPE_8021Q          0x8100  /* IEEE 802.1Q VLAN tagging */
#endif
#ifndef ETHERTYPE_PPPOEDISC
# define ETHERTYPE_PPPOEDISC     0x8863  /* PPP Over Ethernet Discovery Stage */
#endif
#ifndef ETHERTYPE_PPPOE
# define ETHERTYPE_PPPOE         0x8864  /* PPP Over Ethernet Session Stage */
#endif
#ifndef ETHERTYPE_IPX
# define ETHERTYPE_IPX           0x8137
#endif
#ifndef ETHERTYPE_PUP
# define ETHERTYPE_PUP           0x0200  /* PUP protocol */
#endif
#ifndef ETHERTYPE_ARP
# define ETHERTYPE_ARP           0x0806  /* addr. resolution protocol */
#endif
#ifndef ETHERTYPE_REVARP
# define ETHERTYPE_REVARP        0x8035  /* reverse addr. resolution protocol */
#endif
#ifndef ETHERTYPE_VLAN
# define ETHERTYPE_VLAN          0x8100  /* IEEE 802.1Q VLAN tagging */
#endif
#ifndef ETHERTYPE_EAP
# define ETHERTYPE_EAP           0x888e  /* IEEE 802.1X EAP authentication */
#endif
#ifndef ETHERTYPE_MPLS
# define ETHERTYPE_MPLS          0x8847  /* MPLS */
#endif
#ifndef ETHERTYPE_LOOPBACK
# define ETHERTYPE_LOOPBACK      0x9000  /* used to test interfaces */
#endif

/*
 * Ethernet address length
 */
#define ETHER_ADDR_LEN           6

/*
 * Length of a DEC/Intel/Xerox or 802.3 Ethernet header; note that some
 * compilers may pad "struct ether_header" to a multiple of 4 bytes,
 * for example, so "sizeof (struct ether_header)" may not give the right
 * answer.
 */
#define ETHER_HDRLEN             14

#define	ETHER_MTU	             1500
#define	ETHERMTU	             ETHER_MTU

 /* ethernet broadcast address */
#define ETHER_BCAST_MAC          "\xff\xff\xff\xff\xff\xff"

/*
 * Ethernet header
 */
#pragma pack(1)
struct ether_hdr
{
	uint8_t  ether_dhost[ETHER_ADDR_LEN];
	uint8_t  ether_shost[ETHER_ADDR_LEN];
	uint16_t ether_type; // in network byte order
};
#pragma pack()