#pragma once
#include <stdint.h>

#ifndef ETHERTYPE_ARP
# define ETHERTYPE_ARP           0x0806
#endif
# define RETHERTYPE_ARP          0x0608

/*
 * ARP header (without variable-sized fields)
 */
#pragma pack(1)
struct arp_hdr
{
	uint16_t	hrd_type;		/* Format of hardware address.  */
	uint16_t	proto_type;		/* Format of protocol address.  */
	uint8_t		hrd_len;		/* Length of hardware address.  */
	uint8_t		proto_len;		/* Length of protocol address.  */
	uint16_t	opcode;		    /* ARP opcode (command).  */
#if 0
	/* variable-sized fields: */
	uint8_t	__shrd[];	/* Sender hardware address.  */
	uint8_t	__sip[];	/* Sender IP address.  */
	uint8_t	__thrd[];	/* Target hardware address.  */
	uint8_t	__tip[];	/* Target IP address.  */
#endif
};
#pragma pack()

/* ARP protocol HARDWARE identifiers. */
#define ARPHRD_NETROM	    0	/* From KA9Q: NET/ROM pseudo. */
#define ARPHRD_ETHER 	    1	/* Ethernet 10/100Mbps.  */
#define	ARPHRD_EETHER	    2	/* Experimental Ethernet.  */
#define ARPHRD_AX25	        3	/* AX.25 Level 2.  */
#define	ARPHRD_PRONET	    4	/* PROnet token ring.  */
#define	ARPHRD_CHAOS 	    5	/* Chaosnet.  */
#define	ARPHRD_IEEE802	    6	/* IEEE 802.2 Ethernet/TR/TB.  */
#define	ARPHRD_ARCNET	    7	/* ARCnet.  */
#define ARPHRD_APPLETLK	    8	/* APPLEtalk.  */
#define ARPHRD_DLCI	        15	/* Frame Relay DLCI.  */
#define ARPHRD_METRICOM	    23	/* Metricom STRIP (new IANA id).  */

/* ARP protocol HARDWARE identifiers in network byte order. */
#define RARPHRD_NETROM	    0x0000	/* From KA9Q: NET/ROM pseudo. */
#define RARPHRD_ETHER 	    0x0100	/* Ethernet 10/100Mbps.  */
#define	RARPHRD_EETHER	    0x0200	/* Experimental Ethernet.  */
#define RARPHRD_AX25	    0x0300	/* AX.25 Level 2.  */
#define	RARPHRD_PRONET	    0x0400	/* PROnet token ring.  */
#define	RARPHRD_CHAOS 	    0x0500	/* Chaosnet.  */
#define	RARPHRD_IEEE802	    0x0600	/* IEEE 802.2 Ethernet/TR/TB.  */
#define	RARPHRD_ARCNET	    0x0700	/* ARCnet.  */
#define RARPHRD_APPLETLK	0x0800	/* APPLEtalk.  */
#define RARPHRD_DLCI	    0x0f00	/* Frame Relay DLCI.  */
#define RARPHRD_METRICOM	0x1700	/* Metricom STRIP (new IANA id).  */

/* Dummy types for non ARP hardware */
#define ARPHRD_SLIP	    256
#define ARPHRD_CSLIP	257
#define ARPHRD_SLIP6	258
#define ARPHRD_CSLIP6	259
#define ARPHRD_RSRVD	260	/* Notional KISS type.  */
#define ARPHRD_ADAPT	264
#define ARPHRD_ROSE	    270
#define ARPHRD_X25	    271	/* CCITT X.25.  */
#define ARPHRD_PPP	    512
#define ARPHRD_HDLC	    513	/* (Cisco) HDLC.  */
#define ARPHRD_LAPB	    516	/* LAPB.  */
#define ARPHRD_ASH	    517	/* ASH.  */
#define ARPHRD_TUNNEL	768	/* IPIP tunnel.  */
#define ARPHRD_TUNNEL6	769	/* IPIP6 tunnel.  */
#define ARPHRD_FRAD	    770	/* Frame Relay Access Device.  */
#define ARPHRD_SKIP	    771	/* SKIP vif.  */
#define ARPHRD_LOOPBACK	772	/* Loopback device.  */
#define ARPHRD_LOCALTLK 773	/* Localtalk device.  */
#define ARPHRD_FDDI	    774	/* Fiber Distributed Data Interface. */
#define ARPHRD_BIF      775	/* AP1000 BIF.  */
#define ARPHRD_SIT	    776	/* sit0 device - IPv6-in-IPv4.  */

/* ARP protocol opcodes. */
#define	ARPOP_REQUEST	    1	/* ARP request.  */
#define	ARPOP_REPLY	        2	/* ARP reply.  */
#define	ARPOP_RREQUEST	    3	/* RARP request.  */
#define	ARPOP_RREPLY	    4	/* RARP reply.  */
#define ARPOP_REVREQUEST	ARPOP_RREQUEST
#define ARPOP_REVREPLY	    ARPOP_RREPLY
#define ARPOP_IREQUEST	    8	/* InARP request. */
#define ARPOP_IREPLY	    9	/* InARP reply. */
#define ARPOP_INVREQUEST	ARPOP_IREQUEST
#define ARPOP_INVREPLY	    ARPOP_IREPLY

/* ARP protocol opcodes in network byte order. */
#define	RARPOP_REQUEST	    0x0100	/* ARP request.  */
#define	RARPOP_REPLY	    0x0200	/* ARP reply.  */
#define	RARPOP_RREQUEST	    0x0300	/* RARP request.  */
#define	RARPOP_RREPLY	    0x0400	/* RARP reply.  */
#define RARPOP_REVREQUEST	RARPOP_RREQUEST
#define RARPOP_REVREPLY	    RARPOP_RREPLY
#define RARPOP_IREQUEST	    0x0800	/* InARP request. */
#define RARPOP_IREPLY	    0x0900	/* InARP reply. */
#define RARPOP_INVREQUEST	RARPOP_IREQUEST
#define RARPOP_INVREPLY	    RARPOP_IREPLY

/*
 * Ethernet Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  Structure below is adapted
 * to resolving internet addresses.  Field names used correspond to
 * RFC 826.
 */
#pragma pack(1)
struct ether_arp
{
	arp_hdr	 hdr;		/* fixed-size header */
	uint8_t	 shrd[6];	/* sender hardware address */
	uint8_t  sip[4];	/* sender protocol address */
	uint8_t	 thrd[6];	/* target hardware address */
	uint8_t  tip[4];	/* target protocol address */
};
#pragma pack()

#define	arp_hrd	ea_hdr.ar_hrd
#define	arp_pro	ea_hdr.ar_pro
#define	arp_hln	ea_hdr.ar_hln
#define	arp_pln	ea_hdr.ar_pln
#define	arp_op	ea_hdr.ar_op