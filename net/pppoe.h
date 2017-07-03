#pragma once
#include <stdint.h>

#ifndef ANY_SIZE
# define ANY_SIZE 1
#endif

/* references: RFC 2516 */

/* ETHER_TYPE fields for PPPoE */
#ifndef	ETHERTYPE_PPPOEDISC
# define ETHERTYPE_PPPOEDISC	0x8863	/* PPP Over Ethernet Discovery Stage */
#endif
#ifndef	ETHERTYPE_PPPOE
# define ETHERTYPE_PPPOE		0x8864  /* PPP Over Ethernet Session Stage */
#endif

# define RETHERTYPE_PPPOEDISC	0x6388	/* PPP Over Ethernet Discovery Stage, in network byte order */
# define RETHERTYPE_PPPOE		0x6488  /* PPP Over Ethernet Session Stage, in network byte order */

/* MUST be set to 0x1 for this version of the PPPoE specification */
#define PPPOE_VER_RFC2516       0x1
#define PPPOE_TYPE_RFC2516      0x1

#define	PPPOE_VER_S		        0	    /* Version shift */
#define	PPPOE_VER_M		        0x0f	/* Version mask */
#define	PPPOE_TYPE_S	        4	    /* Type shift */
#define	PPPOE_TYPE_M	        0xf0	/* Type mask */
#define	PPPOE_VER(vt)	        (((vt) & PPPOE_VER_M) >> PPPOE_VER_S)
#define	PPPOE_TYPE(vt)	        (((vt) & PPPOE_TYPE_M) >> PPPOE_TYPE_S)
#define	PPPOE_VERTYPE(v,t)		((((v) << PPPOE_VER_S) & PPPOE_VER_M) | (((t) << PPPOE_TYPE_S) & PPPOE_TYPE_M))

#define	PPPOE_CODE_SESSION		0x00	/* Session */
#define	PPPOE_CODE_PADO			0x07	/* Active Discovery Offer */
#define	PPPOE_CODE_PADI			0x09	/* Active Discovery Initiation */
#define	PPPOE_CODE_PADR			0x19	/* Active Discovery Request */
#define	PPPOE_CODE_PADS			0x65	/* Active Discovery Session-Confirm */
#define	PPPOE_CODE_PADT			0xa7	/* Active Discovery Terminate */

#define	PPPOE_TAG_END_OF_LIST		    0x0000	/* End Of List */
#define	PPPOE_TAG_SERVICE_NAME		    0x0101	/* Service Name */
#define	PPPOE_TAG_AC_NAME		        0x0102	/* Access Concentrator Name */
#define	PPPOE_TAG_HOST_UNIQ		        0x0103	/* Host Uniq */
#define	PPPOE_TAG_AC_COOKIE		        0x0104	/* Access Concentratr Cookie */
#define	PPPOE_TAG_VENDOR_SPEC		    0x0105	/* Vendor Specific */
#define	PPPOE_TAG_RELAY_SESSION		    0x0110	/* Relay Session Id */
#define	PPPOE_TAG_SERVICE_NAME_ERROR	0x0201	/* Service Name Error */
#define	PPPOE_TAG_AC_SYSTEM_ERROR	    0x0202	/* Acc. Concentrator Error */
#define	PPPOE_TAG_GENERIC_ERROR		    0x0203	/* Generic Error */

#define	RPPPOE_TAG_END_OF_LIST		    0x0000	/* End Of List, in network byte order */
#define	RPPPOE_TAG_SERVICE_NAME		    0x0101	/* Service Name, in network byte order */
#define	RPPPOE_TAG_AC_NAME		        0x0201	/* Access Concentrator Name, in network byte order */
#define	RPPPOE_TAG_HOST_UNIQ		    0x0301	/* Host Uniq, in network byte order */
#define	RPPPOE_TAG_AC_COOKIE		    0x0401	/* Access Concentratr Cookie, in network byte order */
#define	RPPPOE_TAG_VENDOR_SPEC		    0x0501	/* Vendor Specific, in network byte order */
#define	RPPPOE_TAG_RELAY_SESSION	    0x1001	/* Relay Session Id, in network byte order */
#define	RPPPOE_TAG_SERVICE_NAME_ERROR	0x0102	/* Service Name Error, in network byte order */
#define	RPPPOE_TAG_AC_SYSTEM_ERROR	    0x0202	/* Acc. Concentrator Error, in network byte order */
#define	RPPPOE_TAG_GENERIC_ERROR	    0x0302	/* Generic Error, in network byte order */

#define	PPPOE_MTU		                (ETHER_MTU - sizeof(struct pppoe_hdr))

#pragma pack(1)
struct pppoe_hdr
{
	uint8_t  vertype;	    /* PPPoE version (low 4), type (high 4) */
	uint8_t  code;		    /* PPPoE code (packet type) */
	uint16_t sessionid;	    /* PPPoE session id, in network byte order */
	uint16_t payloadlen;	/* PPPoE payload length, in network byte order */
};
#pragma pack()

/* A TAG is a TLV (type-length-value) construct */
#pragma pack(1)
struct pppoe_tag
{
	uint16_t tagtype;		/* Tag Type */
	uint16_t len;	        /* Tag Length, in network byte order */
	uint8_t  val[ANY_SIZE];	/* Tag Value */
};
#pragma pack()