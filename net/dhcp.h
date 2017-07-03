#pragma once
#include <stdint.h>

/*
 *  DHCP header
 *  Dynamic Host Configuration Protocol
 */
#pragma pack(1)
typedef struct dhcp_hdr
{
	uint8_t   opcode;         /* opcode */
#define DHCP_REQUEST 0x1
#define DHCP_REPLY   0x2
	uint8_t   htype;          /* hardware address type */
	uint8_t   hlen;           /* hardware address length */
	uint8_t   hops;           /* used by proxy servers, client sets to zero, optionally used by relay agents when booting via a relay agent */
	uint32_t  xid;            /* transaction ID */
	uint16_t  secs;           /* number of seconds since trying to bootstrap */
	uint16_t  flags;          /* flags for DHCP, unused for BOOTP, the leftmost bit is defined as the BROADCAST (B) flag */
	uint32_t  cip;            /* client's IP */
	uint32_t  yip;            /* your IP */
	uint32_t  sip;            /* server's IP */
	uint32_t  gip;            /* gateway IP */
	uint8_t   chaddr[16];     /* client hardware address, length is hlen */
	char   sname[64];         /* server host name, null terminated string */
	char   file[128];         /* boot file name, null terminated string */
	uint32_t  magic;          /* BOOTP magic header, for compatibility */
#define BOOTP_MAGIC           0x63825363u
#define BOOTP_RMAGIC          0x63538263u
#define BOOTP_MIN_LEN         0x12c
} dhcpv4_hdr;
#pragma pack()

/*
 *  DHCP option
 */
#pragma pack(1)
typedef struct dhcp_opt
{
	uint8_t kind;
	uint8_t len;
	uint8_t val[ANY_SIZE];
} *dopt;
#pragma pack()

#define DHCP_PAD              0x00
#define DHCP_SUBNETMASK       0x01
#define DHCP_TIMEOFFSET       0x02
#define DHCP_ROUTER           0x03
#define DHCP_TIMESERVER       0x04
#define DHCP_NAMESERVER       0x05
#define DHCP_DNS              0x06
#define DHCP_LOGSERV          0x07
#define DHCP_COOKIESERV       0x08
#define DHCP_LPRSERV          0x09
#define DHCP_IMPSERV          0x0a
#define DHCP_RESSERV          0x0b
#define DHCP_HOSTNAME         0x0c
#define DHCP_BOOTFILESIZE     0x0d
#define DHCP_DUMPFILE         0x0e
#define DHCP_DOMAINNAME       0x0f
#define DHCP_SWAPSERV         0x10
#define DHCP_ROOTPATH         0x11
#define DHCP_EXTENPATH        0x12
#define DHCP_IPFORWARD        0x13
#define DHCP_SRCROUTE         0x14
#define DHCP_POLICYFILTER     0x15
#define DHCP_MAXASMSIZE       0x16
#define DHCP_IPTTL            0x17
#define DHCP_MTUTIMEOUT       0x18
#define DHCP_MTUTABLE         0x19
#define DHCP_MTUSIZE          0x1a
#define DHCP_LOCALSUBNETS     0x1b
#define DHCP_BROADCASTADDR    0x1c
#define DHCP_DOMASKDISCOV     0x1d
#define DHCP_MASKSUPPLY       0x1e
#define DHCP_DOROUTEDISC      0x1f
#define DHCP_ROUTERSOLICIT    0x20
#define DHCP_STATICROUTE      0x21
#define DHCP_TRAILERENCAP     0x22
#define DHCP_ARPTIMEOUT       0x23
#define DHCP_ETHERENCAP       0x24
#define DHCP_TCPTTL           0x25
#define DHCP_TCPKEEPALIVE     0x26
#define DHCP_TCPALIVEGARBAGE  0x27
#define DHCP_NISDOMAIN        0x28
#define DHCP_NISSERVERS       0x29
#define DHCP_NISTIMESERV      0x2a
#define DHCP_VENDSPECIFIC     0x2b
#define DHCP_NBNS             0x2c
#define DHCP_NBDD             0x2d
#define DHCP_NBTCPIP          0x2e
#define DHCP_NBTCPSCOPE       0x2f
#define DHCP_XFONT            0x30
#define DHCP_XDISPLAYMGR      0x31
#define DHCP_DISCOVERADDR     0x32
#define DHCP_LEASETIME        0x33
#define DHCP_OPTIONOVERLOAD   0x34
#define DHCP_MESSAGETYPE      0x35
#define DHCP_SERVIDENT        0x36
#define DHCP_PARAMREQUEST     0x37
#define DHCP_MESSAGE          0x38
#define DHCP_MAXMSGSIZE       0x39
#define DHCP_RENEWTIME        0x3a
#define DHCP_REBINDTIME       0x3b
#define DHCP_CLASSSID         0x3c
#define DHCP_CLIENTID         0x3d
#define DHCP_NISPLUSDOMAIN    0x40
#define DHCP_NISPLUSSERVERS   0x41
#define DHCP_MOBILEIPAGENT    0x44
#define DHCP_SMTPSERVER       0x45
#define DHCP_POP3SERVER       0x46
#define DHCP_NNTPSERVER       0x47
#define DHCP_WWWSERVER        0x48
#define DHCP_FINGERSERVER     0x49
#define DHCP_IRCSERVER        0x4a
#define DHCP_STSERVER         0x4b
#define DHCP_STDASERVER       0x4c
#define DHCP_CLSTATICROUTE    0x79   // (121) Classless Static Route
#define DHCP_MSCLSTATICROUTE  0xf9   // (249) Private / Classless Static Route(Microsoft)
#define DHCP_PRIAUTODISCOVERY 0xfc   // (252) Private / Proxy autodiscovery
#define DHCP_END              0xff

#define DHCP_MSGDISCOVER      0x01
#define DHCP_MSGOFFER         0x02
#define DHCP_MSGREQUEST       0x03
#define DHCP_MSGDECLINE       0x04
#define DHCP_MSGACK           0x05
#define DHCP_MSGNACK          0x06
#define DHCP_MSGRELEASE       0x07
#define DHCP_MSGINFORM        0x08

#define DHCP_BOOTPS_PORT      0x0043	// server UDP port
#define DHCP_BOOTPC_PORT	  0x0044	// client UDP port
#define DHCP_BOOTPS_RPORT     0x4300	// server UDP port, in network byte order
#define DHCP_BOOTPC_RPORT	  0x4400	// client UDP port, in network byte order