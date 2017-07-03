#define _HAS_EXCEPTIONS 0
#include <thread>
#include "netdev.h"
#include "net/ethernet.h"
#include "net/pppoe.h"
#include "net/ip.h"
#include "net/udp.h"
#include "net/arp.h"
#include "net/dhcp.h"
#define ETHER_SELF_MAC "\x88\x88\x88\x88\x88\x88"
#define DOT_IP(s)      ((unsigned char *)s)[0], ((unsigned char *)s)[1], ((unsigned char *)s)[2], ((unsigned char *)s)[3]
#define DOT_MAC(s)     ((unsigned char *)s)[0], ((unsigned char *)s)[1], ((unsigned char *)s)[2], ((unsigned char *)s)[3], ((unsigned char *)s)[4], ((unsigned char *)s)[5]
#define DOT_IPF        "%u.%u.%u.%u"
#define DOT_MACF       "%.2x.%.2x.%.2x.%.2x.%.2x.%.2x"

//-------------------------------------------------------------------------

template<typename iphdr> static void calc_ip_checksum(iphdr *ip)
{
	ip->checksum = NULL;
	auto ipseq   = reinterpret_cast<unsigned short *>(ip);
	uint32_t crc = ipseq[0] + ipseq[1] + ipseq[2] + ipseq[3] + ipseq[4] + ipseq[6] + ipseq[7] + ipseq[8] + ipseq[9];
	uint32_t crt = (crc >> 16) + (crc & 0xffffu);
	ipseq[5]     = ~static_cast<uint16_t>(crt);
}

//-------------------------------------------------------------------------

static void build_DHCP_Discovery(builder<> &packet)
{
	auto eth     = packet.get<ether_hdr>();
	auto ipcalc  = calculator<>(); // size of ip
	auto ip      = packet.get(ipcalc.push<ip_hdr>());
	auto udpcalc = calculator<>(); // size of udp
	auto udp     = packet.get(ipcalc.push(udpcalc.push<udp_hdr>()));
	auto dhcp    = packet.get(ipcalc.push(udpcalc.push<dhcp_hdr>()));
	dopt opts[]  = { 
		packet.get<dhcp_opt>(ipcalc.push(udpcalc.push(3))),
		packet.get<dhcp_opt>(ipcalc.push(udpcalc.push(9))),
		packet.get<dhcp_opt>(ipcalc.push(udpcalc.push(6))),
		packet.get<dhcp_opt>(ipcalc.push(udpcalc.push(8))), // host name
		packet.get<dhcp_opt>(ipcalc.push(udpcalc.push(10))),
		packet.get<dhcp_opt>(ipcalc.push(udpcalc.push(15)))
	};
	auto optend  = packet.get(ipcalc.push(udpcalc.push(1)));
	auto padcalc = calculator<>();
 	auto padding = packet.get(ipcalc.push(udpcalc.push( padcalc.push( BOOTP_MIN_LEN - (udpcalc.length() - sizeof(udp_hdr)) ) )));

	memcpy(eth->ether_dhost, ETHER_BCAST_MAC, ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, ETHER_SELF_MAC, ETHER_ADDR_LEN);
	eth->ether_type  = RETHERTYPE_IP;
	ip->hdrlen       = sizeof(ip_hdr) / sizeof(uint32_t);
	ip->version      = 4;
	ip->TOS          = 0;
	ip->len          = ipcalc.rlength<uint16_t>();
	ip->identifier   = 0;
	ip->fragoffset   = 0;
	ip->TTL          = 128;
	ip->protocol     = IPPROTO_UDP;
//	ip->checksum     = NULL;
	ip->srcaddr      = IP_THIS_ADDR;
	ip->dstaddr      = IP_BCAST_ADDR;
	calc_ip_checksum(ip);
	udp->srcport     = DHCP_BOOTPC_RPORT;
	udp->dstport     = DHCP_BOOTPS_RPORT;
	udp->len         = udpcalc.rlength<uint16_t>();
	udp->checksum    = NULL;
	dhcp->opcode     = DHCP_REQUEST;
	dhcp->htype      = ARPHRD_ETHER;
	dhcp->hlen       = ETHER_ADDR_LEN;
	dhcp->hops       = 0;
	dhcp->xid        = 0; // TODO: Transaction ID
	dhcp->secs       = 0;
	dhcp->flags      = 0; // UNICAST
	dhcp->cip        = IP_THIS_ADDR;
	dhcp->yip        = IP_THIS_ADDR;
	dhcp->sip        = IP_THIS_ADDR;
	dhcp->gip        = IP_THIS_ADDR;
	memcpy(dhcp->chaddr, ETHER_SELF_MAC, ETHER_ADDR_LEN);
	memset(&dhcp->chaddr[ETHER_ADDR_LEN], 0, sizeof(dhcp_hdr::chaddr) - ETHER_ADDR_LEN);
	memset(dhcp->sname, 0, sizeof(dhcp_hdr::sname));
	memset(dhcp->file, 0, sizeof(dhcp_hdr::file));
	dhcp->magic      = BOOTP_RMAGIC;
	opts[0]->kind    = DHCP_MESSAGETYPE;
	opts[0]->len     = 1;
	opts[0]->val[0]  = DHCP_MSGDISCOVER;
	opts[1]->kind    = DHCP_CLIENTID;
	opts[1]->len     = 7;
	opts[1]->val[0]  = ARPHRD_ETHER; // hardware address
	memcpy(&opts[1]->val[1], ETHER_SELF_MAC, ETHER_ADDR_LEN);
	opts[2]->kind    = DHCP_DISCOVERADDR;
	opts[2]->len     = IPV4_ADDR_LEN;
	memcpy(opts[2]->val, "\x00\x00\x00\x00", opts[2]->len);
	opts[3]->kind    = DHCP_HOSTNAME;
	opts[3]->len     = sizeof("Huawei") - 1;
	memcpy(opts[3]->val, "Huawei", opts[3]->len);
	opts[4]->kind    = DHCP_CLASSSID;
	opts[4]->len     = sizeof("MSFT 5.0") - 1;
	memcpy(opts[4]->val, "MSFT 5.0", opts[4]->len);
	opts[5]->kind    = DHCP_PARAMREQUEST;
	opts[5]->len     = 13;
	opts[5]->val[0]  = DHCP_SUBNETMASK;
	opts[5]->val[1]  = DHCP_ROUTER;
	opts[5]->val[2]  = DHCP_DNS;
	opts[5]->val[3]  = DHCP_DOMAINNAME;
	opts[5]->val[4]  = DHCP_DOROUTEDISC;
	opts[5]->val[5]  = DHCP_STATICROUTE;
	opts[5]->val[6]  = DHCP_VENDSPECIFIC;
	opts[5]->val[7]  = DHCP_NBNS;
	opts[5]->val[8]  = DHCP_NBTCPIP;
	opts[5]->val[9]  = DHCP_NBTCPSCOPE;
	opts[5]->val[10] = DHCP_CLSTATICROUTE;
	opts[5]->val[11] = DHCP_MSCLSTATICROUTE;
	opts[5]->val[12] = DHCP_PRIAUTODISCOVERY;
	optend[0]        = DHCP_END;
	memset(padding, 0, padcalc.length());
}

//-------------------------------------------------------------------------

static void build_DHCP_Request(builder<> &packet, ULONG addr)
{
	auto eth     = packet.get<ether_hdr>();
	auto ipcalc  = calculator<>(); // size of ip
	auto ip      = packet.get(ipcalc.push<ip_hdr>());
	auto udpcalc = calculator<>(); // size of udp
	auto udp     = packet.get(ipcalc.push(udpcalc.push<udp_hdr>()));
	auto dhcp    = packet.get(ipcalc.push(udpcalc.push<dhcp_hdr>()));
	dopt opts[]  = { 
		packet.get<dhcp_opt>(ipcalc.push(udpcalc.push(3))),
		packet.get<dhcp_opt>(ipcalc.push(udpcalc.push(9))),
		packet.get<dhcp_opt>(ipcalc.push(udpcalc.push(6))),
		packet.get<dhcp_opt>(ipcalc.push(udpcalc.push(8))), // host name
		packet.get<dhcp_opt>(ipcalc.push(udpcalc.push(10))),
		packet.get<dhcp_opt>(ipcalc.push(udpcalc.push(15)))
	};
	auto optend  = packet.get(ipcalc.push(udpcalc.push(1)));
	auto padcalc = calculator<>();
 	auto padding = packet.get(ipcalc.push(udpcalc.push( padcalc.push( BOOTP_MIN_LEN - (udpcalc.length() - sizeof(udp_hdr)) ) )));

	memcpy(eth->ether_dhost, ETHER_BCAST_MAC, ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, ETHER_SELF_MAC, ETHER_ADDR_LEN);
	eth->ether_type  = RETHERTYPE_IP;
	ip->hdrlen       = sizeof(ip_hdr) / sizeof(uint32_t);
	ip->version      = 4;
	ip->TOS          = 0;
	ip->len          = ipcalc.rlength<uint16_t>();
	ip->identifier   = 0;
	ip->fragoffset   = 0;
	ip->TTL          = 128;
	ip->protocol     = IPPROTO_UDP;
//	ip->checksum     = NULL;
	ip->srcaddr      = IP_THIS_ADDR;
	ip->dstaddr      = IP_BCAST_ADDR;
	calc_ip_checksum(ip);
	udp->srcport     = DHCP_BOOTPC_RPORT;
	udp->dstport     = DHCP_BOOTPS_RPORT;
	udp->len         = udpcalc.rlength<uint16_t>();
	udp->checksum    = NULL;
	dhcp->opcode     = DHCP_REQUEST;
	dhcp->htype      = ARPHRD_ETHER;
	dhcp->hlen       = ETHER_ADDR_LEN;
	dhcp->hops       = 0;
	dhcp->xid        = 0; // TODO: Transaction ID
	dhcp->secs       = 0;
	dhcp->flags      = 0; // UNICAST
	dhcp->cip        = IP_THIS_ADDR;
	dhcp->yip        = IP_THIS_ADDR;
	dhcp->sip        = IP_THIS_ADDR;
	dhcp->gip        = IP_THIS_ADDR;
	memcpy(dhcp->chaddr, ETHER_SELF_MAC, ETHER_ADDR_LEN);
	memset(&dhcp->chaddr[ETHER_ADDR_LEN], 0, sizeof(dhcp_hdr::chaddr) - ETHER_ADDR_LEN);
	memset(dhcp->sname, 0, sizeof(dhcp_hdr::sname));
	memset(dhcp->file, 0, sizeof(dhcp_hdr::file));
	dhcp->magic      = BOOTP_RMAGIC;
	opts[0]->kind    = DHCP_MESSAGETYPE;
	opts[0]->len     = 1;
	opts[0]->val[0]  = DHCP_MSGREQUEST;
	opts[1]->kind    = DHCP_CLIENTID;
	opts[1]->len     = 7;
	opts[1]->val[0]  = ARPHRD_ETHER; // hardware address
	memcpy(&opts[1]->val[1], ETHER_SELF_MAC, ETHER_ADDR_LEN);
	opts[2]->kind    = DHCP_DISCOVERADDR;
	opts[2]->len     = IPV4_ADDR_LEN;
	memcpy(opts[2]->val, &addr, opts[2]->len);
	opts[3]->kind    = DHCP_HOSTNAME;
	opts[3]->len     = sizeof("Huawei") - 1;
	memcpy(opts[3]->val, "Huawei", opts[3]->len);
	opts[4]->kind    = DHCP_CLASSSID;
	opts[4]->len     = sizeof("MSFT 5.0") - 1;
	memcpy(opts[4]->val, "MSFT 5.0", opts[4]->len);
	opts[5]->kind    = DHCP_PARAMREQUEST;
	opts[5]->len     = 13;
	opts[5]->val[0]  = DHCP_SUBNETMASK;
	opts[5]->val[1]  = DHCP_ROUTER;
	opts[5]->val[2]  = DHCP_DNS;
	opts[5]->val[3]  = DHCP_DOMAINNAME;
	opts[5]->val[4]  = DHCP_DOROUTEDISC;
	opts[5]->val[5]  = DHCP_STATICROUTE;
	opts[5]->val[6]  = DHCP_VENDSPECIFIC;
	opts[5]->val[7]  = DHCP_NBNS;
	opts[5]->val[8]  = DHCP_NBTCPIP;
	opts[5]->val[9]  = DHCP_NBTCPSCOPE;
	opts[5]->val[10] = DHCP_CLSTATICROUTE;
	opts[5]->val[11] = DHCP_MSCLSTATICROUTE;
	opts[5]->val[12] = DHCP_PRIAUTODISCOVERY;
	optend[0]        = DHCP_END;
	memset(padding, 0, padcalc.length());
}

//-------------------------------------------------------------------------

int main()
{
	builder<ether_hdr, ip_hdr, udp_hdr, dhcp_hdr, char[64]> dhcp;
	build_DHCP_Discovery(dhcp);
	dhcp.validate();

	pcap_t *fp = npcap::opendev("\\Device\\NPF_{75182FD2-8975-4BE6-9DED-E54F510F63DD}", PCAP_D_IN);
	bpf_program filter;
	npcap::setfilter(fp, "udp port 67", &filter);
	if (fp != NULL) {
		std::thread([](pcap_t *fp) {
			pcap_pkthdr  *header;
			const u_char *pkt_data;
			while (pcap_next_ex(fp, &header, &pkt_data) >= 0) {
				parser pr(pkt_data, header->caplen);
				auto eth  = pr.get<ether_hdr>();
				auto ip   = pr.get<ip_hdr>();
				auto udp  = pr.get<udp_hdr>();
				auto dhcp = pr.get<dhcp_hdr>();
				auto opt1 = pr.get<dhcp_opt>();
				if (ip != NULL && dhcp != NULL && opt1 != NULL) {
					if (memcmp(eth->ether_dhost, ETHER_SELF_MAC, ETHER_ADDR_LEN) == 0 && 
						eth->ether_type == RETHERTYPE_IP && 
						ip->protocol == IPPROTO_UDP && 
						udp->srcport == DHCP_BOOTPS_RPORT &&
						dhcp->opcode == DHCP_REPLY && 
						opt1->kind == DHCP_MESSAGETYPE) {
						
						if (opt1->val[0] == DHCP_MSGOFFER) {
							fprintf(stdout, "got DHCP Offer from " DOT_IPF ", client ip " DOT_IPF "\n",
									DOT_IP(&ip->srcaddr),
									DOT_IP(&dhcp->yip));
							builder<ether_hdr, ip_hdr, udp_hdr, dhcp_hdr, char[64]> dhcp2;
							build_DHCP_Request(dhcp2, dhcp->yip);
							dhcp2.validate();
							fprintf(stdout, "sending DHCP Request...\n");
							npcap::sendpacket(fp, dhcp2);
						} else if (opt1->val[0] == DHCP_MSGACK) {
							fprintf(stdout, "got DHCP ACK from " DOT_IPF ", client ip " DOT_IPF "\n",
									DOT_IP(&ip->srcaddr),
									DOT_IP(&dhcp->yip));
							break;
						} //if					
					} //if				
				} //if
			}
		}, fp).detach();

		SleepEx(100, TRUE);
		fprintf(stdout, "current mac is " DOT_MACF "\n", DOT_MAC(ETHER_SELF_MAC));
		fprintf(stdout, "sending DHCP Discovery...\n");
		npcap::sendpacket(fp, dhcp);
		SleepEx(1000000, TRUE);

		npcap::freefilter(&filter);
		pcap_close(fp);
	} //if
	return 0;
}

