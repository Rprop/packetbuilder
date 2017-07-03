#include "netdev.h"
#include "net/ethernet.h"
#include "net/pppoe.h"
#include "net/ip.h"
#include "net/udp.h"
#include "net/arp.h"
#define ETHER_SELF_MAC "\x60\x08\x10\x29\x39\x48" "\xd8\x50\xe6\xe2\x2c\xf6"
#define SELF_IP_ADDR   "\xac\x13\xc7\x6b"

//-------------------------------------------------------------------------

static void build_PADI(builder<> &packet)
{
	auto eth       = packet.get<ether_hdr>();
	auto pppoe     = packet.get<pppoe_hdr>();
	auto tagcalc   = calculator<>();
	auto service   = packet.get(tagcalc.push<pppoe_tag>());
	auto host_uniq = packet.seek_back(tagcalc.pop(ANY_SIZE)).get(tagcalc.push<pppoe_tag>());
	auto uniqcalc  = calculator<>();
	packet.seek_back(tagcalc.pop(ANY_SIZE)).get(tagcalc.push(uniqcalc.push(12)));

	memcpy(eth->ether_dhost, ETHER_BCAST_MAC, ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, "\x60\x08\x10\x29\x39\x45 " ETHER_SELF_MAC, ETHER_ADDR_LEN);
	eth->ether_type    = RETHERTYPE_PPPOEDISC;
	pppoe->vertype     = PPPOE_VERTYPE(PPPOE_VER_RFC2516, PPPOE_TYPE_RFC2516);
	pppoe->code        = PPPOE_CODE_PADI;
	pppoe->sessionid   = NULL;
	pppoe->payloadlen  = tagcalc.rlength<uint16_t>();
	service->tagtype   = PPPOE_TAG_SERVICE_NAME;
	service->len       = 0;
	host_uniq->tagtype = RPPPOE_TAG_HOST_UNIQ;
	host_uniq->len     = uniqcalc.rlength<uint16_t>();
	memcpy(host_uniq->val, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", uniqcalc.length());
}

//-------------------------------------------------------------------------

static void build_PADR(builder<> &packet)
{
	auto eth       = packet.get<ether_hdr>();
	auto pppoe     = packet.get<pppoe_hdr>();
	auto tagcalc   = calculator<>();
	auto service   = packet.get(tagcalc.push<pppoe_tag>());
	auto host_uniq = packet.seek_back(tagcalc.pop(ANY_SIZE)).get(tagcalc.push<pppoe_tag>());
	auto uniqcalc  = calculator<>();
	packet.seek_back(tagcalc.pop(ANY_SIZE)).get(tagcalc.push(uniqcalc.push(12)));

	memcpy(eth->ether_dhost, "\x60\x08\x10\x29\x39\x4d", ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, "\x60\x08\x10\x29\x39\x45 " ETHER_SELF_MAC, ETHER_ADDR_LEN);
	eth->ether_type    = RETHERTYPE_PPPOEDISC;
	pppoe->vertype     = PPPOE_VERTYPE(PPPOE_VER_RFC2516, PPPOE_TYPE_RFC2516);
	pppoe->code        = PPPOE_CODE_PADR;
	pppoe->sessionid   = NULL;
	pppoe->payloadlen  = tagcalc.rlength<uint16_t>();
	service->tagtype   = PPPOE_TAG_SERVICE_NAME;
	service->len       = 0;
	host_uniq->tagtype = RPPPOE_TAG_HOST_UNIQ;
	host_uniq->len     = uniqcalc.rlength<uint16_t>();
	memcpy(host_uniq->val, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", uniqcalc.length());
}

//-------------------------------------------------------------------------

static pppoe_hdr *build_PADT(builder<> &packet)
{
	auto eth       = packet.get<ether_hdr>();
	auto pppoe     = packet.get<pppoe_hdr>();

	memcpy(eth->ether_shost, "\x60\x08\x10\x29\x39\x4d", ETHER_ADDR_LEN);
	memcpy(eth->ether_dhost, "\x3C\x97\x0E\x00\xCE\x7C", ETHER_ADDR_LEN);
	eth->ether_type    = RETHERTYPE_PPPOEDISC;
	pppoe->vertype     = PPPOE_VERTYPE(PPPOE_VER_RFC2516, PPPOE_TYPE_RFC2516);
	pppoe->code        = PPPOE_CODE_PADT;
//	pppoe->sessionid   = sessionid;
	pppoe->payloadlen  = 0;
	return pppoe;
}

//-------------------------------------------------------------------------

static void build_ARP(builder<> &packet)
{
	auto eth = packet.get<ether_hdr>();
	auto arp = packet.get<ether_arp>();

	memcpy(eth->ether_dhost, ETHER_BCAST_MAC, ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, "\x60\x08\x10\x29\x39\x45 " ETHER_SELF_MAC, ETHER_ADDR_LEN);
	eth->ether_type     = RETHERTYPE_ARP;
	arp->hdr.hrd_type   = RARPHRD_ETHER;
	arp->hdr.hrd_len    = ETHER_ADDR_LEN;
	arp->hdr.proto_type = RETHERTYPE_IPV4;
	arp->hdr.proto_len  = IPV4_ADDR_LEN;
	arp->hdr.opcode     = RARPOP_REQUEST;
	memcpy(arp->shrd, eth->ether_shost, ETHER_ADDR_LEN);
	memcpy(arp->sip, SELF_IP_ADDR, IPV4_ADDR_LEN);
	memcpy(arp->thrd, ETHER_BCAST_MAC, ETHER_ADDR_LEN);
	memcpy(arp->tip, SELF_IP_ADDR, IPV4_ADDR_LEN);

	memcpy(eth->ether_dhost, ETHER_BCAST_MAC, ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, "\x60\x08\x10\x29\x39\x45", ETHER_ADDR_LEN);
	eth->ether_type     = RETHERTYPE_ARP;
	arp->hdr.hrd_type   = RARPHRD_ETHER;
	arp->hdr.hrd_len    = ETHER_ADDR_LEN;
	arp->hdr.proto_type = RETHERTYPE_IPV4;
	arp->hdr.proto_len  = IPV4_ADDR_LEN;
	arp->hdr.opcode     = RARPOP_REPLY;
	memcpy(arp->shrd, eth->ether_shost, ETHER_ADDR_LEN);
	memcpy(arp->sip, "\xc0\xa8\x01\x02", IPV4_ADDR_LEN);
	memcpy(arp->thrd, eth->ether_dhost, ETHER_ADDR_LEN);
	memcpy(arp->tip, "\xff\xff\xff\xff", IPV4_ADDR_LEN);
}

//-------------------------------------------------------------------------

int main()
{
	builder<ether_hdr, ether_arp> arp;
	build_ARP(arp);
	arp.validate();
	builder<ether_hdr, pppoe_hdr, pppoe_tag[2], char[12]> padi;
	build_PADI(padi);
	padi.validate();
	builder<ether_hdr, pppoe_hdr, pppoe_tag[2], char[12]> padr;
	build_PADR(padr);
	padr.validate();
	builder<ether_hdr, pppoe_hdr> padt;
	auto pppoe = build_PADT(padt);
	padt.validate();

//	npcap::findalldevs();
	pcap_t *fp = npcap::opendev("\\Device\\NPF_{75182FD2-8975-4BE6-9DED-E54F510F63DD}"); // \\Device\\NPF_{03D535A4-2529-4D04-B70A-DA7196B7968A}
	if (fp != NULL) {
		npcap::sendpacket(fp, arp);
		npcap::sendpacket(fp, padi);
		npcap::sendpacket(fp, padr);

		pppoe->sessionid = 0;
		npcap::sendpacket(fp, padt);

		pcap_close(fp);
	} //if
	return 0;
}

