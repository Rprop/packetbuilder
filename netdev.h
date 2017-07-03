#pragma once
//#pragma warning(disable:4200)
#define WIN32
#define HAVE_REMOTE
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <Packet32.h>
#include "builder.h"
#include "parser.h"
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "wpcap.lib")

class npcap
{
public:
	static void findalldevs()
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_if_t *ifs;
		pcap_findalldevs(&ifs, errbuf);
		pcap_freealldevs(ifs);
		if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &ifs, errbuf) == -1) {
			fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		} //if
	}
	static pcap_t *opendev(const char *dev, pcap_direction_t direction = PCAP_D_INOUT)
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *fp = pcap_open_live(dev,
									65536,			// portion of the packet to capture. It doesn't matter in this case 
									TRUE,			// promiscuous mode (nonzero means promiscuous)
									1,			    // read timeout
									errbuf			// error buffer
		);
		if (fp == NULL) {
			fprintf(stderr, "\nUnable to open the adapter.\n");
		} else {
			int bs = pcap_setdirection(fp, direction);
			if (bs != 0) {
				fprintf(stderr, "pcap_setdirection failed with %s\n", pcap_geterr(fp));
			} //if
		} //if
		return fp;
	}
	static bool setfilter(pcap_t *fp, const char *fs, bpf_program *bp) {
		return pcap_compile(fp, bp, fs, TRUE, NULL) != -1 && pcap_setfilter(fp, bp) == 0;
	}
	static void freefilter(bpf_program *bp) {
		pcap_freecode(bp);
	}
	static bool sendpacket(pcap_t *fp, builder<> &packet)
	{
		int ret = pcap_sendpacket(fp, packet.first<u_char>(), packet.get_length<int>());
		if (ret != 0) {
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
		} //if
		return ret == 0;
	}
	static void sendpacket(pcap_t *fp, builder<> &packet, int times)
	{
		while (--times >= 0) {
			if (!npcap::sendpacket(fp, packet)) break;
			if (times > 0) SleepEx(800, TRUE);
		}
	}
	static void close(pcap_t * fp)
	{
		pcap_close(fp);
	}
};