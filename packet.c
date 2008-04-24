/*
 * Copyright (C) 2001-2004 The Honeynet Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by The Honeynet Project.
 * 4. The name "The Honeynet Project" may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* This code is mostly from http://ntdev.h1.ru/ndis_fw.html but was put into public domain by Vlad */

#include <ntddk.h>
#include <ndis.h>

#include "net.h"
#include "packet.h"
#include "sock.h"
#include "sebek.h"
#include "exports.h"

int
filter_packet(int direction, int iface, PNDIS_PACKET packet)
{
	PNDIS_BUFFER buffer;
	UINT packet_len, buffer_len, hdr_len;
	int result;
	void *pointer;
	struct ether_hdr *ether_hdr;
	struct ip_hdr *ip_hdr;

	//lint -e506 -e613 -e774 -e831 -e550 
	NdisQueryPacket(packet, NULL, NULL, &buffer, &packet_len);

	if (packet_len < sizeof(struct ether_hdr)) {
		DBGOUT(("filter_packet: too small packet for ether_hdr! (%u)\n", packet_len));
		return FILTER_UNKNOWN;
	}

	/* process ether_hdr */

	NdisQueryBuffer(buffer, &ether_hdr, &buffer_len);

	if (buffer_len < sizeof(struct ether_hdr)) {
		DBGOUT(("filter_packet: too small buffer for ether_hdr! (%u)\n", buffer_len));
		return FILTER_UNKNOWN;
	}
	
	// go to the next header
	if (buffer_len > sizeof(struct ether_hdr)) {

		pointer = (char *)ether_hdr + sizeof(struct ether_hdr);

		buffer_len -= sizeof(struct ether_hdr);

	} else {
		// use next buffer in chain
		NdisGetNextBuffer(buffer, &buffer);
		NdisQueryBuffer(buffer, &pointer, &buffer_len);
	}

	if (ether_hdr->ether_type == ETHERNET_TYPE_IP) {
		/* process ip_hdr */

		if (buffer_len < sizeof(struct ip_hdr)) {
			DBGOUT(("filter_packet: too small buffer for ip_hdr! (%u)\n",	buffer_len));
			return FILTER_UNKNOWN;
		}

		ip_hdr = (struct ip_hdr *)pointer;
		hdr_len = ip_hdr->ip_hl * 4;

		if (buffer_len < hdr_len) {
			DBGOUT(("filter_packet: too small buffer for ip_hdr! (%u vs. %u)\n", buffer_len, hdr_len));
			return FILTER_UNKNOWN;
		}

		// go to the next header
		if (buffer_len > hdr_len) {

			pointer = (char *)ip_hdr + hdr_len;
					
			buffer_len -= hdr_len;
			
		} else {
			// use next buffer in chain
			NdisGetNextBuffer(buffer, &buffer);
			NdisQueryBuffer(buffer, &pointer, &buffer_len);
		}

		result = process_transp(direction, iface, ip_hdr->ip_p, ip_hdr, pointer, buffer_len);
		if (result != FILTER_ALLOW)
			return result;
	}

	// default behavior
	return FILTER_ALLOW;
}

int
process_ip_packet(int direction, int iface, UCHAR *ip_packet, UINT size)
{
	struct ip_hdr *ip_hdr;
	UINT hdr_len;
	
	if(!ip_packet) {
		DBGOUT(("process_ip_packet: NULL ip_packet passed!\n"));
		return FILTER_UNKNOWN;
	}

	if (size < sizeof(struct ip_hdr)) {
		DBGOUT(("process_ip_packet: too small buffer for ip_hdr! (%u)\n", size));
		return FILTER_UNKNOWN;
	}

	ip_hdr = (struct ip_hdr *)ip_packet;
	if(!ip_hdr)
		return FILTER_UNKNOWN;

	hdr_len = ip_hdr->ip_hl * 4;

	if (size < hdr_len) {
		DBGOUT(("process_ip_packet: too small buffer for ip_hdr! (%u vs. %u)\n",
			size, hdr_len));
		return FILTER_UNKNOWN;
	}

	return process_transp(direction, iface, ip_hdr->ip_p, ip_hdr,
		ip_packet + hdr_len, size - hdr_len);
}

/* process TCP, UDP or ICMP header */
int
process_transp(int direction, int iface, UCHAR proto, struct ip_hdr *ip_hdr,
			   UCHAR *pointer, UINT buffer_len)
{
	struct udp_hdr *udp_hdr;

	switch (proto) {
		case IPPROTO_UDP:
			/* process udp_hdr */

			if (buffer_len < sizeof(struct udp_hdr)) {
				DBGOUT(("filter_packet: too small buffer for udp_hdr! (%u)\n", buffer_len));
				return FILTER_UNKNOWN;
			}

			udp_hdr = (struct udp_hdr *)pointer;

			return process_udp(direction, iface, ip_hdr, udp_hdr, pointer, buffer_len);

		default:
			return FILTER_UNKNOWN;
	}

	/* UNREACHED */
}

int
process_udp(int direction, int iface, struct ip_hdr *ip_hdr, struct udp_hdr *udp_hdr, UCHAR *pointer, UINT buffer_len)
{
	UINT hdr_len = UDP_HEADER_LEN;
	struct sebek_hdr *sbk_hdr;

	if(udp_hdr && (udp_hdr->uh_dport == g_usDestPort)) {
		// go to the next header
		if (buffer_len > hdr_len) {
			pointer = (UCHAR *)udp_hdr + hdr_len;
			buffer_len -= hdr_len;			
		}

		if (buffer_len < sizeof(struct sebek_hdr)) {
			DBGOUT(("filter_packet: too small buffer for sebek_hdr! (%u)\n",	buffer_len));
			return FILTER_ALLOW;
		}

		sbk_hdr = (struct sebek_hdr *)pointer;
		if(!sbk_hdr)
			return FILTER_UNKNOWN;

		if(sbk_hdr->magic == g_uiMagic)
			return FILTER_DENY;
	}

	return FILTER_ALLOW;
}
