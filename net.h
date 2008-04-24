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

#ifndef _net_h_
#define _net_h_

/*
 * network definitions
 */

#include <pshpack1.h>

#define ETH_ADDR_LEN	6

struct ether_hdr {
	UCHAR		ether_dhost[ETH_ADDR_LEN];
	UCHAR		ether_shost[ETH_ADDR_LEN];
	USHORT	ether_type;
};

#define ETH_HEADER_LEN	14

#define	ETHERNET_TYPE_IP	0x0008 /* IP protocol, host order */

#define IP_HEADER_LEN	20
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */

struct ip_hdr {
	UCHAR		ip_hl:4;	/* header length */
	UCHAR		ip_v:4;		/* version */
	UCHAR		ip_tos;		/* type of service */
	USHORT	ip_len;		/* total length */
	USHORT	ip_id;		/* identification */
	USHORT	ip_off;		/* fragment offset field */
	UCHAR		ip_ttl;		/* time to live */
	UCHAR		ip_p;		/* protocol */
	USHORT	ip_sum;		/* checksum */
	ULONG		ip_src;		/* source address */
	ULONG		ip_dst;		/* dest address */
};

struct udp_hdr {
	USHORT	uh_sport;		/* source port */
	USHORT	uh_dport;		/* destination port */
	USHORT	uh_ulen;		/* udp length */
	USHORT	uh_sum;			/* udp checksum */
};

#define UDP_HEADER_LEN	8

#include <poppack.h>

#endif
