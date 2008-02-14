//--------------------------------------------------------------------
//----- $Header$
//--------------------------------------------------------------------
/*
 * Copyright (C) 2001 - 2003  The Honeynet Project.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#ifdef FREEBSD
#include <netinet/in.h>
#endif

#include <arpa/inet.h>



#define DEFAULT_LOG_DIR    "/var/log/sebek"
#define DEFAULT_IF         "eth0"



char logdir[255];

struct eth_h
{
  u_int8_t  dhost[6];   // destination mac
  u_int8_t  shost[6];   // source mac
  u_int16_t type;       // ethernet frame type
};


struct ip_h
{
  u_int8_t  vhl;        // version & header length 
  u_int8_t  tos;        // type of service 
  u_int16_t len;        // datagram length 
  u_int16_t id;         // identification
  u_int16_t foff;       // fragment offset
  u_int8_t  ttl;        // time to live field
  u_int8_t  proto;      // datagram protocol
  u_int16_t csum;       // checksum
  struct in_addr src;   // source IP
  struct in_addr dst;   // dest IP
};

struct udp_h {
  u_int16_t     sport;  // source port
  u_int16_t     dport;  // destination port
  u_int16_t     len;    // length
  u_int16_t     csum;   // checksum
};


struct sbk_h{
  u_int32_t  magic       __attribute__((packed)) ;
  u_int16_t  ver         __attribute__((packed)) ;
  u_int16_t  type        __attribute__((packed)) ;
  u_int32_t  counter     __attribute__((packed)) ;
  u_int32_t  time_sec    __attribute__((packed)) ;
  u_int32_t  time_usec   __attribute__((packed)) ;
  u_int32_t  time_usec   __attribute__((packed)) ;
  u_int32_t  parent_pid  __attribute__((packed)) ;
  u_int32_t  uid         __attribute__((packed)) ;
  u_int32_t  fd          __attribute__((packed)) ;
  char       com[12]     __attribute__((packed)) ;
  u_int32_t  length      __attribute__((packed)) ;
};


u_char ethlen;
u_char iplen;
u_char udplen;

int static_port   = 1101;
int use_file      = 0;

pcap_t *pcap_nic;

u_int last_lost   = 0;


void handler (char *, const struct pcap_pkthdr *, const u_char *);


void help (void);
