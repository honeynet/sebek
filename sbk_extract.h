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
#include <sys/types.h>
#include <pwd.h>
#include <time.h>


#define DEFAULT_IF         "eth0"

#if defined  FREEBSD ||  defined OPENBSD
#include <netinet/in.h>
#endif

#ifdef MACOS
#include <inttypes.h>
#include <netinet/in.h>
#define DEFAULT_IF         "en0"
#endif

#define MAX_SBK_AGENT 128
#define SBK_VER       3

#include <arpa/inet.h>



struct eth_h
{
  uint8_t  dhost[6];   // destination mac
  uint8_t  shost[6];   // source mac
  uint16_t type;       // ethernet frame type
};


struct ip_h
{
  uint8_t  vhl;        // version & header length 
  uint8_t  tos;        // type of service 
  uint16_t len;        // datagram length 
  uint16_t id;         // identification
  uint16_t foff;       // fragment offset
  uint8_t  ttl;        // time to live field
  uint8_t  proto;      // datagram protocol
  uint16_t csum;       // checksum
  struct in_addr src;   // source IP
  struct in_addr dst;   // dest IP
};

struct udp_h {
  uint16_t     sport;  // source port
  uint16_t     dport;  // destination port
  uint16_t     len;    // length
  uint16_t     csum;   // checksum
};


struct sbk_h{
  uint32_t  magic       __attribute__((packed)) ;
  uint16_t  ver         __attribute__((packed)) ;
  uint16_t  type        __attribute__((packed)) ;
  uint32_t  counter     __attribute__((packed)) ;
  uint32_t  time_sec    __attribute__((packed)) ;
  uint32_t  time_usec   __attribute__((packed)) ;
  uint32_t  parent_pid  __attribute__((packed)) ;
  uint32_t  pid         __attribute__((packed)) ;
  uint32_t  uid         __attribute__((packed)) ;
  uint32_t  fd          __attribute__((packed)) ;
  uint32_t  inode       __attribute__((packed)) ;
  char      com[12]     __attribute__((packed)) ;
  uint32_t  length      __attribute__((packed)) ;
};



struct agent{
  uint32_t  ip_addr;
  uint32_t  pkt_counter;
  uint32_t  last_rec_id;
  time_t    last_time; 
  struct agent  * next;
};
  
struct agent * agent_list_head = NULL;


//--- if agent record exists return the match
//--- if no match create new.
struct agent * get_agent(uint32_t addr);



void handler (char *, const struct pcap_pkthdr *, const u_char *);


void help (void);


