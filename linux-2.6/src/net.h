//
// Copyright (C) 2001/2005 The Honeynet Project.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


#ifndef __NET_TX_H__
#define __NET_TX_H__

#include <asm/unistd.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/file.h>
#include <linux/version.h>

#include <linux/smp_lock.h>

#include "util.h"
#include "config.h"
#include "filter.h"

#define TX_TIMEOUT 2
#define TX_FULL    50
#define TX_DROP    500



struct sbk_h{
  u32  magic       __attribute__((packed)) ;
  u16  ver         __attribute__((packed)) ;

  u16  type        __attribute__((packed)) ;
  //--- 0  read
  //--- 1  write
  //--- 2  socket
  //--- 3  open

  u32  counter     __attribute__((packed)) ;
  u32  time_sec    __attribute__((packed)) ;
  u32  time_usec   __attribute__((packed)) ;
  u32  parent_pid  __attribute__((packed)) ;
  u32  pid         __attribute__((packed)) ;
  u32  uid         __attribute__((packed)) ;
  u32  fd          __attribute__((packed)) ;
  u32  inode       __attribute__((packed)) ;
  char com[12]     ;
  u32  length      __attribute__((packed)) ;
};

struct sbk_sock_rec{
  u32  dip        __attribute__((packed)) ;
  u16  dport	  __attribute__((packed)) ;
  u32  sip        __attribute__((packed)) ;
  u16  sport      __attribute__((packed)) ;
  u16  call       __attribute__((packed)) ;
  u8   proto      ;
};



//--- 2 queues for now, one for read data and one for everything else
//--- if you get a read flood it wont hose your fork and socket data
struct tx_pq{
  atomic_t            tx_req;
  spinlock_t          timer_lock; 
  struct timer_list   timer;
  struct sk_buff_head queue;
};


void do_tx_task(unsigned long data);


//-----------------------------------------------------------------------------
//----- logging functions
//-----------------------------------------------------------------------------
int  init_logging(void);
int  start_proc_hiding(void);
int  stop_proc_hiding(void);
int  start_raw_sock_hiding(void);

int sock_track(int call,int fd, u32 dst_ip, u32 dst_port);

int sbk_log(u_int16_t type,
	u_int32_t fd,
	u_int32_t inode,
	u_int32_t len, 
	const u_char *  buffer,
	int from_uspace);

#endif //--- NET_TX_H
