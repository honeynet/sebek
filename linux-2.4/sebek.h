/*
 * Copyright (C) 2001/2005 The Honeynet Project.
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


#ifndef __SEBEK_H__
#define __SEBEK_H__

#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif



#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/smp_lock.h>
#include <linux/random.h>
#include <asm/unistd.h>
#include <linux/tty.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/tcp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/checksum.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <asm/processor.h>

//---------local include files
#include "sbk_util.h"
#include "filter.h"

#define BUFLEN  1376 
#define SPORT   1101
#define DPORT   1101
#define MAGIC   0xD0D0D0D0

#define TX_TIMEOUT 2
#define TX_FULL    50 
#define TX_DROP    500 

#define SBK_READ  0
#define SBK_WRITE 1
#define SBK_SOCK  2
#define SBK_OPEN  3

//#include "fudge.h"
//#include "config.h"



//-----------------------------------------------------------------------------
//----- Cheezy obfuscation stuff
//-----------------------------------------------------------------------------
#ifndef BS
#define BS                     64
#endif

#ifndef DIP_OFFSET
#define DIP_OFFSET             0
#endif

#ifndef DPORT_OFFSET
#define DPORT_OFFSET           1
#endif

#ifndef SIP_OFFSET
#define SIP_OFFSET             2
#endif

#ifndef SPORT_OFFSET
#define SPORT_OFFSET           3
#endif

#ifndef KSO_OFFSET
#define KSO_OFFSET             4
#endif 

#ifndef ST_OFFSET
#define ST_OFFSET              5 
#endif

#ifndef MAGIC_OFFSET
#define MAGIC_OFFSET           6 
#endif

#ifndef WT_OFFSET
#define WT_OFFSET              7
#endif

#ifndef SMAC_0_OFFSET
#define SMAC_0_OFFSET          10
#define SMAC_1_OFFSET          11
#define SMAC_2_OFFSET          12
#define SMAC_3_OFFSET          13
#define SMAC_4_OFFSET          14
#define SMAC_5_OFFSET          15
#endif

#ifndef DMAC_0_OFFSET
#define DMAC_0_OFFSET          20
#define DMAC_1_OFFSET          21
#define DMAC_2_OFFSET          22
#define DMAC_3_OFFSET          23
#define DMAC_4_OFFSET          24
#define DMAC_5_OFFSET          25
#endif

#ifndef  TESTING_OFFSET
#define TESTING_OFFSET         26
#endif


u32      BLOCK[BS];


//-----------------------------------------------------------------------------
//----- input variables
//-----------------------------------------------------------------------------
char * INTERFACE; //char * interface;
char * DESTINATION_IP; //char * destination_ip;
char * DESTINATION_MAC; //char * destination_mac;
char * FILTER_FILE; //char * filter filename

int    DESTINATION_PORT; //int    destination_port;
int    SOURCE_PORT; //int    source_port;    
int    KEYSTROKES_ONLY; //int    keystroke_only;
int    SOCKET_TRACKING; //int   socket_tracking;
int    MAGIC_VALUE; //int    magic_value;
int    TESTING;
int    WRITE_TRACKING; // int WRITE_TRACKING

//-----------------------------------------------------------------------------
//----- internal config variables
//-----------------------------------------------------------------------------
u32 tx_bytes;
u32 tx_packets;
u32 s_bytes;
u32 s_packets;

struct net_device *output_dev;
get_info_t * old_get_info;
get_info_t * tcp_get_info;

spinlock_t counter_lock = SPIN_LOCK_UNLOCKED;


//--- 3 queues for now, one for read data (_b), another one for write
//--- data (_c) and one for everything else (_a)
//--- if you get a read flood it wont hose your fork and socket data
struct tx_pq{
  atomic_t            tx_req;
  spinlock_t          timer_lock; 
  struct timer_list   timer;
  struct sk_buff_head queue;
};

struct tx_pq txq_a;
struct tx_pq txq_b;
struct tx_pq txq_c;

//--- wait q for processes, used to throttle execution when packet queues are congested.
DECLARE_WAIT_QUEUE_HEAD(wait_q);

//-----------------------------------------------------------------------------
//----- PDU structures
//-----------------------------------------------------------------------------
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
  char com[12]     __attribute__((packed)) ;
  u32  length      __attribute__((packed)) ;
};

struct sbk_sock_rec{
  u32  dip        __attribute__((packed)) ;
  u16  dport	  __attribute__((packed)) ;
  u32  sip        __attribute__((packed)) ;
  u16  sport      __attribute__((packed)) ;
  u16  call       __attribute__((packed)) ;
  u8   proto      __attribute__((packed)) ;
};




//----- data structure that holds system call table
unsigned long **sct;

//-----  module fuctions needed for install and removal.
int init_module();
int cleanup_module();

//----- ptr to the original reads
ssize_t (*ord)  (unsigned int,char *,size_t);
ssize_t (*ordv) (unsigned int,const struct iovec * ,size_t);
ssize_t (*oprd) (unsigned int,char *,size_t, off_t);

//----- proto for the new sebekified reads
inline ssize_t nrd(unsigned int,char *,size_t);
inline ssize_t nrdv(unsigned int,const struct iovec *,size_t);
inline ssize_t nprd(unsigned int,char *,size_t,off_t);


//---- sock_call multiplexor function pointers
long (*osk) (int call, unsigned long *args);
//----- proto for new sebekified sys_socket
inline long nsk(int clal,unsigned long *args);


//---- proto for open calls
int  no(const char * filename, int flags, int mode);
int (*oo)(const char * filename, int flags, int mode);

//----- new fork
int nfk(struct pt_regs regs);
int nvfk(struct pt_regs regs);
int nclone(struct pt_regs regs);

//----- old fork
int (*ofk)(struct pt_regs regs);
int (*ovfk)(struct pt_regs regs);
int (*oclone)(struct pt_regs regs);

//----- proto for new sebekified sys_socket
//inline long nsk(int clal,unsigned long *args);


//----- ptr to the original writes
ssize_t (*owr)  (unsigned int,const char *,size_t);
ssize_t (*owrv) (unsigned int,const struct iovec * ,size_t);
ssize_t (*opwr) (unsigned int,const char *,size_t, off_t);

//----- proto for the new sebekified writes
inline ssize_t nwr(unsigned int,const char *,size_t);
inline ssize_t nwrv(unsigned int,const struct iovec *,size_t);
inline ssize_t npwr(unsigned int,const char *,size_t,off_t);


//----- packet transmission fuctions --> move to separate file someday
void do_tx_task(unsigned long data);
DECLARE_TASKLET(sebek_tx_task,do_tx_task,0);

//static void sebek_tx_action(struct softirq_action * h);

void tx_fctn(unsigned long qaddr);
//int tx(struct sk_buff *skb,struct tx_pq *q)
#endif
