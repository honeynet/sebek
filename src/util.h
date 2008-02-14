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


#ifndef __UTIL_H__
#define __UTIL_H__

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <linux/dcache.h>

#include "fudge.h"
#include "config.h"

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

#ifndef SOCKET_OFFSET
#define SOCKET_OFFSET           5 
#endif

#ifndef MAGIC_OFFSET
#define MAGIC_OFFSET           6 
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

#ifndef WRITE_OFFSET
#define WRITE_OFFSET           27
#endif


#define SBK_READ  0
#define SBK_WRITE 1
#define SBK_SOCK  2
#define SBK_OPEN  3


#define BUFLEN 1376


extern u32 BLOCK[BS];
extern u32 tx_bytes;
extern u32 tx_packets;
extern u32 s_bytes;
extern  u32 s_packets;

extern struct net_device *output_dev;
extern  get_info_t * old_get_info;

//-----------------------------------------------------------------------------
//----- Functions
//-----------------------------------------------------------------------------


char * sebek_ntoa(u32 addr,char *str);

unsigned long fd2inode(long fd);

struct inode * fd2inode_ptr(long fd);

char * fd2path(long fd,char *buffer,int pathmax);

/*dev_t fd2dev(long fd);*/


#endif // __UTIL_H_
