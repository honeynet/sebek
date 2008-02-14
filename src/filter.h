/*
// (C) 2006 The Trustees of Indiana University.  All rights reserved.
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
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
//
*/
/*
 * Copyright (C) 2004  Edward Balas.
 * All rights reserved.
 * 
 */



#ifndef __FILTER_H__
#define __FILTER_H__
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
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <net/checksum.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/proc_fs.h>
#include <asm/processor.h>
#include <linux/fs.h>

/*by cviecco*/
#include <linux/mount.h>

#include "util.h"
#include "config.h"

//--- Process Flags to set in task struct
#define PF_KSO                   0x00010000
#define PF_FULL                  0x00020000
#define PF_INHERIT               0x00040000
#define PF_IGNORE                0x00080000


//--- inode flages set in the inode->flags field
#define INODE_KSO                0x10000000
#define INODE_FULL               0x20000000
#define INODE_IGNORE             0x40000000


#define SBK_FILT_TYPE_FS         1
#define SBK_FILT_TYPE_SOCK       2

#define SBK_FILT_ACT_IGNORE      0
#define SBK_FILT_ACT_FULL        1
#define SBK_FILT_ACT_KSO         2

#define SBK_FILT_OPT_UID         0x0001
#define SBK_FILT_OPT_PROTO       0x0002
#define SBK_FILT_OPT_LIP         0x0004
#define SBK_FILT_OPT_LMASK       0x0008
#define SBK_FILT_OPT_LPORT       0x0010
#define SBK_FILT_OPT_RIP         0x0020
#define SBK_FILT_OPT_RMASK       0x0040
#define SBK_FILT_OPT_RPORT       0x0080
#define SBK_FILT_OPT_DEV         0x0100
#define SBK_FILT_OPT_INODE       0x0200
#define SBK_FILT_OPT_FS_RECURSE  0x0400

#define SBK_FILT_ALL_SOCK_OPT    0xC0FE
#define SBK_FILT_ALL_FILE_OPT    0x0700

#define SBK_FILT_OPT_INHERIT     0x1000
#define SBK_FILT_OPT_STRICT      0x2000

//----- used to indicate if we are generally interested in server
//----- or client connections
#define SBK_FILT_OPT_SOCK_C      0x4000
#define SBK_FILT_OPT_SOCK_S      0x8000
//--- inheritance implies that we are not doing strict
//--- matching. but we could still do non-strict and non-inherit


struct sbk_fs_filter{
  u32  inode;              //----- inode for the file or dir in question.
  dev_t dev;
};


struct sbk_sock_filter{
  u16     proto;

  u32     local_ip;
  u32      local_mask;
  u16     local_port;

  u32     remote_ip;
  u32      remote_mask;
  u16     remote_port;
};

struct sbk_filter{
  u8   action;
  u16  options;
  u32  uid;          
  u8   type;  
  union{
    struct sbk_fs_filter fs;
    struct sbk_sock_filter sock;
  }u;

  struct sbk_filter * next;
};
 

//-----------------------------------------------------------------------------
//----- data capture filtering related structures 
//-----------------------------------------------------------------------------
extern struct sbk_filter * sbk_filter_head;


//----- function for reading in the filter config file
int parse_filter_file(char * filename);

//----- fuction used to tag socket activity
int sbk_filter_socket(struct file *f_ptr, 
		      struct inode * i_ptr,
		      u16 proto, 
		      u32 lip, 
		      u16 lport, 
		      u32 rip, 
		      u16 rport, 
		      int call);

//----- function used to tag sys_open file activity
int sbk_filter_open(struct file *f_ptr);

//------ fucntion used to determine if what to record in sys_read
int sbk_filter_eval(unsigned int fd);


//----- utility to dump filter configuration
void dump_filter(void);


//----- function to filter fork calls
int sbk_filter_fork(void);

#endif
