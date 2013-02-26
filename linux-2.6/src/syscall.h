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
//


#ifndef  __SYSCALL_MON__
#define  __SYSCALL_MON__

#include <linux/sched.h>
#include <linux/irq.h>

#include "config.h"
#ifdef HAVE_LINUX_SYSCALLS_H
  #include <linux/syscalls.h>
#endif

#include <asm/unistd.h>

#include <asm/desc.h>

#include "net.h"
#include "filter.h"


extern atomic_t refcount;
extern wait_queue_head_t wait;

//-----------------------------------------------------------------------------
//----- functions for controlling system call monitoring
//-----------------------------------------------------------------------------

int init_monitoring(void);

int start_monitoring(void);

int stop_monitoring(void);



#endif 
