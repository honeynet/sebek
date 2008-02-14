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

#ifndef __SEBEK_MOD_H__
#define __SEBEK_MOD_H__

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

#include <linux/random.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/tcp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/inet.h>
#include <linux/if_arp.h>

//#ifdef MODVERSIONS
//#include <linux/modversions.h>
//#endif



#define SPORT   1101
#define DPORT   1101
#define MAGIC   0xD0D0D0D0

#include "util.h"
#include "syscall.h"
#include "filter.h"
//-----------------------------------------------------------------------------
//----- input variables
//-----------------------------------------------------------------------------
static char * INTERFACE        = "eth0"; //char * interface;
static char * DESTINATION_IP   = "10.0.0.254"; //char * destination_ip;
static char * DESTINATION_MAC  = "FF:FF:FF:FF:FF:FF"; //char * destination_mac;
static char * FILTER_FILE      = "filter.txt";

static int    DESTINATION_PORT = 1101; //int    destination_port;
static int    SOURCE_PORT      = 1101; //int    source_port;
static int    KEYSTROKES_ONLY  = 1; //int    keystroke_only;
static int    SOCKET_TRACKING  = 1; //int   socket_tracking;
static int    WRITE_TRACKING   = 0; 
static int    MAGIC_VALUE      = 666; //int    magic_value;
static int    TESTING          = 0;

extern u32 BLOCK[BS];






#endif //# __SEBEK_MOD_H_
