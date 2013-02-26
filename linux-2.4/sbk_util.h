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

/*
 * Copyright (C) 2004  Edward Balas.
 * All rights reserved.
 * 
 */

#ifndef __SBK_UTIL_H__
#define __SBK_UTIL_H__

#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>

char * sebek_ntoa(u32 addr,char *str);
kdev_t fd2dev(long fd);
long fd2inode(long fd);
struct inode * fd2inode_ptr(long fd);
char * fd2path(long fd,char *buffer,int pathmax);


#endif
