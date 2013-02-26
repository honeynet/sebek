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
 * Copyright 2004-2006 Edward Balas, The Honeynet Project
 * All rights reserved.
 *
 */

#define __KERNEL__
#include "sbk_util.h"


//------ ip address as text to integer
char * sebek_ntoa(u32 addr,char *str){

	u32 ip = ntohl(addr);
 	sprintf(str,"%u.%u.%u.%u",(ip & 0xff000000) >> 24,(ip & 0x00ff0000) >> 16,(ip & 0x0000ff00) >> 8,ip & 0x000000ff);
	return str;	
}




kdev_t fd2dev(long fd){

  struct file         * f_ptr;
  struct inode        * i_ptr;
  struct files_struct * files;

   files = current->files;
    
   //-----  get file pointer associated with file descriptor 
   if(files) 
     f_ptr = fcheck_files(files,fd);
   
   //------ get the inode associated with the file
   if(f_ptr && f_ptr->f_dentry && f_ptr->f_vfsmnt)
     i_ptr = f_ptr->f_dentry->d_inode;
   
   if(!i_ptr){
     return 0;
   }
    
   return i_ptr->i_dev;
}

long fd2inode(long fd){
   struct inode *i_ptr;
   i_ptr=fd2inode_ptr(fd);
   if(NULL!=i_ptr){
      return i_ptr->i_dev;
     }
   else{
      return 0;
     }
};

struct inode * fd2inode_ptr(long fd){

  struct file         * f_ptr;
  struct inode        * i_ptr;
  struct files_struct * files;

   files = current->files;
    
   //-----  get file pointer associated with file descriptor 
   if(files) 
     f_ptr = fcheck_files(files,fd);
   
   //------ get the inode associated with the file
   if(f_ptr && f_ptr->f_dentry && f_ptr->f_vfsmnt)
     i_ptr = f_ptr->f_dentry->d_inode;
   
   if(!i_ptr){
     return 0;
   }
     
   return i_ptr;
}

char * fd2path(long fd,char *buffer,int pathmax){

  struct files_struct * files;
  struct file         * f_ptr;

  //----- need to convert inode to dentry.
   files = current->files;
    
   //-----  get file pointer associated with file descriptor 
   if(files) 
     f_ptr = fcheck_files(files,fd);

   
   //----- resolve path
   return  __d_path(f_ptr->f_dentry,f_ptr->f_vfsmnt,
	    current->fs->root,current->fs->rootmnt,
	    buffer,pathmax);
}
