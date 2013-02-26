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


#include "util.h"

//------ ip address as text to integer
inline char * sebek_ntoa(u32 addr,char *str){

	u32 ip = ntohl(addr);
 	sprintf(str,"%u.%u.%u.%u",(ip & 0xff000000) >> 24,(ip & 0x00ff0000) >> 16,(ip & 0x0000ff00) >> 8,ip & 0x000000ff);
	return str;	
}




inline unsigned long fd2inode(long fd){

  struct file         * f_ptr = 0;
  struct inode        * i_ptr = 0;
  struct files_struct * files = 0;

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
    
   return i_ptr->i_ino;
}

struct inode * fd2inode_ptr(long fd){

  struct file         * f_ptr = 0;
  struct inode        * i_ptr = 0;
  struct files_struct * files = 0;

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




inline char * fd2path(long fd,char *buffer,int pathmax){

  struct files_struct * files = 0;
  struct file         * f_ptr = 0;

  //----- need to convert inode to dentry.
   files = current->files;
    
   //-----  get file pointer associated with file descriptor 
   if(files) 
     f_ptr = fcheck_files(files,fd);

   
   return d_path(f_ptr->f_dentry,f_ptr->f_vfsmnt,buffer,pathmax);
}


