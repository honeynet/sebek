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
 * Copyright (C) 2004 Edward Balas
 * All rights reserved.
 *
 */

//#define __KERNEL__

#include "filter.h"

struct sbk_filter * sbk_filter_head;

int parse_filter(char buffer[32], struct sbk_filter * rule){  
  void *ptr;

  if(rule == NULL || buffer == NULL)return 0;

  ptr                         = buffer;
  rule->action                = *(u8 * )ptr; 
  ptr+=1;
  
  rule->options               = *(u16 *)ptr;  
  ptr+=2;
  
  rule->uid                   = *(u32 *)ptr;  
  ptr+=4;

  if(rule->options & SBK_FILT_ALL_SOCK_OPT ){
    //----- this is a socket based rules we store these in netbyte order
    rule->type                = SBK_FILT_TYPE_SOCK;

    rule->u.sock.proto        = htons(*(u16 *)ptr);  
    ptr+=2;

    rule->u.sock.local_ip     = htonl(*(u32 *)ptr);  
    ptr+=4;
    rule->u.sock.local_mask   = htonl(0xffffffff << (32 - *(u8  *)ptr));  
    ptr+=1;
    rule->u.sock.local_port   = htons(*(u16 *)ptr);  
    ptr+=2;

    rule->u.sock.remote_ip    = htonl(*(u32 *)ptr);  
    ptr+=4;
    rule->u.sock.remote_mask  = htonl(0xffffffff << (32 - *(u8  *)ptr));  
    ptr+=1;
    rule->u.sock.remote_port  = htons(*(u16 *)ptr);  
    ptr+=2;
  }else
    if(rule->options & SBK_FILT_ALL_FILE_OPT){
      //---- move pointer to correct point.
      ptr += 16;
      //----- this is a file based rule
      rule->type                = SBK_FILT_TYPE_FS;
      
      rule->u.fs.dev            = *(u32 *)ptr;  
      ptr+=4;
      rule->u.fs.inode          = *(u32 *)ptr;  
      ptr+=4;
    }

  rule->next = NULL;
  return 1;
}



//----- read and parse the sebek filtering config file
int parse_filter_file(char * filename){
  int ret_code = 0;
  struct file   *file = NULL;
  mm_segment_t  fs;

  struct sbk_filter * prior_filter = NULL;
  struct sbk_filter * filter       = NULL;

  char buffer[32];

  printk(KERN_ALERT  "Sebek Filter - filename=%s\n",filename);

  if((file = filp_open(filename,O_RDONLY,0400)) ==  NULL)goto out;
  
  if (IS_ERR(file))goto out;
  if (!S_ISREG(file->f_dentry->d_inode->i_mode))goto out;
  
  fs = get_fs ();
  set_fs (KERNEL_DS);

  while(file->f_op->read(file,buffer,32,&file->f_pos) == 32){
    if(!(filter = kmalloc(sizeof(struct sbk_filter),GFP_KERNEL))){
      ret_code = 0;
      goto out;
    }
    if(!parse_filter(buffer,filter)){
      ret_code = 0;
      goto out;
    }
    
    if(prior_filter == NULL){
      sbk_filter_head = filter;
      prior_filter    = filter;
    }else{
      prior_filter->next   = filter;
      prior_filter  = prior_filter->next;
    }

  }
  set_fs (fs);
  filp_close (file,NULL);
  ret_code = 1;
		 
 out:
  return ret_code;
}
//---------------------

int sbk_filter_fork(){
  
  int retval = 0;

  struct sbk_filter *ptr = sbk_filter_head;


  //----- take care of the inheritance of process tracking flags
#ifdef SBK_TASK_P_PPTR
  if(!(current->p_pptr->flags & PF_INHERIT)){
#else
  if(!(current->parent->flags & PF_INHERIT)){
#endif
    //--- parent didnt have inherit set, zero out our flags
    current->flags &= (~PF_KSO);
    current->flags &= (~PF_FULL);
    current->flags &= (~PF_IGNORE);
  }
   

  //---- check to see if we need to tag this process
  while(ptr){
    if(ptr->type == SBK_FILT_TYPE_FS || ptr->type == SBK_FILT_TYPE_SOCK)
      goto next_rule;
    
    //--- this is a UID based rule.
    if(ptr->options & SBK_FILT_OPT_UID  && ptr->uid  != current->uid)
      goto next_rule;
    
    goto determine_action;

  next_rule:
    ptr = ptr->next; 
  }
  
  
  if(!ptr)
    goto out;


  determine_action:

  if(ptr->action == SBK_FILT_ACT_IGNORE)
    current->flags |= PF_IGNORE;
  
  if(ptr->action == SBK_FILT_ACT_KSO)
    current->flags |= PF_KSO;
  
  if(ptr->action == SBK_FILT_ACT_FULL)
    current->flags |= PF_FULL;
  
  if(ptr->options & SBK_FILT_OPT_INHERIT)
    current->flags |= PF_INHERIT;
    
  retval=1;


  out:
  return retval;
}




int sbk_filter_socket(struct file *f_ptr, struct inode * i_ptr, u16 proto, u32 lip, u16 lport, u32 rip, u16 rport, int call){

  int retval = 0;
  struct sbk_filter *ptr = sbk_filter_head;

  if(!f_ptr || !i_ptr)return 0;



  while(ptr){
    //---!!!___ WE NEEED SUBNET MASKS___!!!---
    
    //--- check to see if this is a socket oriented rules
    if(ptr->type != SBK_FILT_TYPE_SOCK)
      goto next_rule;

    if(ptr->options & SBK_FILT_OPT_SOCK_C && !(call == SYS_CONNECT || call == SYS_SENDMSG || call == SYS_SENDTO))
      goto next_rule;

     if(ptr->options & SBK_FILT_OPT_SOCK_S && !(call == SYS_ACCEPT || call == SYS_RECVMSG || call == SYS_RECVFROM))
       goto next_rule;

    //--- check all possible parameters
    if(ptr->options & SBK_FILT_OPT_UID   && ptr->uid                 != current->uid)
      goto next_rule;

    if(ptr->options & SBK_FILT_OPT_PROTO  && ptr->u.sock.proto       != proto)
      goto next_rule;

    
   
    if(ptr->options & SBK_FILT_OPT_LIP){
      if(ptr->options & SBK_FILT_OPT_LMASK){
	//--- compare network IDs
	if( (ptr->u.sock.local_ip & ptr->u.sock.local_mask) !=  (lip & ptr->u.sock.local_mask))
	  goto next_rule;
      }else{
	//--- compare ip addr
	if( ptr->u.sock.local_ip != lip)
	  goto next_rule;
      }
    }

    if(ptr->options & SBK_FILT_OPT_RIP){
      if(ptr->options & SBK_FILT_OPT_RMASK){
	//--- compare network IDs
	//printk(" rip = %x rmask = %x\n",ptr->u.sock.remote_ip,ptr->u.sock.remote_mask);
	if( (ptr->u.sock.remote_ip & ptr->u.sock.remote_mask) !=  (rip & ptr->u.sock.remote_mask))
	  goto next_rule;
      }else{
	//--- compare ip addr
	if( ptr->u.sock.remote_ip   != rip )
	  goto next_rule;
      }
    }
    
    if(ptr->options & SBK_FILT_OPT_LPORT  && ptr->u.sock.local_port  != lport)
      goto next_rule; 

    if(ptr->options & SBK_FILT_OPT_RPORT  && ptr->u.sock.remote_port != rport)
      goto next_rule; 

    
    goto determine_action;

  next_rule:
    ptr = ptr->next;
  }


  if(!ptr)
    goto out;
  
 determine_action:
  //----- if we are here then we have a match, now determine set action flags


  if(ptr->action == SBK_FILT_ACT_IGNORE){
    if(ptr->options & SBK_FILT_OPT_STRICT){
      i_ptr->i_flags |= INODE_IGNORE;
    }else{
      current->flags |= PF_IGNORE;
    }
  }
    

  if(ptr->action == SBK_FILT_ACT_FULL){
    if(ptr->options & SBK_FILT_OPT_STRICT){
      i_ptr->i_flags |= INODE_FULL;
    }else{
      current->flags |= PF_FULL;
      }
  }
  
  if(ptr->action == SBK_FILT_ACT_KSO){
    if(ptr->options & SBK_FILT_OPT_STRICT){
      i_ptr->i_flags |= INODE_KSO;
    }else{
      current->flags |= PF_KSO;
    }
  }
  
  if(ptr->options & SBK_FILT_OPT_INHERIT){
    current->flags |= PF_INHERIT;
  }
  retval = 1;
  

 out:
  return retval;

}

int sbk_filter_open(struct file *f_ptr){
  int retval = 0;
  struct inode * i_ptr;
  struct dentry * dentry_ptr;
  struct vfsmount * vfsmnt_ptr;

  struct sbk_filter * ptr  = sbk_filter_head;

  //---- init i_ptr before use
  i_ptr = 0;

  //---- get inode.
   if(f_ptr && f_ptr->f_dentry && f_ptr->f_vfsmnt)
     i_ptr = f_ptr->f_dentry->d_inode;
 
  if(!i_ptr)return 0;

  while(ptr){
   
    if(ptr->type != SBK_FILT_TYPE_FS)
      goto next_rule;
   
    if(ptr->options & SBK_FILT_OPT_UID && ptr->uid != current->uid)
      goto next_rule;

     if(ptr->options & SBK_FILT_OPT_DEV && ptr->u.fs.dev != i_ptr->i_rdev)
      goto next_rule;

    if(ptr->options & SBK_FILT_OPT_FS_RECURSE){
      //--- this is a subdirectory match, if the target inode is a subdir
      //--- of the specified inode then we record
      dentry_ptr = f_ptr->f_dentry;
      vfsmnt_ptr = f_ptr->f_vfsmnt;

      for(;;){
	//--- at the overal fs root ?
	if(dentry_ptr == current->fs->root &&
	   vfsmnt_ptr == current->fs->rootmnt)break;

	//--- at the vfs root?
	if(dentry_ptr == vfsmnt_ptr->mnt_root ||
	   IS_ROOT(dentry_ptr)){
 
	  dentry_ptr = vfsmnt_ptr->mnt_mountpoint;
	  vfsmnt_ptr = vfsmnt_ptr->mnt_parent;
	}

	if(ptr->options & SBK_FILT_OPT_INODE && ptr->u.fs.inode == dentry_ptr->d_inode->i_ino)
	  goto determine_action;
	//--- walk the dentry back to the root
	dentry_ptr = dentry_ptr->d_parent;
      }
      goto next_rule;
      

    }else{
      //---- match exact
      if(ptr->options & SBK_FILT_OPT_INODE && ptr->u.fs.inode != i_ptr->i_ino)
	goto next_rule;
    }

    goto determine_action;
    

  next_rule:
    ptr = ptr->next;
  }

  if(!ptr)
    goto out;
  
 determine_action:

  //----- if we are here then we matched and we need to mark the task
  //----- and the inode
  if(ptr->action == SBK_FILT_ACT_IGNORE){
    if(ptr->options & SBK_FILT_OPT_STRICT){
      i_ptr->i_flags |= INODE_IGNORE;
    }else{
      current->flags |= PF_IGNORE;
    }
  }

  if(ptr->action == SBK_FILT_ACT_FULL){
    if(ptr->options & SBK_FILT_OPT_STRICT){
      i_ptr->i_flags |= INODE_FULL;
    }else{
      current->flags |= PF_FULL;
    }
  }

  if(ptr->action == SBK_FILT_ACT_KSO){
    if(ptr->options & SBK_FILT_OPT_STRICT){
      i_ptr->i_flags |= INODE_KSO;
    }else{
      current->flags |= PF_KSO;
    }
  }

  if(ptr->options & SBK_FILT_OPT_INHERIT){
    current->flags |= PF_INHERIT;
  }
  
  retval = 1;

 out:  
  return retval;
}




int sbk_filter_eval(unsigned int fd){
  struct inode * i_ptr;
  struct sbk_filter * ptr  = sbk_filter_head;

  i_ptr = fd2inode_ptr(fd);

  //--- INODE level flags
  if((i_ptr->i_flags & INODE_FULL))
    return SBK_FILT_ACT_FULL;

  if((i_ptr->i_flags & INODE_KSO))
     return SBK_FILT_ACT_KSO;

  if(i_ptr->i_flags & INODE_IGNORE)
     return SBK_FILT_ACT_IGNORE;


  //---- PROCESS level checks
  if(current->flags & PF_FULL)
    return SBK_FILT_ACT_FULL;
  
  if(current->flags & PF_KSO)
    return SBK_FILT_ACT_KSO;
  
  if(current->flags & PF_IGNORE)
    return SBK_FILT_ACT_IGNORE;

  //---- check rules that dont have any sock or file section
  //----
  //---- we do this check here and in nfk to make sure we 
  //---- catch processes that may have started with one UID and then 
  //---- changed
  while(ptr != NULL){
    if(ptr->type == SBK_FILT_TYPE_FS || ptr->type == SBK_FILT_TYPE_SOCK)
      goto next_rule;
      //--- this is a UID based rule.

      if(ptr->options & SBK_FILT_OPT_UID  && ptr->uid  != current->uid)
	goto next_rule;

      if(ptr->action == SBK_FILT_ACT_IGNORE)
	current->flags |= PF_IGNORE;

      if(ptr->action == SBK_FILT_ACT_KSO)
	current->flags |= PF_KSO;

      if(ptr->action == SBK_FILT_ACT_FULL)
	current->flags |= PF_FULL;
      
      if(ptr->options & SBK_FILT_OPT_INHERIT)
	current->flags |= PF_INHERIT;


      //--- rerun the check now that the flags have been set.
      return sbk_filter_eval(fd);
      
  next_rule:
      ptr = ptr->next; 
  }



  //---- default to keystroke logging
  return SBK_FILT_ACT_IGNORE;
}




//----- something to help with debugging.
void dump_filter(){
  
  struct sbk_filter * rule       = sbk_filter_head;

  while(rule != NULL){
    printk("%i:%i:%i",
	   rule->action,rule->options,
	   rule->uid);

    if(rule->options & SBK_FILT_OPT_PROTO){
    //----- this is a socket based rule
      printk(":%i:%i:%i:%i:%i:%i:%i:%i:%i\n", 
	     ntohs(rule->u.sock.proto),
	     ntohl(rule->u.sock.local_ip),
	     rule->u.sock.local_mask,
	     ntohs(rule->u.sock.local_port),
	     ntohl(rule->u.sock.remote_ip),
	     rule->u.sock.remote_mask,
	     ntohs(rule->u.sock.remote_port),
	     0,
	     0);
    }else{
      printk(":%i:%i:%i:%i:%i:%i:%i:%i:%i\n",
	     0,
	     0,
	     0,
	     0,
	     0,
	     0,
	     0,
	     rule->u.fs.dev,
	     rule->u.fs.inode);
  }


    //-----
    rule = rule->next;
  }

}

