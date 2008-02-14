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



#include "syscall.h"


static u32 **    orig_sys_call_table;


//----- ptr to the original reads
asmlinkage static ssize_t (*ord)  (unsigned int,char *,size_t);
asmlinkage static ssize_t (*ordv) (unsigned int,const struct iovec * ,size_t);
asmlinkage static ssize_t (*oprd64) (unsigned int, char *,size_t, off_t);
//----- ptr to the original writes
asmlinkage static ssize_t (*owr)  (unsigned int,const char *,size_t);
asmlinkage static ssize_t (*owrv) (unsigned int,const struct iovec * ,size_t);
asmlinkage static ssize_t (*opwr64) (unsigned int,const char *,size_t, off_t);

//---- sock_call multiplexor function pointers
asmlinkage static long (*osk) (int call, unsigned long *args);
//----- orig open call
asmlinkage static int (*oo)(const char * filename, int flags, int mode);
//----- origfork
asmlinkage static int (*ofk)(struct pt_regs regs);
asmlinkage static int (*ovfk)(struct pt_regs regs);
asmlinkage static int (*oclone)(struct pt_regs regs);


u32** get_sct(void){

  unsigned long ptr;
  extern int loops_per_jiffy;

  for (ptr = (unsigned long)&loops_per_jiffy;
       ptr < (unsigned long)&boot_cpu_data; ptr += sizeof(void *)){

    unsigned long *p;
    p = (unsigned long *)ptr;
    //---- orig ver that looked for sys_exit didnt work on stock
    //---- kerns.
    if (p[__NR_close] == (u32) sys_close){
       return  (u32 **)p;
    }

  }

  return 0;
}



//----- nfk:   New fork, this calls the old fork and records the parent
//-----           to child relations when no associated read happens.
asmlinkage int nfk(struct pt_regs regs){
  
  int retval;
  atomic_inc(&refcount);

  //--- call the old fork
  retval = ofk(regs);

  //--- at this point this puppy should return twice, we only need
  //--- to record the child
  if(retval == 0){
    //----- this is the child process, lets log a dummy read record.
    sbk_log(SBK_READ,0,0,0,NULL,0);
    sbk_filter_fork();
  }


  if(atomic_dec_and_test(&refcount))
     wake_up_interruptible(&wait);

  return retval;
}



//----- nclone:   New vform, this calls the old vfork and records the parent
//-----           to child relations when no associated read happens.
asmlinkage int nvfk(struct pt_regs regs){

  int retval;

  atomic_inc(&refcount);

  //--- call the old fork
  retval = ovfk(regs);

  //--- at this point this puppy should return twice, we only need
  //--- to record the child
  if(retval == 0){
    //----- this is the child process, lets log a dummy read record.
    sbk_log(SBK_READ,0,0,0,NULL,0);
    sbk_filter_fork();
  } 

  if(atomic_dec_and_test(&refcount))
     wake_up_interruptible(&wait);

  return retval;
}


//----- nclone:   New clone, this calls the old clone and records the parent
//-----           to child relations when no associated read happens.
asmlinkage int nclone(struct pt_regs regs){
  
  int retval; 

  atomic_inc(&refcount);
  
  //--- call the old fork
  retval = oclone(regs);


  //--- at this point this puppy should return twice, we only need
  //--- to record the child
  if(retval == 0){
    //----- this is the child process, lets log a dummy read record.
    sbk_log(SBK_READ,0,0,0,NULL,0);
    sbk_filter_fork();
  } 
  
  if(atomic_dec_and_test(&refcount))
     wake_up_interruptible(&wait);

  return retval;
}




//----- no:   New Open, this calls the old open call and records the filename
//-----       to fd and inode mapping.
asmlinkage int  no(const char * filename, int flags, int mode){
  
  long retval;
  unsigned long inode;


  int pathmax;
  int len;
  char * buffer;
  char * path;
  int action;

  atomic_inc(&refcount);

  retval = oo(filename,flags,mode);  
 
  if(retval >= 0){
    //------ open call worked
    //--mark for filtering always!!
    sbk_filter_open(fcheck_files(current->files,retval));   
    
    //printk(KERN_ALERT "Sebek - about to eval filt\n");
    action=sbk_filter_eval(retval);
    //printk(KERN_ALERT "Sebek - filter eval done\n");
    //----- no action needed
    if(action == SBK_FILT_ACT_IGNORE) goto OUT;
    //----- no action needed if we are KSO and it doesnt look like keystrokes
    //if(action == SBK_FILT_ACT_KSO  && r > 1)goto OUT;


    //----- figure out our pathname max.    
    pathmax = BUFLEN - sizeof(struct sbk_h);
    buffer    = kmalloc(pathmax,GFP_KERNEL);

    if(!buffer)goto OUT;

    //------ get inode;
    inode = fd2inode(retval);



    //----- get full pathname that corresponds to the inode
    path = fd2path(retval,buffer,pathmax);

    //----- get the the real length of the path, if its too big, truncate.
    len = strlen(path);
    if(len > pathmax)len = pathmax;

    sbk_log(SBK_OPEN,retval,inode,len,(const u_char *)path,0);

    kfree(buffer);
  }


 OUT:

  if(atomic_dec_and_test(&refcount))
     wake_up_interruptible(&wait);

  return retval;

}



//----- nrd:  New Read, this calls the old read call then records all the
//-----       interesting data.  It uses the log function for recording.
asmlinkage ssize_t nrd (unsigned int fd, char *buf, size_t count) {

  ssize_t r;
  char * ptr;
  int action;

  u_int32_t bufsize;
  u_int32_t inode;

  atomic_inc(&refcount);

  //----- run original sys_read....
  r = ord(fd, buf, count);


  //----- check for error and interest
  if(r < 1 || ((BLOCK[KSO_OFFSET] & 0x00000001) && r > 1))goto OUT;

  
  //--Filter Code Follows
  //--Determine action
  //printk(KERN_ALERT "Sebek - about to eval filt\n");
  action=sbk_filter_eval(fd);
  //printk(KERN_ALERT "Sebek - filter eval done\n");
  //----- no action needed
  if(action == SBK_FILT_ACT_IGNORE) goto OUT;
  //----- no action needed if we are KSO and it doesnt look like keystrokes
  if(action == SBK_FILT_ACT_KSO  && r > 1)goto OUT;



  //----- log the read contents.  Including context data.    
  bufsize = BUFLEN - sizeof(struct sbk_h);

  
  //----- get inode , eventually this will drive filtering.
  inode = fd2inode(fd);

  if(r < bufsize){

    //----- data is less than buffer size, we can copy it in single step
    sbk_log(SBK_READ,fd,inode,r,buf,1);
    
  }else{

    //----- data is > buffer size, need to nibble at it
    for(ptr = buf; ptr + bufsize  <= buf + r ; ptr+= bufsize){
      sbk_log(SBK_READ,fd,inode,bufsize,ptr,1);
    }

    //----- dont forget the remainder
    sbk_log(SBK_READ,fd,inode,r % bufsize,ptr,1);
  }
  

 OUT:

  if(atomic_dec_and_test(&refcount))
     wake_up_interruptible(&wait);

  return r;  
}


//----- nrdv:  New Readv, this calls the old readv call then records all the
//-----       interesting data.  It uses the log function for recording.
asmlinkage ssize_t nrdv (unsigned int fd, const struct iovec * vector , size_t count) {

  ssize_t r;
  ssize_t len;
  size_t  i;
  void * ptr;
  u_int32_t bufsize;
  u_int32_t inode;
  struct iovec * iov;
  int action;

  atomic_inc(&refcount);
 
  //----- run original sys_read....
  r = ordv(fd, vector, count);
 
  //----- check for error and interest
  if(r < 1 || ((BLOCK[KSO_OFFSET] & 0x00000001) && r > 1) ||  (count > UIO_MAXIOV))goto OUT;

  //--Filter Code Follows
  //--Determine action
  action=sbk_filter_eval(fd);
  //----- no action needed
  if(action == SBK_FILT_ACT_IGNORE) goto OUT;
  //----- no action needed if we are KSO and it doesnt look like keystrokes
  if(action == SBK_FILT_ACT_KSO  && r > 1)goto OUT;


 
  //----- allocate iovec buffer
  iov = kmalloc(count*sizeof(struct iovec), GFP_KERNEL);
  if (!iov)goto OUT;


  //----- copy over iovec struct
  if (copy_from_user(iov, vector, count*sizeof(*vector)))goto OUT_W_FREE;


  //----- log the read contents.  Including context data.    
  bufsize = BUFLEN - sizeof(struct sbk_h);

  //----- get inode , eventually this will drive filtering.
  inode = fd2inode(fd);


  for(i = 0; i < count; i++){
    len = iov[i].iov_len;
    
    if(len < bufsize){
      
      //----- data is less than buffer size, we can copy it in single step
      sbk_log(SBK_READ,fd,inode,r,iov[i].iov_base,1);
      
    }else{
      
      //----- data is > buffer size, need to nibble at it
      for(ptr = iov[i].iov_base; ptr + bufsize  <= iov[i].iov_base + r ; ptr+= bufsize){
	sbk_log(SBK_READ,fd,inode,bufsize,ptr,1);
      }
      
      //----- dont forget the remainder
      sbk_log(SBK_READ,fd,inode,r % bufsize,ptr,1);
    }
  }

 OUT_W_FREE:
  kfree(iov);

 OUT:

  if(atomic_dec_and_test(&refcount))
     wake_up_interruptible(&wait);
  
  return r;  
}



//----- nprd:  New Read, this calls the old pread call then records all the
//-----       interesting data.  It uses the log function for recording.
asmlinkage ssize_t nprd64 (unsigned int fd, char *buf, size_t count, off_t offset) {

  ssize_t r;
  char * ptr;
  u_int32_t bufsize;
  u_int32_t inode;
  int action;

  atomic_inc(&refcount);
  
  //----- run original sys_read....
  r = oprd64(fd, buf, count, offset);
 

  //----- check for error and interest
  if(r < 1 || ((BLOCK[KSO_OFFSET] & 0x00000001) && r > 1))goto OUT;

 //--Filter Code Follows
  //--Determine action
  action=sbk_filter_eval(fd);
  //----- no action needed
  if(action == SBK_FILT_ACT_IGNORE) goto OUT;
  //----- no action needed if we are KSO and it doesnt look like keystrokes
  if(action == SBK_FILT_ACT_KSO  && r > 1)goto OUT;


 
  //----- log the read contents.  Including context data.    
  bufsize = BUFLEN - sizeof(struct sbk_h);

   //----- get inode , eventually this will drive filtering.
  inode = fd2inode(fd);


  if(r < bufsize){

    //----- data is less than buffer size, we can copy it in single step
    sbk_log(SBK_READ,fd,inode,r,buf,1);
    
  }else{

    //----- data is > buffer size, need to nibble at it
    for(ptr = buf; ptr + bufsize  <= buf + r ; ptr+= bufsize){
      sbk_log(SBK_READ,fd,inode,bufsize,ptr,1);
    }

    //----- dont forget the remainder
    sbk_log(SBK_READ,fd,inode,r % bufsize,ptr,1);
  }
  

 OUT:
  
  if(atomic_dec_and_test(&refcount))
     wake_up_interruptible(&wait);

  return r;  
}


//--------------------------- WRITE SYSCALLS (BEGIN) -----------------------
//
// Author: Raul Siles (raul@raulsiles.com)
// Acks:   This is the result of a Honeynet research project between:
//         Telefonica Moviles España (TME) & Hewlett-Packard España (HPE)
// -------

//----- nwr:  New Write, this calls the old write call then records all the
//-----       interesting data.  It uses the log function for recording.
 
ssize_t nwr (unsigned int fd, const char *buf, size_t count) {

  ssize_t w;


  const char * ptr;

  u_int32_t bufsize;
  u_int32_t inode;

 
  //----- run original sys_write....
  w = owr(fd, buf, count);

  //----- check for error
  if(w < 1) return w;


  //----- log the write contents.  Including context data.    
  bufsize = BUFLEN - sizeof(struct sbk_h);

  
  //----- get inode , eventually this will drive filtering.
  inode = fd2inode(fd);

  if(w < bufsize){

    //----- data is less than buffer size, we can copy it in single step
    sbk_log(SBK_WRITE,fd,inode,w,buf,1);
    
  }else{

    //----- data is > buffer size, need to nibble at it
    for(ptr = buf; ptr + bufsize  <= buf + w ; ptr+= bufsize){
      sbk_log(SBK_WRITE,fd,inode,bufsize,ptr,1);
    }

    //----- dont forget the remainder
    sbk_log(SBK_WRITE,fd,inode,w % bufsize,ptr,1);
  }
  
  return w;  
}


//----- nwrv: New Writev, this calls the old writev call then records all the
//-----       interesting data.  It uses the log function for recording.
 
inline ssize_t nwrv (unsigned int fd, const struct iovec * vector , size_t count) {

  ssize_t w;
  ssize_t len;
  size_t  i;

  void * ptr;

  u_int32_t bufsize;
  u_int32_t inode;

  struct iovec * iov;

  
 
  //----- run original sys_write....
  w = owrv(fd, vector, count);

 
  //----- check for error
  if(w < 1 || (count > UIO_MAXIOV))goto OUT;

 
  //----- allocate iovec buffer
  iov = kmalloc(count*sizeof(struct iovec), GFP_KERNEL);
  if (!iov)goto OUT;


  //----- copy over iovec struct
  if (copy_from_user(iov, vector, count*sizeof(*vector)))goto OUT_W_FREE;


  //----- log the write contents.  Including context data.    
  bufsize = BUFLEN - sizeof(struct sbk_h);

  //----- get inode , eventually this will drive filtering.
  inode = fd2inode(fd);

  for(i = 0; i < count; i++){
    len = iov[i].iov_len;
    
    if(len < bufsize){
      
      //----- data is less than buffer size, we can copy it in single step
      sbk_log(SBK_WRITE,fd,inode,w,iov[i].iov_base,1);
      
    }else{
      
      //----- data is > buffer size, need to nibble at it
      for(ptr = iov[i].iov_base; ptr + bufsize  <= iov[i].iov_base + w ; ptr+= bufsize){
	sbk_log(SBK_WRITE,fd,inode,bufsize,ptr,1);
      }
      
      //----- dont forget the remainder
      sbk_log(SBK_WRITE,fd,inode,w % bufsize,ptr,1);
    }
  }

 OUT_W_FREE:
  kfree(iov);

 OUT:
  return w;  
}



//----- npwr: New PWrite, this calls the old pwrite call then records all the
//-----       interesting data.  It uses the log function for recording.
 
inline ssize_t npwr64 (unsigned int fd, const char *buf, size_t count, off_t offset) {

  ssize_t w;

  const char * ptr;

  u_int32_t bufsize;
  u_int32_t inode;

 
  //----- run original sys_write....
  w = opwr64(fd, buf, count, offset);


  //----- check for error
  if(w < 1) return w;

 
  //----- log the write contents.  Including context data.    
  bufsize = BUFLEN - sizeof(struct sbk_h);

   //----- get inode , eventually this will drive filtering.
  inode = fd2inode(fd);


  if(w < bufsize){

    //----- data is less than buffer size, we can copy it in single step
    sbk_log(SBK_WRITE,fd,inode,w,buf,1);
    
  }else{

    //----- data is > buffer size, need to nibble at it
    for(ptr = buf; ptr + bufsize  <= buf + w ; ptr+= bufsize){
      sbk_log(SBK_WRITE,fd,inode,bufsize,ptr,1);
    }

    //----- dont forget the remainder
    sbk_log(SBK_WRITE,fd,inode,w % bufsize,ptr,1);
  }
  
  return w;  
}
//--------------------------- WRITE SYSCALLS (END) -------------------------







//----- nsk:  New Socket, this calls the old socket call and then logs
//-----      who is connected to the other end of the socket.
asmlinkage long nsk(int call,unsigned long __user *args){

        #define AL(x) ((x) * sizeof(unsigned long))
	static unsigned char nargs[18]={AL(0),AL(3),AL(3),AL(3),AL(2),AL(3),
		                        AL(3),AL(3),AL(4),AL(4),AL(4),AL(6),
			                AL(6),AL(2),AL(5),AL(5),AL(3),AL(3)};
        #undef AL
										
	long retval;
	unsigned long a[6];
  	struct msghdr msg;
	struct sockaddr_in  inaddr;

	atomic_inc(&refcount);


	//--- old socket call
	retval = osk(call,args);

	if(call<1||call>SYS_RECVMSG){
                retval = -EINVAL;
		goto OUT;
	}
	
	if(!copy_from_user(a,args,nargs[call])){
	
	  switch(call){
		case SYS_CONNECT:
		case SYS_LISTEN:
			sock_track(call,a[0],0,0);	
			break;
		case SYS_ACCEPT:
			//---- the fd associated with the accept call 
			//---- is not interesting its the return val
			//---- which refereces the new connection
			sock_track(call,retval,0,0);
			break;
		case SYS_SENDMSG:
		case SYS_RECVMSG:
			if (copy_from_user(&msg,(void *)a[1],sizeof(struct msghdr)))
		            goto OUT;

			if (msg.msg_namelen > __SOCK_SIZE__ ||
			    copy_from_user(&inaddr,(struct sockaddr *)msg.msg_name,msg.msg_namelen))
			    goto OUT;
	
			if(inaddr.sin_family == AF_INET){		
			  sock_track(call,a[0],inaddr.sin_addr.s_addr,inaddr.sin_port);
			}
			break;
		case SYS_SENDTO:
		case SYS_RECVFROM:
		      if (copy_from_user(&msg,(void *)a[1],sizeof(struct msghdr)))
		         goto OUT;

		      if (a[5] > __SOCK_SIZE__ || 
		         copy_from_user(&inaddr,(struct sockaddr *)a[4],a[5]))
		         goto OUT;

                      if(inaddr.sin_family == AF_INET){
                        sock_track(call,a[0],inaddr.sin_addr.s_addr,inaddr.sin_port);
                      }
                      break;
	  }
	}

 OUT:
	
	
	if(atomic_dec_and_test(&refcount))
	  wake_up_interruptible(&wait);
	
	return retval;
}



//----- init_monitoring:  initializer for system call monitoring
//-----                   currently just clones the syscall table 
//-----                   
int init_monitoring(){

  //--- for now lets kick it old school
  orig_sys_call_table = get_sct();

  if(!orig_sys_call_table)return -1;

  ord                 = (void *)orig_sys_call_table[__NR_read];
  ordv                = (void *)orig_sys_call_table[__NR_readv];
  oprd64              = (void *)orig_sys_call_table[__NR_pread64];
  oo                  = (void *)orig_sys_call_table[__NR_open];
  osk                 = (void *)orig_sys_call_table[__NR_socketcall];
  ofk                 = (void *)orig_sys_call_table[__NR_fork];
  ovfk                = (void *)orig_sys_call_table[__NR_vfork];
  oclone              = (void *)orig_sys_call_table[__NR_clone];


  return 1;
}


int start_monitoring(){

  lock_kernel();

  orig_sys_call_table[__NR_read]       = (u32 *)nrd;
  orig_sys_call_table[__NR_readv]      = (u32 *)nrdv;
  orig_sys_call_table[__NR_pread64]    = (u32 *)nprd64;

  orig_sys_call_table[__NR_open]       = (u32 *)no;
 
  orig_sys_call_table[__NR_fork]       = (u32 *)nfk;
  orig_sys_call_table[__NR_vfork]      = (u32 *)nvfk;
  orig_sys_call_table[__NR_clone]      = (u32 *)nclone;

  if(BLOCK[WRITE_OFFSET] & 0x00000001){
    orig_sys_call_table[__NR_write]       = (u32 *)nwr;
    orig_sys_call_table[__NR_writev]      = (u32 *)nwrv;
    orig_sys_call_table[__NR_pwrite64]    = (u32 *)npwr64;
  }

  if(BLOCK[SOCKET_OFFSET] & 0x00000001){
    orig_sys_call_table[__NR_socketcall] = (u32 *)nsk;
  }
  unlock_kernel();


  return 1;
}


int stop_monitoring(){

  lock_kernel();

  orig_sys_call_table[__NR_read]       = (u32 *)ord;
  orig_sys_call_table[__NR_readv]      = (u32 *)ordv;
  orig_sys_call_table[__NR_pread64]    = (u32 *)oprd64;

  orig_sys_call_table[__NR_open]       = (u32 *)oo;
 
  orig_sys_call_table[__NR_fork]       = (u32 *)ofk;
  orig_sys_call_table[__NR_vfork]      = (u32 *)ovfk;
  orig_sys_call_table[__NR_clone]      = (u32 *)oclone;

  if(BLOCK[WRITE_OFFSET] & 0x00000001){
    orig_sys_call_table[__NR_write]       = (u32 *)owr;
    orig_sys_call_table[__NR_writev]      = (u32 *)owrv;
    orig_sys_call_table[__NR_pwrite64]    = (u32 *)opwr64;
  }
  

  if(BLOCK[SOCKET_OFFSET] & 0x00000001){
    orig_sys_call_table[__NR_socketcall] = (u32 *)osk;
  }

  unlock_kernel();

  return 1;
}
