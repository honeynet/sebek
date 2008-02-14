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

#define MODULE 
#define __KERNEL__


#include "config.h"
#include "fudge.h"
#include "sebek.h"
#include "filter.h"

//---- this is dumb
#include "af_packet.c"


//---- get parameters from insmod

MODULE_PARM(INTERFACE,"s");
MODULE_PARM(DESTINATION_IP,"s");
MODULE_PARM(DESTINATION_MAC,"s");
MODULE_PARM(FILTER_FILE,"s");
MODULE_PARM(DESTINATION_PORT,"i");
MODULE_PARM(SOURCE_PORT,"i");
MODULE_PARM(KEYSTROKES_ONLY,"i");
MODULE_PARM(SOCKET_TRACKING,"i");
MODULE_PARM(MAGIC_VALUE,"i");
MODULE_PARM(TESTING,"i");
MODULE_PARM(WRITE_TRACKING,"i");




/*

inline unsigned long fd2inode(long fd){

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
    
   return i_ptr->i_ino;
}
*/


//----- generates internal values for parameters passed in at time of insmod.


inline int  parse_params(void){
  int x;

  char * endptr;
  struct in_device *in_dev;

  
  //------- need to initialize BLOCK to random values
  //------- and then mask off used portion and set it to real
  //------- values.

  //------- this is yet another cheezy obfuscation technique 
  //------- to make it more difficult to extract the config
  //------- from memory.

  for(x=0;x<BS;x++){
    //---- initialized each array elem to a random value
    get_random_bytes(&BLOCK[x],sizeof(u32));
  }

  //------ mask off bits in use
   BLOCK[TESTING_OFFSET]   &= 0xfffffffe;
   BLOCK[KSO_OFFSET]       &= 0xfffffffe;
   BLOCK[ST_OFFSET]        &= 0xfffffffe;
   BLOCK[WT_OFFSET]        &= 0xfffffffe;  
 
   BLOCK[DPORT_OFFSET]     &= 0xffff0000;
   BLOCK[SPORT_OFFSET]     &= 0xffff0000;
      
   BLOCK[DMAC_0_OFFSET]    &= 0xffffff00;
   BLOCK[DMAC_1_OFFSET]    &= 0xffffff00;
   BLOCK[DMAC_2_OFFSET]    &= 0xffffff00;
   BLOCK[DMAC_3_OFFSET]    &= 0xffffff00;
   BLOCK[DMAC_4_OFFSET]    &= 0xffffff00;
   BLOCK[DMAC_5_OFFSET]    &= 0xffffff00;

   BLOCK[SMAC_0_OFFSET]    &= 0xffffff00;
   BLOCK[SMAC_1_OFFSET]    &= 0xffffff00;
   BLOCK[SMAC_2_OFFSET]    &= 0xffffff00;
   BLOCK[SMAC_3_OFFSET]    &= 0xffffff00;
   BLOCK[SMAC_4_OFFSET]    &= 0xffffff00;
   BLOCK[SMAC_5_OFFSET]    &= 0xffffff00;
 
   


  //------- now add in data of interest

  //------- is this running in test mode
  if(TESTING){
    BLOCK[TESTING_OFFSET] |= 1; 
    TESTING = 0;
  }

  //------- read in keystroke only value
  if(KEYSTROKES_ONLY){
    BLOCK[KSO_OFFSET] |= 1; 
    KEYSTROKES_ONLY = 0;
  }

  //------- read in socket tracking value
  if(SOCKET_TRACKING){
    BLOCK[ST_OFFSET] |= 1; 
    SOCKET_TRACKING = 0;
  }

  //------- read in write tracking value
  if(WRITE_TRACKING){
    BLOCK[WT_OFFSET] |= 1;
    WRITE_TRACKING = 0;
  }


              

  //------- read in magic value
  if(MAGIC_VALUE){
    BLOCK[MAGIC_OFFSET] = MAGIC_VALUE;
    MAGIC_VALUE = 0;
  }

  //------- read in destination port
  if(DESTINATION_PORT){
    BLOCK[DPORT_OFFSET] |= DESTINATION_PORT;
    DESTINATION_PORT = 0;
  }

  //------- read in source port
  if(SOURCE_PORT){
    BLOCK[SPORT_OFFSET] |= SOURCE_PORT;
    SOURCE_PORT = 0;
  }

  if(!DESTINATION_IP || !DESTINATION_MAC){
    return 0;
  }

  //------ read in output interface
  if(INTERFACE){
    output_dev = __dev_get_by_name(INTERFACE);
    memset(INTERFACE,0,strlen(INTERFACE));
  }
  
  if(!output_dev)return 0;

    

  //----- initialize data needed for packet output  
  if(!output_dev || output_dev->type != ARPHRD_ETHER || !netif_running(output_dev))
    return 0;
  
  //------ set up src MAC addr
  BLOCK[SMAC_0_OFFSET] |= output_dev->dev_addr[0];
  BLOCK[SMAC_1_OFFSET] |= output_dev->dev_addr[1];
  BLOCK[SMAC_2_OFFSET] |= output_dev->dev_addr[2];
  BLOCK[SMAC_3_OFFSET] |= output_dev->dev_addr[3];
  BLOCK[SMAC_4_OFFSET] |= output_dev->dev_addr[4];
  BLOCK[SMAC_5_OFFSET] |= output_dev->dev_addr[5];
  
  if (output_dev->ip_ptr){
    in_dev = output_dev->ip_ptr;
    
    if(!in_dev)
      return 0;
    
    if (in_dev->ifa_list){
      BLOCK[SIP_OFFSET] = in_dev->ifa_list->ifa_address;
    }else{
      return 0;
    }
 } 
  

  
  
  //------- read in dst ip
  BLOCK[DIP_OFFSET] = in_aton(DESTINATION_IP);
  memset(DESTINATION_IP,0,strlen(DESTINATION_IP)); 


  //------- read in dst mac
  if(DESTINATION_MAC && strnlen(DESTINATION_MAC,18) == 17){
    
    BLOCK[DMAC_0_OFFSET] |= simple_strtoul(DESTINATION_MAC   ,&endptr, 16);
    BLOCK[DMAC_1_OFFSET] |= simple_strtoul(DESTINATION_MAC+3 ,&endptr, 16);
    BLOCK[DMAC_2_OFFSET] |= simple_strtoul(DESTINATION_MAC+6 ,&endptr, 16);
    BLOCK[DMAC_3_OFFSET] |= simple_strtoul(DESTINATION_MAC+9 ,&endptr, 16);
    BLOCK[DMAC_4_OFFSET] |= simple_strtoul(DESTINATION_MAC+12,&endptr, 16);
    BLOCK[DMAC_5_OFFSET] |= simple_strtoul(DESTINATION_MAC+15,&endptr, 16);

    memset(DESTINATION_MAC,0,strlen(DESTINATION_MAC));
  }else{
    //--- something is wrong with the dest mac address parameter
    return 0;
  }  

  if(FILTER_FILE){  //cviecco-NOTE: need to add check condition!
    if(!parse_filter_file(FILTER_FILE))return 0;
    memset(FILTER_FILE,0,strlen(FILTER_FILE));
  }

  
  return 1;
}




//----- this create a udp packet based on the parameters passed into the
//----- module at ismode time, payload is added later.
//----- 
//----- if user is set, we expect to copy from user space
inline struct sk_buff *  gen_pkt(u_int16_t type,
				 u_int32_t time_sec,
				 u_int32_t time_usec,
				 u_int32_t fd,
				 u_int32_t inode,
				 int       from_uspace,
				 u_int32_t len,
				 const u_char *  buffer
				 ){




  struct sk_buff *skb;
  struct ethhdr  *eth;
  struct iphdr   *iph;
  struct udphdr  *udph;
  u_char         *payload;
  struct sbk_h   *header;


  static u_int32_t counter;

  unsigned long flags;    //--- used by irqsave spinlock

 int pktsize;
 int paysize;

 //------ size of sebek header + length of data is the payload
 paysize  = sizeof(struct sbk_h) + len;


 //----- packet length
 pktsize = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + paysize;


 
 skb = alloc_skb(pktsize, GFP_ATOMIC);

 if (!skb) {
   return 0;
 }
 
 //----- setup pointers
 skb_reserve(skb,sizeof(struct ethhdr));

 eth     = (struct ethhdr *) skb_push(skb,sizeof(struct ethhdr));
 iph     = (struct iphdr *)  skb_put(skb, sizeof(struct iphdr));
 udph    = (struct udphdr *) skb_put(skb, sizeof(struct udphdr));
 payload = (u_char *)        skb_put(skb, paysize);


 //----- fill udp header data
 udph->source  = htons(BLOCK[SPORT_OFFSET]);
 udph->dest    = htons(BLOCK[DPORT_OFFSET]);
 udph->len     = htons(paysize+ sizeof(struct udphdr));
 udph->check   = 0; 
 

 //-----fill ip header data
 iph->ihl      = 5;
 iph->version  = 4;
 iph->ttl      = 32;
 iph->tos      = 13;
 iph->protocol = IPPROTO_UDP; 
 iph->saddr    = BLOCK[SIP_OFFSET];
 iph->daddr    = BLOCK[DIP_OFFSET];
 iph->frag_off = 0;
 iph->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + paysize );
 iph->check    = 0;
 

 //-----fill ethernet header data
 eth->h_proto = htons(ETH_P_IP);

 eth->h_source[0] = BLOCK[SMAC_0_OFFSET];
 eth->h_source[1] = BLOCK[SMAC_1_OFFSET];
 eth->h_source[2] = BLOCK[SMAC_2_OFFSET];
 eth->h_source[3] = BLOCK[SMAC_3_OFFSET];
 eth->h_source[4] = BLOCK[SMAC_4_OFFSET];
 eth->h_source[5] = BLOCK[SMAC_5_OFFSET];

 eth->h_dest[0] = BLOCK[DMAC_0_OFFSET];
 eth->h_dest[1] = BLOCK[DMAC_1_OFFSET];
 eth->h_dest[2] = BLOCK[DMAC_2_OFFSET];
 eth->h_dest[3] = BLOCK[DMAC_3_OFFSET];
 eth->h_dest[4] = BLOCK[DMAC_4_OFFSET];
 eth->h_dest[5] = BLOCK[DMAC_5_OFFSET];

 

 //-----fill sock buff header data
 skb->protocol = __constant_htons(ETH_P_IP);
 skb->mac.raw = ((u8 *)eth);
 skb->dev = output_dev;
 skb->pkt_type = PACKET_HOST;


 //----- fill in the sebek data
 header = (struct sbk_h *)payload;
 header->magic        = htonl(BLOCK[MAGIC_OFFSET]);
 header->ver          = htons(3);
 header->type         = htons(type);

 //--- cant use atomic_t cause we need 32 bits.
 spin_lock_irqsave(&counter_lock,flags);
 header->counter      = htonl(counter++);
 spin_unlock_irqrestore(&counter_lock,flags);

 header->time_sec     = htonl(time_sec);
 header->time_usec    = htonl(time_usec);
#ifdef SBK_TASK_P_PPTR
 header->parent_pid   = htonl(current->p_pptr->pid);
#else
 header->parent_pid   = htonl(current->parent->pid);
#endif

 header->pid          = htonl(current->pid);
 header->uid          = htonl(current->uid);
 header->fd           = htonl(fd);
 header->inode        = htonl(inode);
 strncpy(header->com,current->comm,sizeof(header->com));
 header->length       = htonl(len);

 //----- copy over the goods.
 if(from_uspace){
   copy_from_user(payload + sizeof(struct sbk_h),buffer,len);
 }else{
   memcpy(payload + sizeof(struct sbk_h),buffer,len);
 }
 
 //----- run the checksum
 iph->check    = ip_fast_csum((void *) iph, iph->ihl);

 return skb;
}




inline int tx_pkt(struct sk_buff *pkt){

  spin_lock_bh(&output_dev->xmit_lock);
  if( !netif_queue_stopped(output_dev)){
    if(!output_dev->hard_start_xmit(pkt, output_dev)){
	s_packets++;
        s_bytes += pkt->len;
        goto SUCCESS;

    }
    goto FAIL;
  }

  FAIL:
  spin_unlock_bh(&output_dev->xmit_lock);
  return 1;


  SUCCESS:
  spin_unlock_bh(&output_dev->xmit_lock);
  return 0;  
}


inline void tx_fctn(unsigned long qaddr){

  struct tx_pq   *q;
  struct sk_buff *pkt;
  int q_len;

  //---- determine which q we are talking about
  q = (struct tx_pq *)qaddr;

  //----- Interface ready for TX
  pkt = skb_dequeue(&(q->queue));
 
  while(pkt  != NULL){
    if(tx_pkt(pkt)){
      //--- transmission failed
      skb_queue_head(&(q->queue),pkt);
      tasklet_schedule(&sebek_tx_task);
      return;
    }
    //--- success
    pkt = skb_dequeue(&(q->queue));
  }

  wake_up_interruptible(&wait_q);
}


void do_tx_task(unsigned long data){

	tx_fctn((unsigned long)&txq_a);

	tx_fctn((unsigned long)&txq_b);

	tx_fctn((unsigned long)&txq_c);
}

//------ tx:   a tasklet that services the packet buffer, thus decoupling packet TX from
//------       the read call a bit.
inline int tx(struct sk_buff *skb,struct tx_pq *q){
  int q_len;

  if(!skb || !q)return 0;  

  //----- check to see if queue is to the drop point.
  q_len = skb_queue_len(&(q->queue));

  if(q_len >= TX_DROP){
      //--- block process until there is room in the queue
      interruptible_sleep_on(&wait_q);
  }
 
  //--- add new packet to queue and check the queue length
  skb_queue_tail(&(q->queue),skb);

  tasklet_schedule(&sebek_tx_task);

  return 2;
}





//-----  sock_track: logs state of a given socket
//------------------------------------------------------------
//--- dst_ip and dst_port are optional and in netbyte order
//
inline int sock_track(int call,int fd, u32 dst_ip, u32 dst_port){

  struct timeval tv;
	
  struct sbk_sock_rec buffer;
 
  struct sk_buff      * skb;
  struct file         * f_ptr;
  struct inode        * i_ptr;
  struct socket       * s_ptr; 
  struct files_struct * files;
  
  //----- get timestamp
   do_gettimeofday(&tv);
    
  
  files = current->files;

  //-----  get file pointer associated with file descriptor 
  if(files) 
    f_ptr = fcheck_files(files,fd);
  

  //------ get the inode associated with the file
  if(f_ptr && f_ptr->f_dentry && f_ptr->f_vfsmnt){
    i_ptr = f_ptr->f_dentry->d_inode;
    
    //----- get the socke associated with the inode
    if(i_ptr && i_ptr->i_sock){
      s_ptr = &i_ptr->u.socket_i;


      //---- check to see if this is a INET socket
      if(!s_ptr || s_ptr->ops->family != PF_INET)
	return 0;      
      
      if(s_ptr && s_ptr->sk->sport != 0){

	if(!dst_ip)    dst_ip   = s_ptr->sk->daddr;
	if(!dst_port)  dst_port = s_ptr->sk->dport;

      }
    }
  }

  //----- populate buffer
  buffer.dip   = dst_ip;
  buffer.dport = dst_port;
  
  buffer.sip   = s_ptr->sk->rcv_saddr;
  buffer.sport = s_ptr->sk->sport;

  buffer.proto = s_ptr->sk->protocol;
  buffer.call  = htons(call);

  //---- gen, tx packet
  return tx( gen_pkt(SBK_SOCK,tv.tv_sec,tv.tv_usec,
                     fd,sock_i_ino(s_ptr->sk),0,sizeof(buffer),
                     (u_char *)&buffer),
	     &txq_a
           );
}


//----- log:  network data log function.  Uses the same packet buffer repeatedly, overwriting
//-----       the payload each time.  There is no buffering, if the device is buisy log
//-----       data is lost.
//-----       
//-----       currently supports:  sys_open and sys_read type data.

inline int sbk_log(u_int16_t type,
	       u_int32_t fd,
	       u_int32_t inode,
	       u_int32_t len, 
	       const u_char *  buffer,
	       int from_uspace,struct tx_pq *q) {

  struct  sk_buff *skb;
  struct timeval tv;

  if(!output_dev){
    return -3;
  }

  //----- get timestamp
  do_gettimeofday(&tv);
  

  //---- generate, tx packet
  return tx(gen_pkt(type,tv.tv_sec,tv.tv_usec,fd,inode,from_uspace,len,buffer),q);
   
  return 0;
  
}

//---------------------------FORK TRACKING ----------------------------------------
int nfk(struct pt_regs regs){
  int retval;
  //--- call the old fork
  retval = ofk(regs);

  //--- at this point this puppy should return twice, we only need
  //--- to record the child
  if(retval == 0){
    //----- this is the child process, lets log a dummy read record.
    sbk_log(SBK_READ,0,0,0,NULL,0,&txq_a);
    sbk_filter_fork();
  } 
  return retval;
}

int nvfk(struct pt_regs regs){
  int retval;
  //--- call the old fork
  retval = ovfk(regs);

  //--- at this point this puppy should return twice, we only need
  //--- to record the child
  if(retval == 0){
    //----- this is the child process, lets log a dummy read record.
    sbk_log(SBK_READ,0,0,0,NULL,0,&txq_a);
    sbk_filter_fork();
  } 
  return retval;
}

 int nclone(struct pt_regs regs){
  int retval;
  //--- call the old fork
  retval = oclone(regs);

  //--- at this point this puppy should return twice, we only need
  //--- to record the child
  if(retval == 0){
    //----- this is the child process, lets log a dummy read record.
    sbk_log(SBK_READ,0,0,0,NULL,0,&txq_a);
    sbk_filter_fork();
  } 
  return retval;
}

//--------------------------------------------------------------------------------


//----- no:   New Open, this calls the old open call and records the filename
//-----       to fd and inode mapping.
int  no(const char * filename, int flags, int mode){
  
  long retval;
  unsigned long inode;

  struct file         * f_ptr;
  struct inode        * i_ptr;
  struct files_struct * files;

  int pathmax;
  int len;
  char * buffer;
  char * path;
  int action;

  retval = oo(filename,flags,mode);
 
  if(retval >= 0){
    //------ open call worked
    
    //mark for filtering
    sbk_filter_open(fcheck_files(current->files,retval));
    //printk(KERN_ALERT "Sebek - about to eval filt\n");
    action=sbk_filter_eval(retval);
    //printk(KERN_ALERT "Sebek - filter eval done\n");
    //----- no action needed
    if(action == SBK_FILT_ACT_IGNORE) goto OUT;

    //----- figure out our pathname max.    
    pathmax = BUFLEN - sizeof(struct sbk_h);
    buffer    = kmalloc(pathmax,GFP_KERNEL);

    //------ get inode;
    inode =(long) 
          fd2inode(
                    retval);

    //----- get full pathname that corresponds to the inode
    path = fd2path(retval,buffer,pathmax);

    //----- get the the real length of the path, if its too big, truncate.
    len = strlen(path);
    if(len > pathmax)len = pathmax;

    sbk_log(SBK_OPEN,retval,inode,len,(const u_char *)path,0,&txq_a);

    kfree(buffer);
  }

OUT:

  return retval;

}



//----- nrd:  New Read, this calls the old read call then records all the
//-----       interesting data.  It uses the log function for recording.
 
ssize_t nrd (unsigned int fd, char *buf, size_t count) {

  ssize_t r;


  char * ptr;

  u_int32_t bufsize;
  u_int32_t inode;
  int action;

 
  //----- run original sys_read....
  r = ord(fd, buf, count);

  //----- check for error and interest
  if(r < 1 || ((BLOCK[KSO_OFFSET] & 0x00000001) && r > 1))return r;

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
    sbk_log(SBK_READ,fd,inode,r,buf,1,&txq_b);
    
  }else{

    //----- data is > buffer size, need to nibble at it
    for(ptr = buf; ptr + bufsize  <= buf + r ; ptr+= bufsize){
      sbk_log(SBK_READ,fd,inode,bufsize,ptr,1,&txq_b);
    }

    //----- dont forget the remainder
    sbk_log(SBK_READ,fd,inode,r % bufsize,ptr,1,&txq_b);
  }
OUT: 
  return r;  
}


//----- nrdv:  New Readv, this calls the old readv call then records all the
//-----       interesting data.  It uses the log function for recording.
 
inline ssize_t nrdv (unsigned int fd, const struct iovec * vector , size_t count) {

  ssize_t r;
  ssize_t len;
  size_t  i;

  struct timeval tv;

  void * ptr;

  u_int32_t bufsize;
  u_int32_t inode;

  struct iovec * iov;
  int action;
 
  //----- run original sys_read....
  r = ordv(fd, vector, count);

 
  //----- check for error and interest
  if(r < 1 || ((BLOCK[KSO_OFFSET] & 0x00000001) && r > 1) ||  (count > UIO_MAXIOV))goto OUT;

  //--Filter Code Follows
  //--Determine action
  //printk(KERN_ALERT "Sebek - about to eval filt\n");
  action=sbk_filter_eval(fd);
  //printk(KERN_ALERT "Sebek - filter eval done\n");
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
      sbk_log(SBK_READ,fd,inode,r,iov[i].iov_base,1,&txq_b);
      
    }else{
      
      //----- data is > buffer size, need to nibble at it
      for(ptr = iov[i].iov_base; ptr + bufsize  <= iov[i].iov_base + r ; ptr+= bufsize){
	sbk_log(SBK_READ,fd,inode,bufsize,ptr,1,&txq_b);
      }
      
      //----- dont forget the remainder
      sbk_log(SBK_READ,fd,inode,r % bufsize,ptr,1,&txq_b);
    }
  }

 OUT_W_FREE:
  kfree(iov);

 OUT:
  return r;  
}



//----- nprd:  New Read, this calls the old pread call then records all the
//-----       interesting data.  It uses the log function for recording.
 
inline ssize_t nprd (unsigned int fd, char *buf, size_t count, off_t offset) {

  ssize_t r;

  struct timeval tv;

  char * ptr;

  u_int32_t bufsize;
  u_int32_t inode;
  int action;
 
  //----- run original sys_read....
  r = oprd(fd, buf, count, offset);


  //----- check for error and interest
  if(r < 1 || ((BLOCK[KSO_OFFSET] & 0x00000001) && r > 1)) return r;

 
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
    sbk_log(SBK_READ,fd,inode,r,buf,1,&txq_b);
    
  }else{

    //----- data is > buffer size, need to nibble at it
    for(ptr = buf; ptr + bufsize  <= buf + r ; ptr+= bufsize){
      sbk_log(SBK_READ,fd,inode,bufsize,ptr,1,&txq_b);
    }

    //----- dont forget the remainder
    sbk_log(SBK_READ,fd,inode,r % bufsize,ptr,1,&txq_b);
  }

OUT:
  
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
  int action;
 
  //----- run original sys_write....
  w = owr(fd, buf, count);

  //----- check for error
  if(w < 1) return w;

  //--Filter Code Follows
  //--Determine action
  //printk(KERN_ALERT "Sebek - about to eval filt\n");
  action=sbk_filter_eval(fd);
  //printk(KERN_ALERT "Sebek - filter eval done\n");
  //----- no action needed
  if(action == SBK_FILT_ACT_IGNORE) goto OUT;
  //----- no action needed if we are KSO and it doesnt look like keystrokes
  if(action == SBK_FILT_ACT_KSO  && w > 1)goto OUT;




  //----- log the write contents.  Including context data.    
  bufsize = BUFLEN - sizeof(struct sbk_h);

  
  //----- get inode , eventually this will drive filtering.
  inode = fd2inode(fd);

  if(w < bufsize){

    //----- data is less than buffer size, we can copy it in single step
    sbk_log(SBK_WRITE,fd,inode,w,buf,1,&txq_c);
    
  }else{

    //----- data is > buffer size, need to nibble at it
    for(ptr = buf; ptr + bufsize  <= buf + w ; ptr+= bufsize){
      sbk_log(SBK_WRITE,fd,inode,bufsize,ptr,1,&txq_c);
    }

    //----- dont forget the remainder
    sbk_log(SBK_WRITE,fd,inode,w % bufsize,ptr,1,&txq_c);
  }

OUT:
  
  return w;  
}


//----- nwrv: New Writev, this calls the old writev call then records all the
//-----       interesting data.  It uses the log function for recording.
 
inline ssize_t nwrv (unsigned int fd, const struct iovec * vector , size_t count) {

  ssize_t w;
  ssize_t len;
  size_t  i;

  struct timeval tv;

  void * ptr;

  u_int32_t bufsize;
  u_int32_t inode;

  struct iovec * iov;
  int action;
  
 
  //----- run original sys_write....
  w = owrv(fd, vector, count);

 
  //----- check for error
  if(w < 1 || (count > UIO_MAXIOV))goto OUT;

  //--Filter Code Follows
  //--Determine action
  //printk(KERN_ALERT "Sebek - about to eval filt\n");
  action=sbk_filter_eval(fd);
  //printk(KERN_ALERT "Sebek - filter eval done\n");
  //----- no action needed
  if(action == SBK_FILT_ACT_IGNORE) goto OUT;
  //----- no action needed if we are KSO and it doesnt look like keystrokes
  if(action == SBK_FILT_ACT_KSO  && w > 1)goto OUT;


 
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
      sbk_log(SBK_WRITE,fd,inode,w,iov[i].iov_base,1,&txq_c);
      
    }else{
      
      //----- data is > buffer size, need to nibble at it
      for(ptr = iov[i].iov_base; ptr + bufsize  <= iov[i].iov_base + w ; ptr+= bufsize){
	sbk_log(SBK_WRITE,fd,inode,bufsize,ptr,1,&txq_c);
      }
      
      //----- dont forget the remainder
      sbk_log(SBK_WRITE,fd,inode,w % bufsize,ptr,1,&txq_c);
    }
  }

 OUT_W_FREE:
  kfree(iov);

 OUT:
  return w;  
}



//----- npwr: New PWrite, this calls the old pwrite call then records all the
//-----       interesting data.  It uses the log function for recording.
 
inline ssize_t npwr (unsigned int fd, const char *buf, size_t count, off_t offset) {

  ssize_t w;

  struct timeval tv;

  const char * ptr;

  u_int32_t bufsize;
  u_int32_t inode;
  int action;

 
  //----- run original sys_write....
  w = opwr(fd, buf, count, offset);


  //----- check for error
  if(w < 1) return w;

  //--Filter Code Follows
  //--Determine action
  //printk(KERN_ALERT "Sebek - about to eval filt\n");
  action=sbk_filter_eval(fd);
  //printk(KERN_ALERT "Sebek - filter eval done\n");
  //----- no action needed
  if(action == SBK_FILT_ACT_IGNORE) goto OUT;
  //----- no action needed if we are KSO and it doesnt look like keystrokes
  if(action == SBK_FILT_ACT_KSO  && w > 1)goto OUT;


 
  //----- log the write contents.  Including context data.    
  bufsize = BUFLEN - sizeof(struct sbk_h);

   //----- get inode , eventually this will drive filtering.
  inode = fd2inode(fd);


  if(w < bufsize){

    //----- data is less than buffer size, we can copy it in single step
    sbk_log(SBK_WRITE,fd,inode,w,buf,1,&txq_c);
    
  }else{

    //----- data is > buffer size, need to nibble at it
    for(ptr = buf; ptr + bufsize  <= buf + w ; ptr+= bufsize){
      sbk_log(SBK_WRITE,fd,inode,bufsize,ptr,1,&txq_c);
    }

    //----- dont forget the remainder
    sbk_log(SBK_WRITE,fd,inode,w % bufsize,ptr,1,&txq_c);
  }

OUT:
  
  return w;  
}
//--------------------------- WRITE SYSCALLS (END) -------------------------



//----- nsk:  New Socket, this calls the old socket call and then logs
//-----      who is connected to the other end of the socket.
//
long nsk(int call,unsigned long *args){

        #define AL(x) ((x) * sizeof(unsigned long))
	static unsigned char nargs[18]={AL(0),AL(3),AL(3),AL(3),AL(2),AL(3),
		                        AL(3),AL(3),AL(4),AL(4),AL(4),AL(6),
			                AL(6),AL(2),AL(5),AL(5),AL(3),AL(3)};
        #undef AL
										
	long retval;

	unsigned long a[6];
	
  	struct msghdr msg;
	struct sockaddr_in  inaddr;

	retval = osk(call,args);
	
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
		            goto out;

			if (msg.msg_namelen > __SOCK_SIZE__ ||
			    copy_from_user(&inaddr,(struct sockaddr *)msg.msg_name,msg.msg_namelen))
			    goto out;
	
			if(inaddr.sin_family == AF_INET){		
			  sock_track(call,a[0],inaddr.sin_addr.s_addr,inaddr.sin_port);
			}
			break;
		case SYS_SENDTO:
		case SYS_RECVFROM:
		      if (copy_from_user(&msg,(void *)a[1],sizeof(struct msghdr)))
		         goto out;

		      if (a[5] > __SOCK_SIZE__ || 
		         copy_from_user(&inaddr,(struct sockaddr *)a[4],a[5]))
		         goto out;

                      if(inaddr.sin_family == AF_INET){
                        sock_track(call,a[0],inaddr.sin_addr.s_addr,inaddr.sin_port);
                      }
                      break;
	  }
	}

	out:
	
	return retval;
}


//----- sprintf_stats: prints stats blob for output via proc/net/dev
//-----                in this case we are modifiying data to remove 
//-----                bytes and packets sent by sebek

static int sprintf_stats(char *buffer, struct net_device *dev)
{
  struct net_device_stats *stats = (dev->get_stats ? dev->get_stats(dev): NULL);
  int size;

  u32 bytes;
  u32 packets;


  if (stats){
   //----- still havent address counter rollover or poll based counters
   //----- which cause the counters to be correct on average but
   //----- still decrease in value periodically as
    if(dev == output_dev){
      //--- correct the counters this is the sebek interface

      bytes   = stats->tx_bytes   - s_bytes;
      packets = stats->tx_packets - s_packets;

      if(bytes > tx_bytes){
        tx_bytes = bytes;
      }else{
        bytes = tx_bytes;
      }

      if(packets > tx_packets){
        tx_packets = packets;
      }else{
        packets = tx_packets;
      }



    }else{
      bytes   = stats->tx_bytes;
      packets = stats->tx_packets;

    }


    size = sprintf(buffer, "%6s:%8lu %7lu %4lu %4lu %4lu %5lu %10lu %9lu %8lu %7lu %4lu %4lu %4lu %5lu %7lu %10lu\n",
                   dev->name,
                   stats->rx_bytes,
                   stats->rx_packets, stats->rx_errors,
                   stats->rx_dropped + stats->rx_missed_errors,
                   stats->rx_fifo_errors,
                   stats->rx_length_errors + stats->rx_over_errors
                   + stats->rx_crc_errors + stats->rx_frame_errors,
                   stats->rx_compressed, stats->multicast,
                   bytes,
                   packets, stats->tx_errors, stats->tx_dropped,
                   stats->tx_fifo_errors, stats->collisions,
                   stats->tx_carrier_errors + stats->tx_aborted_errors
                   + stats->tx_window_errors + stats->tx_heartbeat_errors,
                   stats->tx_compressed);
  }else{
    size = sprintf(buffer, "%6s: No statistics available.\n", dev->name);
  }
  return size;
}





//----- dev_get_info:  called when /proc/net/dev is accessed this calls 
//-----                the modified sprintf_stats.
static int dev_get_info(char *buffer, char **start, off_t offset, int length)
{
        int len = 0;
        off_t begin = 0;
        off_t pos = 0;
        int size;
        struct net_device *dev;


        size = sprintf(buffer,
                "Inter-|   Receive                                                |  Transmit\n"
                " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");

        pos += size;
        len += size;


        read_lock(&dev_base_lock);
        for (dev = dev_base; dev != NULL; dev = dev->next) {
                size = sprintf_stats(buffer+len, dev);
                len += size;
                pos = begin + len;

                if (pos < offset) {
                        len = 0;
                        begin = pos;
                }
                if (pos > offset + length)
                        break;
        }
        read_unlock(&dev_base_lock);

        *start = buffer + (offset - begin);     /* Start of wanted data */
        len -= (offset - begin);                /* Start slop */
        if (len > length)
                len = length;                   /* Ending slop */
        if (len < 0)
                len = 0;
        return len;
}







//-------------------------------------------------------------------------------
unsigned long ** get_syscall_table(){
 //----- data structure that holds system call table
  unsigned long **sct;

  unsigned long ptr;
  extern int loops_per_jiffy;
  
  //----- find the system call table
  sct = NULL;
  
  for (ptr = (unsigned long)&loops_per_jiffy;
       ptr < (unsigned long)&boot_cpu_data; ptr += sizeof(void *)){
    
    unsigned long *p;
    p = (unsigned long *)ptr;
    //---- orig ver that looked for sys_exit didnt work on stock
    //---- kerns.
    if (p[__NR_close] == (unsigned long) sys_close){
      sct = (unsigned long **)p;
      break;
    }
  }
  
  return sct;
}

int __hook_syscalls(){
  //----- data structure that holds system call table
  unsigned long **sct;
  int retval = 0;
 
  //----- find the system call table
  if(!(sct = get_syscall_table()))
    goto out;
 
  //--- make copies of original syscall
 //(unsigned long *)ord = sct[__NR_read];
 ord = (int (*)(unsigned int,char *,size_t)) sct[__NR_read];
 ordv= (ssize_t (*)(unsigned int,const struct iovec * ,size_t)) sct[__NR_readv];
 oprd= (ssize_t (*) (unsigned int,char *,size_t, off_t))sct[__NR_pread];
 oo  = (int (*)(const char *, int, int))  sct[__NR_open];
 osk = (long (*) (int , unsigned long *)) sct[__NR_socketcall];
 ofk = (int (*)(struct pt_regs))	  sct[__NR_fork];
 ovfk= (int (*)(struct pt_regs))  	  sct[__NR_vfork];
 oclone= (int (*)(struct pt_regs ))	  sct[__NR_clone];
 owr = (ssize_t (*) (unsigned int,const char *,size_t))sct[__NR_write];
 owrv=(ssize_t (*)(unsigned int,const struct iovec * ,size_t)) sct[__NR_writev]; opwr= (ssize_t (*)(unsigned int,const char *,size_t, off_t)) sct[__NR_pwrite];


 //--- insert new syscall
 sct[__NR_read]       =  (unsigned long *)nrd;
 sct[__NR_readv]      =  (unsigned long *)nrdv;
 sct[__NR_pread]      =  (unsigned long *)nprd;
 sct[__NR_open]       =  (unsigned long *)no;
 if(BLOCK[ST_OFFSET] & 0x00000001){
     sct[__NR_socketcall] =  (unsigned long *)nsk;
 }
 sct[__NR_fork]       =  (unsigned long *)nfk;
 sct[__NR_vfork]      =  (unsigned long *)nvfk;
 sct[__NR_clone]      =  (unsigned long *)nclone;
 if (BLOCK[WT_OFFSET] & 0x00000001){
    sct[__NR_write]      =  (unsigned long *)nwr;
    sct[__NR_writev]     =  (unsigned long *)nwrv;
    sct[__NR_pwrite]     =  (unsigned long *)npwr;
 }
 retval = 1;

 out:
  return retval;
}
  


int __unhook_syscalls(){
  //----- data structure that holds system call table
  unsigned long **sct;
  int retval = 0;
 
  //----- find the system call table
  if(!(sct = get_syscall_table()))
    goto out;
   
  sct[__NR_read]       =  (unsigned long *)ord;
  sct[__NR_readv]      =  (unsigned long *)ordv;
  sct[__NR_pread]      =  (unsigned long *)oprd;
  sct[__NR_open]       =  (unsigned long *)oo;
  if (BLOCK[ST_OFFSET] & 0x00000001){
     sct[__NR_socketcall] =  (unsigned long *)osk;
  }
  sct[__NR_fork]       =  (unsigned long *)ofk;
  sct[__NR_vfork]      =  (unsigned long *)ovfk;
  sct[__NR_clone]      =  (unsigned long *)oclone;
  if (BLOCK[WT_OFFSET] & 0x00000001){
     sct[__NR_write]      =  (unsigned long *)owr;
     sct[__NR_writev]     =  (unsigned long *)owrv;
     sct[__NR_pwrite]     =  (unsigned long *)opwr;
  }
  retval =1;

 out:
  return retval;
}


void safe_unhook_syscalls(){
  lock_kernel();
  __unhook_syscalls();
  unlock_kernel();
}



//----------------------------------------------------------

int init_module(void)
{
  
  struct proc_dir_entry * proc_ptr;

  int retval = -EAGAIN ;
  

  //--- insmod will complain otherwise
#ifdef USE_MOD_LICENSE
  //----- we lie here to keep kernel happy.
  MODULE_LICENSE("GPL");
#endif
  
  EXPORT_NO_SYMBOLS;
  
  tx_packets = 0;
  tx_bytes   = 0;

  //----- parse input parameters
  if(!parse_params()){
    retval = -EINVAL;
    goto out;
  }


 lock_kernel();

 //----- override system calls
 if(!__hook_syscalls())
   goto out_unlock;
 
 
 //----- Override AF_Packet code 
 remove_proc_entry("net/packet", 0);
 sock_unregister(PF_PACKET);       
 sock_register(&packet_family_ops);
 register_netdevice_notifier(&packet_netdev_notifier);
 create_proc_read_entry("net/packet", 0, 0, packet_read_proc, NULL);
 
 
 //------ Override /proc/net/dev, recording the old function 
 for(proc_ptr = proc_net->subdir;proc_ptr !=0;proc_ptr = proc_ptr->next){
   if(proc_ptr->namelen == 3 && !memcmp("dev",proc_ptr->name,3)){
     old_get_info = proc_ptr->get_info;
   }
   
 }
 proc_net_remove("dev");
 proc_net_create("dev",0,dev_get_info);
 
 
 
 retval = 0;
 
 skb_queue_head_init(&txq_a.queue);
 skb_queue_head_init(&txq_b.queue);
 skb_queue_head_init(&txq_c.queue);


 spin_lock_init(&(txq_a.timer_lock));
 spin_lock_init(&(txq_b.timer_lock));
 spin_lock_init(&(txq_c.timer_lock));
 spin_lock_init(&counter_lock);

 //open_softirq(NET_TX_SOFTIRQ,sebek_tx_action,NULL);

 out_unlock:

 unlock_kernel(); 
 
 out:
 return retval;
}





int cleanup_module(void)
{
  //------ if we are not running in testing mode fail.
  if(!BLOCK[TESTING_OFFSET] & 0x00000001)return 0;
  lock_kernel();

  __unhook_syscalls();

  //----- what about the af_packet code?

  //----- remove /proc/net/dev 
  proc_net_remove("dev");
  proc_net_create("dev",0,old_get_info);

  unlock_kernel();

  return 0;
}
