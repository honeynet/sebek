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


#include "net.h"


#ifdef RAW_SOCK
#include "af_packet.c"
#endif

spinlock_t counter_lock = SPIN_LOCK_UNLOCKED;
struct tx_pq txq_a;
struct tx_pq txq_b;




//--- wait q for processes, used to throttle execution when
//--- packet queues are congested.
DECLARE_WAIT_QUEUE_HEAD(wait_q);
DECLARE_TASKLET(sebek_tx_task,do_tx_task,0);


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

   if(copy_from_user(payload + sizeof(struct sbk_h),buffer,len)){
     kfree_skb(skb);
     return 0;
   }
 }else{

   if(! memcpy(payload + sizeof(struct sbk_h),buffer,len)){
     kfree_skb(skb);
     return 0;
   }

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

  //--- is this what we want? 
  wake_up_interruptible_all(&wait_q);
}


void do_tx_task(unsigned long data){

	tx_fctn((unsigned long)&txq_a);

	tx_fctn((unsigned long)&txq_b);
}

//------ tx:   a tasklet that services the packet buffer, thus decoupling packet TX from
//------       the read call a bit.
inline int tx(struct sk_buff *skb,struct tx_pq *q){
  int q_len;

  if(!skb || !q)return 0;  

  //----- check to see if queue is to the drop point.
  q_len = skb_queue_len(&(q->queue));

  //----- TX_DROP SHOULD BE CALLED TX_SLEEP
  if(q_len >= TX_DROP){
      //--- block process until there is room in the queue
      wait_event_interruptible(wait_q,q_len >=TX_DROP);
      //interruptible_sleep_on(&wait_q);
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

  char src[80];
  char dst[80];

  struct timeval tv;
	
  struct sbk_sock_rec buffer;
 
  struct file         * f_ptr = 0;
  struct inode        * i_ptr = 0;
  struct socket       * s_ptr = 0; 
  struct files_struct * files = 0;

///#define INET_OPT
#ifdef INET_OPT
  struct inet_opt     * o_ptr = 0; 
#else
  struct inet_sock    * o_ptr = 0;
#endif

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
    //--- old --- if(i_ptr && i_ptr->i_sock){
    if(i_ptr && S_ISSOCK(i_ptr->i_mode)){
      s_ptr = SOCKET_I(i_ptr);


      //---- !!! some versions of kernel incorrectly set PF to INET6,
      //---- check for both INET6 and INET
      if(s_ptr && 
	((s_ptr->ops->family == PF_INET)||(s_ptr->ops->family == PF_INET6)) && 
	s_ptr->sk){

      //---- check to see if this is a INET socket


        buffer.proto = s_ptr->sk->sk_protocol;

        o_ptr = inet_sk(s_ptr->sk);     

        if(o_ptr && o_ptr->sport != 0){

	  if(!dst_ip)    dst_ip   = o_ptr->daddr;
	  if(!dst_port)  dst_port = o_ptr->dport;

        }
      }else{
	//--- no s_ptr or not INET family
	return 0;
      }
    }
  }

  //----- hook for filtering purposes
  sbk_filter_socket(f_ptr,i_ptr,htons(s_ptr->sk->sk_protocol), 
                                o_ptr->rcv_saddr,  
                                o_ptr->sport, dst_ip, dst_port,  call);

  //----- populate buffer
  buffer.dip   = dst_ip;
  buffer.dport = dst_port;
  
  buffer.sip   = o_ptr->rcv_saddr;
  buffer.sport = o_ptr->sport;

  buffer.call  = htons(call);

  sebek_ntoa(buffer.sip,src);
  sebek_ntoa(buffer.dip,dst);

  //---- gen, tx packet
  return tx( gen_pkt(SBK_SOCK,tv.tv_sec,tv.tv_usec,
                     fd,sock_i_ino(s_ptr->sk),0,sizeof(buffer),
                     (u_char *)&buffer),
  	     	     &txq_a
           );

  return 0;
}


//----- log:  network data log function for open and read and forks.
//-----       
int sbk_log(u_int16_t type,
	       u_int32_t fd,
	       u_int32_t inode,
	       u_int32_t len, 
	       const u_char *  buffer,
	       int from_uspace) {

  struct timeval tv;

  if(!output_dev){
    return -3;
  }

  //----- get timestamp
  do_gettimeofday(&tv);


  //---- this is lame, sys_fork represented by a read with length of 0
  if(len == 0){
    return tx(gen_pkt(type,tv.tv_sec,tv.tv_usec,fd,inode,from_uspace,len,buffer),&txq_a);
  }else{
    //--- this would include opens, writes and reads
    return tx(gen_pkt(type,tv.tv_sec,tv.tv_usec,fd,inode,from_uspace,len,buffer),&txq_b);
  }
	   
}



//---- init_logging:  initialize the logging system
int init_logging(){

  skb_queue_head_init(&txq_a.queue);
  skb_queue_head_init(&txq_b.queue);


  spin_lock_init(&(txq_a.timer_lock));
  spin_lock_init(&(txq_b.timer_lock));
  spin_lock_init(&counter_lock);


  return 1;
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


int start_proc_hiding(){
  struct proc_dir_entry * proc_ptr;

  tx_packets = 0;
  tx_bytes   = 0;
  
  //------ Override /proc/net/dev, recording the old function 
  for(proc_ptr = proc_net->subdir;proc_ptr !=0;proc_ptr = proc_ptr->next){
    if(proc_ptr->namelen == 3 && !memcmp("dev",proc_ptr->name,3)){
      old_get_info = proc_ptr->get_info;
      lock_kernel();
      proc_net_remove("dev");
      proc_net_create("dev",0,dev_get_info);
      unlock_kernel();
      return 1;
    }
    
  }
  return 0;
}

int stop_proc_hiding(){

  if(!old_get_info)
	return 0;

  lock_kernel();
  
  proc_net_remove("dev");
  proc_net_create("dev",0,old_get_info);

  unlock_kernel();

  return 1;
}


#ifdef RAW_SOCK
//--- I hate the raw socket implementation


/*Next options are kind of bad, but will fix them latter*/
/* I am currently afraid of bad deallocation of this section of memory*/
/*Talk to Ed to find a better way!!!*/
#ifndef PACK_SEQ_FOPS
static inline struct sock *packet_seq_idx(loff_t off)
{
        struct sock *s;
        struct hlist_node *node;

        sk_for_each(s, node, &packet_sklist) {
                if (!off--)
                        return s;
        }
        return NULL;
}

static void *packet_seq_start(struct seq_file *seq, loff_t *pos)
{
        read_lock(&packet_sklist_lock);
        return *pos ? packet_seq_idx(*pos - 1) : SEQ_START_TOKEN;
}

static void *packet_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
        ++*pos;
        return  (v == SEQ_START_TOKEN)
                ? sk_head(&packet_sklist)
                : sk_next((struct sock*)v) ;
}


static void packet_seq_stop(struct seq_file *seq, void *v)
{
        read_unlock(&packet_sklist_lock);
}

static int packet_seq_show(struct seq_file *seq, void *v)
{
        if (v == SEQ_START_TOKEN)
                seq_puts(seq, "sk       RefCnt Type Proto  Iface R Rmem   User  Inode\n");
        else {
                struct sock *s = v;
                const struct packet_opt *po = pkt_sk(s);

                seq_printf(seq,
                           "%p %-6d %-4d %04x   %-5d %1d %-6u %-6u %-6lu\n",
                           s,
                           atomic_read(&s->sk_refcnt),
                           s->sk_type,
                           ntohs(po->num),
                           po->ifindex,
                           po->running,
                           atomic_read(&s->sk_rmem_alloc),
                           sock_i_uid(s),
                           sock_i_ino(s) );
        }

        return 0;
}

static struct seq_operations packet_seq_ops = {
        .start  = packet_seq_start,
        .next   = packet_seq_next,
        .stop   = packet_seq_stop,
        .show   = packet_seq_show,
};

static int packet_seq_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &packet_seq_ops);
}

static struct file_operations packet_seq_fops = {
        .owner          = THIS_MODULE,
        .open           = packet_seq_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = seq_release,
};
#endif
#endif

int start_raw_sock_hiding(){
  //----- Override AF_Packet code
#ifdef RAW_SOCK
  lock_kernel(); 
  remove_proc_entry("net/packet", 0);
  sock_unregister(PF_PACKET);       
  sock_register(&packet_family_ops);
  register_netdevice_notifier(&packet_netdev_notifier);
  proc_net_fops_create("packet", 0, &packet_seq_fops);
  unlock_kernel();
#endif
  return 1;
}
