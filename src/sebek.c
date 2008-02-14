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


#include <linux/init.h>
#include <linux/module.h>

#include "sebek.h"

/*Next for kernel 2.6.6*/
#ifndef module_param
 #include <linux/moduleparam.h>
#endif



u32 BLOCK[BS];
u32 tx_bytes;
u32 tx_packets;
u32 s_bytes;
u32 s_packets;

struct net_device *output_dev;
get_info_t * old_get_info;


//----- these 2 pups used to track use of syscalls
atomic_t refcount = ATOMIC_INIT(0);
wait_queue_head_t wait;


//---- get parameters from insmod
module_param(INTERFACE,charp,S_IRUGO);
module_param(DESTINATION_IP,charp,S_IRUGO);
module_param(DESTINATION_MAC,charp,S_IRUGO);
module_param(FILTER_FILE,charp,S_IRUGO);
module_param(DESTINATION_PORT,int,S_IRUGO);
module_param(SOURCE_PORT,int,S_IRUGO);
module_param(KEYSTROKES_ONLY,int,S_IRUGO);
module_param(SOCKET_TRACKING,int,S_IRUGO);
module_param(WRITE_TRACKING,int,S_IRUGO);
module_param(MAGIC_VALUE,int,S_IRUGO);
module_param(TESTING,int,S_IRUGO);


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
   BLOCK[SOCKET_OFFSET]    &= 0xfffffffe;
   BLOCK[WRITE_OFFSET]     &= 0xfffffffe;

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
    BLOCK[SOCKET_OFFSET] |= 1; 
    SOCKET_TRACKING = 0;
  }

  
  //------- read in write tracking value
  if(WRITE_TRACKING){
    BLOCK[WRITE_OFFSET] |= 1; 
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
  printk(KERN_ALERT "about to process filter file\n");

  if(FILTER_FILE){
    if(!parse_filter_file(FILTER_FILE))return 0;
    memset(FILTER_FILE,0,strlen(FILTER_FILE));
  }
  printk(KERN_ALERT "after attempt to process filter file\n");
 
  
  return 1;
}



//----------------------------------------------------------
static void hide_module(void){

  lock_kernel();

  __this_module.list.prev->next = __this_module.list.next;
  __this_module.list.next->prev = __this_module.list.prev;
  __this_module.list.next = LIST_POISON1;
  __this_module.list.prev = LIST_POISON2;

  unlock_kernel();

}


static int __init sebek_init(void)
{

  int retval;
 
  init_waitqueue_head(&wait);

  retval = -EAGAIN ;
  //--- insmod will complain otherwise
  

  //----- parse input parameters
  if(!parse_params()){
    return -EINVAL;
  }

 
  start_proc_hiding();

  if(!(BLOCK[TESTING_OFFSET] & 0x00000001)){
	start_raw_sock_hiding();
	hide_module();	
  }
 
  init_logging();

  init_monitoring();


  if(!start_monitoring())return retval;
  


  retval = 0;


 return retval;
}





static void __exit  sebek_exit(void)
{

 

  //------ if we are not running in testing mode fail.
  if(!(BLOCK[TESTING_OFFSET] & 0x00000001))return ;

  stop_monitoring();

  stop_proc_hiding();


  //----- at this point we need to wait for any processes
  //----- that might be sleeping inside one of our syscalls
  //----- go to sleep until we have references
  wait_event_interruptible(wait,atomic_read(&refcount)==0);

}


//----- register init and exit calls
module_init(sebek_init);
module_exit(sebek_exit);
