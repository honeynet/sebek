//--------------------------------------------------------------------
//----- $Id: sbk_extract.c 4560 2006-10-18 15:11:34Z redmaze $
//--------------------------------------------------------------------
/*
 * Copyright (C) 2001 - 2003 The Honeynet Project.
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


#include "sbk_extract.h"

pcap_t    *pcap_nic;
struct bpf_program filter;

uint16_t  dst_port   = 1101;
uint32_t  last_sbk_rec_id = 0;
uint32_t  last_report  = 0;
uint32_t  pkt_counter  = 0;


uint32_t  pkt_head_sz = sizeof(struct eth_h) + sizeof(struct ip_h) + sizeof(struct udp_h) + sizeof(struct sbk_h); 

int main(int argc, char **argv)
{

  int buffsize   = 65535;	
  int promisc   = 1;
  int timeout   = 1000;
  int use_file  = 0;
	
  char pcap_err[PCAP_ERRBUF_SIZE];
  u_char buffer[255];	
  char pcap_file[255];
  char user_name[255];
  char chroot_dir[255];
  char filter_str[255];
  char dev[255];
  char c;
  int user_id;	
  struct passwd *up;

  memset(user_name,0,255);
  memset(chroot_dir,0,255);  


  while ((c = getopt(argc,argv,"hi:p:f:u:c:")) != EOF) {
    switch(c){
    case 'i':
      strncpy(dev,optarg,254);
      break;
    case 'p':
      dst_port = atoi(optarg);
      break;
    case 'h':
      help();
      break;
    case 'f':
      use_file = 1;
      strncpy(pcap_file,optarg,254);
      break;
    case 'u':
      strncpy(user_name,optarg,254);
      break;
    case 'c':
      strncpy(chroot_dir,optarg,254);
      break;    
    }
  }


  if(!use_file){
    if(!strlen(dev)){
      strncpy(dev,DEFAULT_IF,254);
    }
    //----- pull data off net
    if ((pcap_nic = pcap_open_live(dev, buffsize, promisc, timeout, pcap_err)) == NULL) {
      perror(pcap_err);
      exit(-1);
    }
    if (strlen(chroot_dir)>0)    {
       if(0!=chroot(chroot_dir)){
           fprintf(stderr,"Warning: could not chroot to directory %s",chroot_dir);	
           exit(-1);
       }
    }
    if (strlen(user_name)>0)   {
       up=(struct passwd *)getpwnam((char *) user_name);
       user_id= (up== NULL)? -1:(int)  (up->pw_uid);
       if (user_id !=-1)
            setuid(user_id);
    }

    fprintf(stderr," monitoring %s: looking for UDP dst port %i\n",dev,dst_port);
  }else{
    //----- pull data from file
    if ((pcap_nic = pcap_open_offline(pcap_file, pcap_err)) == NULL) {
      perror(pcap_err);
      exit(-1);
    }
    fprintf(stderr," opening %s: looking for UDP dst port %i\n",pcap_file,dst_port);
  }
  

  //--- compile BPF filter
  snprintf(filter_str,255, "udp dst port %i",dst_port);

  if(pcap_compile(pcap_nic, &filter, filter_str, 1, 0) < 0){
    fprintf(stderr,"OpenPcap() FSM compilation failed: %s PCAP command: %s\n", pcap_geterr(pcap_nic), filter_str);
    exit(1);
  }
   

  //--- set the pcap filter 
  if(pcap_setfilter(pcap_nic, &filter) < 0) {
    fprintf(stderr,"OpenPcap() setfilter: \n\t%s\n", pcap_geterr(pcap_nic));
    exit(1);
  }


  
  while (pcap_loop(pcap_nic, -1, (pcap_handler)handler, buffer));
  
  return 0;
}



//----- funtion that looks up agent record.  each sebek client is given a record with which we can track packet loss.
struct agent * get_agent(uint32_t addr){
  int x;
  struct agent * ptr;

  x = 0;
  //--- search for existing
  for(ptr=agent_list_head;ptr!=NULL;ptr=ptr->next){
    x++;
    if(ptr->ip_addr == addr)return ptr;
  }
  
  //--- ok we did not find a match create new
  //--- oh look our failed search left the ptr at the end of the list
  if(x > MAX_SBK_AGENT)return NULL;

  if(!(ptr = malloc(sizeof(struct agent)))){
    return NULL;
  }

  
  //--- initialize the new record;
  ptr->ip_addr     = addr;
  ptr->pkt_counter = 0;
  ptr->last_rec_id = 0;
  ptr->last_time   = 0;
  ptr->next        = NULL;


  //--- bring into linked list
  if(agent_list_head == NULL){
    agent_list_head = ptr;
  }else{
    ptr->next = agent_list_head;
    agent_list_head = ptr;
  }
   

  return ptr;
}


//----- packet loss is tracked based on the record id provided by sebek.
//----- loss could happen in the honyepot's kernel, a network device
//----- or locally, we dont really care, we just want to make sure we
//----- notice that we are losing data.
void agent_track_loss(uint32_t agent_id, uint32_t record_id){
  time_t         epoc_time;
  struct tm      *tm;
  uint32_t       loss;
  float          loss_per;
  struct agent  * agent;
  
  struct in_addr ip;

  ip.s_addr = htonl(agent_id);

  //------ giving up on getting useful data from pcap_stats  for lost data
  agent = get_agent(agent_id);
  
  if(agent){
    agent->pkt_counter++;
    epoc_time = time(NULL);
    
    if((epoc_time - agent->last_time) > 60){
       tm        = gmtime(&epoc_time);	

      if((agent->last_rec_id + agent->pkt_counter) <=  record_id){
	loss = record_id - (agent->pkt_counter + agent->last_rec_id);
	if(loss > 0 && agent->pkt_counter > 1){
	  loss_per = (loss*1.0 / (agent->pkt_counter+loss)*1.0)*100;
	}else{
	  loss     = 0;
	  loss_per = 0;
	}
	
	fprintf(stderr,"%s %.4i/%.2i/%.2i %.2i:%.2i:%.2i  record %u received %u lost %u (%.2f percent)\n",
		inet_ntoa(ip),
		1900 + tm->tm_year,1+ tm->tm_mon,tm->tm_mday,tm->tm_hour,tm->tm_min,tm->tm_sec,
	        record_id,
		agent->pkt_counter,  
		loss,
		loss_per);
      }else{
	fprintf(stderr,"%s %.4i/%.2i/%.2i %.2i:%.2i:%.2i: record %u received %u counter roll or out of order packets.\n",
	       inet_ntoa(ip),
                1900 + tm->tm_year,1+ tm->tm_mon,tm->tm_mday,tm->tm_hour,tm->tm_min,tm->tm_sec,
		record_id,
                agent->pkt_counter);
 	
      }
      
      agent->last_time     = epoc_time;
      agent->last_rec_id   = record_id;
      agent->pkt_counter   = 0;
    }
  }
  
  
}




void handler (char *usr, const struct pcap_pkthdr *pcapheader, const u_char *pkt) {
	
	struct eth_h   *ethheader;
	struct ip_h    *ipheader;
	struct udp_h   *udpheader;
	struct sbk_h   *sbkheader;
	u_char         *data;
       	


	uint16_t dpt;
	uint32_t datalen;



	//----- ignore packets that are just too short
	if(pcapheader->caplen < pkt_head_sz ){
	
	  return;
	}


	ethheader = (struct eth_h *) pkt;
	
	//----- IP Packet?
	if (ethheader->type == htons(0x0800)) {
	
	  ipheader = (struct ip_h *) (pkt + sizeof(struct eth_h));
         
	  //------ UDP Packet?
	  if (ipheader->proto == 0x11) {
	    
            udpheader = (struct udp_h *) ((u_char *)ipheader + sizeof(struct ip_h));
	   
	    dpt = ntohs(udpheader->dport);

	    //---- Sebek Packet?
	    if(dpt == dst_port){
	      
	      sbkheader =  (struct sbk_h *) ((u_char *)udpheader + sizeof(struct udp_h));	 
	
	      //----- only process version 3 records
	      if(ntohs(sbkheader->ver) == SBK_VER){
		
		datalen = ntohl(sbkheader->length); 
		
		data = (u_char *) ((u_char *)sbkheader + sizeof(struct sbk_h));
	     
		//----- check for valid data len
		if(datalen + pkt_head_sz  == pcapheader->caplen){

		  //----- header data seems ok
		  fwrite(&(pcapheader->ts.tv_sec),4,1,stdout);          //----- write the pcap time sec
		  fwrite(&(pcapheader->ts.tv_usec),4,1,stdout);	        //----- write the pcap time usec
		  fwrite(&(ipheader->src),4,1,stdout);		        //----- write the SRC IP
		  fwrite(sbkheader,sizeof(struct sbk_h),1,stdout);	//----- write the Sebek Header
		  fwrite(data,datalen,1,stdout);			//----- write the Sebek data
  	    	  fflush(stdout);
	        
		  agent_track_loss(ntohl(ipheader->src.s_addr), ntohl(sbkheader->counter));
		  
		}else{
		  fprintf(stderr,"malformed sebek record: data length=%u  packet caplen=%u\n",datalen,pcapheader->caplen);
		}
		
	      }else{
		fprintf(stderr,"Unexpected Sebek PDU version: %u \n",ntohs(sbkheader->ver));
	      }

	    }
	  }		
	}
	return;
}



void help(){

  printf("sbk_extract (%s %s)\n",PACKAGE,VERSION);
  printf("  -i <device> get packets from interface\n");
  printf("  -f <file> get packets from pcap file\n");
  printf("  -p <port> dest port to look for\n");
  printf("  -u <user_name> User name to setuid to\n");
  printf("  -c <path_name> Path to chroot to\n");
  printf("  -h  This screen\n");

  exit(0);

}
