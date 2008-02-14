//--------------------------------------------------------------------
//----- $Header$
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


#include "sebek_extract.h"

int main(int argc, char **argv)
{

	int buffsize = 65535;	
	int promisc = 1;
	int timeout = 1000;		
	char pcap_err[PCAP_ERRBUF_SIZE];
	u_char buffer[255];	
        char pcap_file[255];
	char c;

	char *dev="";
	

	ethlen = sizeof(struct eth_h);
	iplen  = sizeof(struct ip_h);
	udplen = sizeof(struct udp_h);
       
	memset(logdir,0,255);
	strncpy(logdir,DEFAULT_LOG_DIR,254);

	while ((c = getopt(argc,argv,"hi:p:f:l:")) != EOF) {
	  switch(c){
	  case 'i':
	    dev = optarg;
	    break;
	  case 'p':
	    static_port = atoi(optarg);
	    break;
	  case 'h':
	    help();
	    break;
	  case 'f':
	    use_file = 1;
	    strncpy(pcap_file,optarg,254);
	    break;
	  case 'l':
	    memset(logdir,0,255);
	    strncpy(logdir,optarg,254);
	    break;
	    
	  }
        }


	if(!use_file){
	  //----- pull data off net
	  if ((pcap_nic = pcap_open_live(dev, buffsize, promisc, timeout, pcap_err)) == NULL) {
	    perror(pcap_err);
	    exit(-1);
	  }
	  printf(" opening %s: looking for UDP dst port %i\n",dev,static_port);
	}else{
	  //----- pull data from file
	  if ((pcap_nic = pcap_open_offline(pcap_file, pcap_err)) == NULL) {
	    perror(pcap_err);
	    exit(-1);
	  }
	  printf(" monitoring %s: looking for UDP dst port %i\n",pcap_file,static_port);
	}

       
	while (pcap_loop(pcap_nic, -1, (pcap_handler)handler, buffer));

	return 0;
}




void handler (char *usr, const struct pcap_pkthdr *header, const u_char *pkt) {
	
	struct eth_h   *ethheader;
	struct ip_h    *ipheader;
	struct udp_h   *udpheader;
	struct sbk_h   *sbkheader;
 
	int spt,size,dpt;

	struct sbk_h * hdr;

	struct pcap_stat stats;

	u_char * ptr;
	int x;
	int datalen;

	
        //----- set ptr to payload of packet.
        const u_char *tmp = pkt+ethlen+iplen+udplen;

	ethheader = (struct eth_h *) pkt;
	
	//----- IP Packet?
	if (ethheader->type == htons(0x0800)) {
	  
	  ipheader = (struct ip_h *) (pkt+ethlen);
         
	  //------ UDP Packet?
	  if (ipheader->proto == 0x11) {
	    udpheader = (struct udp_h *) (pkt+ethlen+iplen);
	    spt = ntohs(udpheader->sport);
	    dpt = ntohs(udpheader->dport);
	    size = ntohs(ipheader->len)- iplen - udplen;
	    udpheader = (struct udp_h *) (pkt+ethlen+iplen);

	    //---- Sebek Packet?
	    if(dpt == static_port){

	      hdr =  (struct sbk_h *)tmp;	     
	
	      //----- only process version 1 records
	      if(ntohs(hdr->ver) == 1){
   
		ptr = (u_char *)tmp+sizeof(struct sbk_h);
		datalen = ntohl(hdr->length);

		//----- check for valid data len
		if((datalen + sizeof(struct sbk_h) + sizeof(struct udp_h) + 
		    sizeof(struct ip_h) + sizeof(struct eth_h))  == header->len){

		  //----- header data seems ok
		  write(fileno(stdout),&(ipheader->src),4);
		  write(fileno(stdout),hdr,sizeof(struct sbk_h));
		  write(fileno(stdout),ptr,datalen);

		  pcap_stats(pcap_nic,&stats);
		  
		  if(stats.ps_drop - last_lost != 0){ 
		    fprintf(stderr,"\nwarning RX %u   Lost %u\n\n",stats.ps_recv,stats.ps_drop);
		  }

		}else{
		  fprintf(stderr,"malformed sebek record\n");
		}
		
	      }else{
		printf("Unexpected Sebek version: %u\n",ntohs(hdr->ver));
	      }

	    }
	  }		
	}
	return;
}



void help(){

  printf("sebek_extract (%s %s)\n",PACKAGE,VERSION);
  printf("  -i <device> get packets from interface\n");
  printf("  -f <file> get packets from pcap file\n");
  printf("  -p <port> dest port to look for\n");
  printf("  -h  This screen\n");

  exit(0);

}
