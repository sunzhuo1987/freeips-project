//
// Copyright (c) 2006-2009 Niels Heinen
// All rights reserved.
//  
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//  
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//  
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 

#include <util.h>

extern int loop_analyzer;
extern int mode_offline;
extern int loop_sniffer;
extern struct linked_list *trafficlist;

//
// Analyze the packets
//

void pcap_analyzer() {

        log_info("Analyzer thread started: accepting data");
	struct list_entry *packet;
        struct traffic* traffic;

        while(loop_analyzer == 1) {

		packet = popListEntryPtr(trafficlist);
                // There might be no data
                if(packet == NULL || packet->data == NULL) {
                        //DEBUG(stdout,"No data in memory..\n");
                        //Avoid CPU hogging
                        usleep(10000);
                        pthread_yield();

                        //If offline modes, we reached EOF
                        if(mode_offline == 1 && loop_sniffer == 0) {
				DEBUG(stdout, "EOF? Analyzer will stop!\n");
                                loop_analyzer=0;
                        }
                } else {
			stats_increase_cnt(CNT_QUEUE_POP,1);

			traffic = (struct traffic*)packet->data;
                        traffic_analyzer(traffic,packet);
                }
        }

	DEBUG(stdout,"Analyzer thread is finished\n");
        pthread_exit(0);
}


int traffic_analyzer(void *data,struct list_entry *packet) {
        struct traffic *traffic = (struct traffic *)data;
        struct signature* sig = NULL;
	int offset  = 0;
	int tr_offset = sizeof(struct ether_header) + (traffic->iphdr->ip_hl * 4);

	// Update stats (IP datagram cnt)
	stats_increase_cnt(CNT_IP,1);
	stats_increase_cnt(CNT_IP_DATA_SIZE,traffic->dsize);

	switch(traffic->proto) {
		case P_UNKNOWN:
			break;
		case P_TCP:
			stats_increase_cnt(CNT_TCP,1);

			// Check if there is enough room 
			if(traffic->dsize - tr_offset < 20) {
				log_error("Malformed TCP packet, no room for TCP header\n");
				traffic->proto=0;
				break;
			}

			traffic->tcphdr  = (struct tcphdr*)(traffic->data + tr_offset);
			offset = tr_offset + (traffic->tcphdr->th_off << 2);
			
			traffic->payload = (void *)(traffic->data +  offset);
			traffic->psize   = traffic->dsize - offset;

			// Negative payload ?? 
			if(traffic->psize < 0) {
				//TODO, make alert
				log_error("Payload size is not sane!");	
				traffic->psize = 0;
				//TODO block or proceed..
				// Right now: proceed.. 
			}

			if(tcp_check_packet(traffic) == 1) {
				//TODO, make alert
				log_error("Malformed TCP packet!\n");
				traffic_dump(traffic);
				traffic->proto=0;
				break;
			}

			// Set the hash
			setTrafficHash(traffic);

			// Add to stream analyzer
			switch(tcp_stream_check(traffic)) {
				case 1: 
					// Alert or not ?
					//traffic_free(traffic);
					stats_increase_cnt(CNT_SESSION_MISS,1);
					return 0;
				case 2:
					//Throw it back in the pool
					pushListEntry(traffic,trafficlist);
					return 0;
			}

			break;
		case P_UDP:
			// Set the hash
			setTrafficHash(traffic);

			// Update stats
			stats_increase_cnt(CNT_UDP,1);
                        traffic->udphdr  = (struct udphdr*)(traffic->data + tr_offset);
                        offset = tr_offset + sizeof(struct udphdr);
			traffic->payload = (void *)(traffic->data +  offset);
			traffic->psize   = traffic->dsize - offset;
			break;
		case P_ICMP:
			// Set the hash
			setTrafficHash(traffic);

			// Update stats
			stats_increase_cnt(CNT_ICMP,1);
			traffic->icmphdr = (struct icmphdr*)(traffic->data + tr_offset);
			offset = tr_offset; // + sizeof(struct icmphdr);
			traffic->payload = (void *)(traffic->data +  offset);
			traffic->psize   = traffic->dsize - offset;
			break;
		default:
			traffic->payload = (void *)traffic->data;
			traffic->psize   = traffic->dsize;
			break;
	}

	if(CONFIG_SHOW_TRAFFIC == 1)
		traffic_dump(traffic);

	// Do the magic
        if((sig = match_signature(traffic)) != NULL)  {
		traffic->signature = sig;
	
		// Drop or not..
		//printf("sig->action = %d, versus %d\n",sig->action,SIG_ACTION_PASS);
		if(CONFIG_DIVERT_ENABLE == 1 && sig->action == SIG_ACTION_PASS) {
			divert_inject(traffic);
		}

		packet->popped = 1;
                alert(sig,traffic);

	} else {

		// Now put the traffic back on the line
		if(CONFIG_DIVERT_ENABLE == 1) {
			divert_inject(traffic);
		}

		packet->popped = 1;
	}

        return 0;
}


