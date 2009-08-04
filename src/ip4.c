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

Fqueue *fqueue[MAX_ID_VALUE];
int queue_init = 0;
extern struct linked_list *trafficlist;
pthread_t cleaner_tid;

int push_ip_frag(struct traffic* traffic) {

	IPfrag* frag =(IPfrag*)allocMem(sizeof(IPfrag));
	IPfrag* tmpfrag;
	Fqueue* qptr = NULL;
	Fqueue* lqptr = NULL;
	Fqueue* frag_queue = NULL;
	int i,id;

	// Update IP frag stats
	stats_increase_cnt(CNT_IP_FRAG,1);

	if(queue_init == 0) {
		queue_init = 1;
		for(i = 0;i<MAX_ID_VALUE;i++) {
			fqueue[i] = NULL;
		}
	}

	frag->offset  = ntohs(traffic->iphdr->ip_off);
	id = frag->id = ntohs(traffic->iphdr->ip_id);
	frag->ip_len  = ntohs(traffic->iphdr->ip_len);
	frag->mf      = frag->offset & IP_MF;
	frag->traffic = traffic;
	frag->offset <<= 3;

	DEBUGF("Adding frag with ID:     %d\n",frag->id);
	DEBUGF("Adding frag with OFFSET: %d\n",frag->offset);

	stats_increase_cnt(CNT_IP_FRAG_QUEUE,1);

	if(fqueue[frag->id] == NULL) {
		fqueue[frag->id] =new_queue(); 
		fqueue[frag->id]->id = frag->id;
		frag_queue=fqueue[frag->id];
	} else {

		// Find the right queue
		lqptr = qptr = fqueue[frag->id];
		while(qptr != NULL) {
			lqptr = qptr;
			tmpfrag = (IPfrag*)qptr->list->start->data;
			if(cmp_frag(tmpfrag,frag) == 0) {
				frag_queue = qptr; 
				break;
			}
			qptr = qptr->next;
		}

		if(frag_queue == NULL) {
			lqptr->next = new_queue();	
			fqueue[frag->id]->id = frag->id;
			frag_queue = lqptr->next;
			frag_queue->prev = lqptr;
		}
	}

	frag_queue->collected += traffic->psize;
	pushListEntry(frag,frag_queue->list);
	frag_queue->fragcnt++;

	// If this is the ending fragment then we can use its values to 
	// calculate the datagram size. This size can then be used to determine
	// if we have received all data.

	if(!frag->mf) {
		DEBUG(stdout,"Last frag !\n");
		frag_queue->required = frag->offset + (frag->ip_len - (frag->traffic->iphdr->ip_hl * 4));
	}

	// Check if last frag has been received..
	//DEBUGF("Collected: %d, Required: %d\n",frag_queue->collected, frag_queue->required);
	if(frag_queue->collected == frag_queue->required) {
		if(assemble_ip_frags(frag_queue) == 1) {
			// Update error
			stats_increase_cnt(CNT_IP_ERR,1);
			log_error("Fragment assembly failed for dst:%s proto: %d",(char*)inet_ntoa(traffic->iphdr->ip_dst), frag->traffic->proto);
			printf("BB\n");
			free_frag_queue(frag_queue,1);
		} else {
			pthread_yield();
			free_frag_queue(frag_queue,0);
		}
	} 

	return 0;
}

// We don't do anything with ptr..
void ip_frag_cleaner() { 
	struct timeval now;
	Fqueue *fptr;
	int i;

	//DEBUG(stdout, "In IP frag cleaner!\n");

	//dump_frag_queues ();
	gettimeofday( &now, NULL );
	for(i=0;i<MAX_ID_VALUE; i++) {
		if(fqueue[i] != NULL) {
			fptr = fqueue[i];
			while(fptr != NULL) {
				if(now.tv_sec - fptr->time.tv_sec > FRAG_TIMEOUT) {
					DEBUGF("Frag queue expired: %d\n",i);
					stats_increase_cnt(CNT_IP_FRAG_TMOUT,1);
					fptr = fptr->next;
					free_frag_queue(fqueue[i],1);
				} else {
					fptr = fptr->next;
				}
			}
		}
	}
	return;
}

Fqueue* new_queue() {

	Fqueue* fqueue = (Fqueue*)allocMem(sizeof(Fqueue));
	fqueue->fragcnt   = 0;
	fqueue->required  = -1;
	fqueue->collected = 0;
	fqueue->next = NULL;
	fqueue->prev = NULL;

	// set the time for expiration
	gettimeofday( &fqueue->time, NULL );

	if((fqueue->list = newLiteList()) == NULL) {
		log_error("Unable to allocate memory for frag !");
		return NULL;
	}

	return fqueue;
}

void dump_frag_queues () {
	struct list_entry* entry;
	IPfrag* tmpfrag;
	int i;

	for(i=0;i<MAX_ID_VALUE; i++) {
		if(fqueue[i] == NULL || fqueue[i]->list == NULL) {
			continue;
		}
		printf("Queue ID: %d Frag cnt: %d, required: %d, collected: %d\n",fqueue[i]->id,fqueue[i]->fragcnt, fqueue[i]->required, fqueue[i]->collected);
		entry = fqueue[i]->list->start;
		while ( entry != NULL) {
			tmpfrag = (IPfrag*)entry->data;
			printf("Frag --> id: %d offset: %d \n",tmpfrag->id, tmpfrag->offset);
			entry = entry->next;
		}
	}
}

int assemble_ip_frags(Fqueue* fragq) {
        struct list_entry* entry;
        IPfrag* tmpfrag;
        struct iphdr*   iphdr;
        struct traffic* traffic;
        int ip_hl,all_h,dgsize;
        void *datagram = NULL;
        int processed = 0;

        entry = fragq->list->start;
 
        //Check the size before allocating memory..
        if(fragq->required > MAX_DATAGRAM_SIZE) {
                log_error("Datagram size is too large !");
                return 0;
        }

        DEBUGF("Assembling IP packet with size: %d\n",fragq->required);

        while (entry != NULL) {
                tmpfrag = (IPfrag*)entry->data;
                iphdr = tmpfrag->traffic->iphdr;
                ip_hl = iphdr->ip_hl * 4;
                all_h = ip_hl + sizeof(struct ether_header);

                if(datagram == NULL) {   
                        dgsize = fragq->required + ((tmpfrag->traffic->iphdr->ip_hl * 4) + sizeof(struct ether_header));
                        DEBUGF("Allocating: %d\n", dgsize);
                        datagram = allocMem(dgsize);
                }
 
                if((fragq->required - tmpfrag->offset) < tmpfrag->ip_len - ip_hl) {
                        log_error("ALARM: IP fragment exceeds buffer!");
                        return 1;
                }

                //We'll copy the first one with ethernet and headers
                if(tmpfrag->offset == 0) {
                        memcpy(datagram,tmpfrag->traffic->data,tmpfrag->traffic->dsize);
                        processed += tmpfrag->traffic->dsize - sizeof(struct ether_header);
                } else {
                        memcpy(datagram + tmpfrag->offset + all_h,tmpfrag->traffic->data + all_h, tmpfrag->traffic->dsize - all_h);
                        processed += tmpfrag->traffic->dsize - all_h;
                }
                entry = entry->next;
        }

	// If this is not 0 then we did not process the mount of data
	// expected to be in the packet
	if(processed > dgsize) {
		//TODO alert
		//TODO have packets analyzed instead of freed
		//printf("Processed: %d, required: %d\n",processed, fragq->required);
		log_error("IP overlap detected !!");
#ifdef BLOCK_IP_FRAG_OVERLAP
		return 1;
#endif
	} else if(processed < fragq->required) {
		//TODO alert
		//TODO have packets analyzed instead of freed
		log_error("Incomplete IP packet: missing %d bytes ",fragq->required - processed);		
		return 1;
	}

	traffic = (struct traffic*)allocMem(sizeof(struct traffic));
	traffic->data   = datagram;
	traffic->ethhdr = (struct ether_header *) datagram;
	traffic->iphdr  = (struct iphdr*)(datagram + sizeof(struct ether_header));
	traffic->dsize  = fragq->required;
	traffic->proto  = traffic->iphdr->ip_p;

	//dumphex(datagram,fragq->required);
	pushListEntry(traffic,trafficlist);
        return 0;
}

// dispatch is a boolean that desides whether the traffic structure
// is supposed to be dispatched to the signature engine

void free_frag_queue(Fqueue* fragq, int dispatch) {
        struct list_entry *entry = fragq->list->start;
	Fqueue *qptr_next = fragq->next;
	Fqueue *qptr_prev = fragq->prev;
        struct list_entry *tmp;
	IPfrag* frag;

        DEBUG(stdout,"In free_frag_queue\n");
        while(entry != NULL) {
		tmp = entry->next;
		frag = (IPfrag*) entry->data; 

		if(dispatch == 0) {
			freeMem(frag->traffic->data);
			freeMem(frag->traffic);
		} else{
			frag->traffic->proto = 0;
			DEBUG(stdout,"Pushing frag to list\n");
			pushListEntry(frag->traffic,trafficlist);
		}

		stats_decrease_cnt(CNT_IP_FRAG_QUEUE,1);
		freeMem(frag);
		freeMem(entry);
                entry = tmp;
        }

	// End of list
	if(qptr_next == NULL && qptr_prev == NULL) {
		fqueue[fragq->id] = NULL;
	} else {
		//Last in list
		if(qptr_next == NULL && qptr_prev != NULL)  {
			qptr_prev->next = NULL;
		}

		//First in list
		if(qptr_next != NULL && qptr_prev == NULL) {
			fqueue[fragq->id] = qptr_next;
		}

		//First in list
		if(qptr_next != NULL && qptr_prev != NULL)  {
			qptr_next->prev = qptr_prev;
			qptr_prev->next = qptr_next;
		}
	}

        freeMem(fragq->list);
        freeMem(fragq);
        DEBUG(stdout,"Done free_frag_queue\n");
}



int cmp_frag(IPfrag* fraga, IPfrag* fragb) {
	if(fraga->id == fragb->id && fraga->traffic->proto == fragb->traffic->proto &&
		fraga->traffic->iphdr->ip_src.s_addr == fragb->traffic->iphdr->ip_src.s_addr) {
		return 0;
	}
	return 1;
}


