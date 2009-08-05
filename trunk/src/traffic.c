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

void traffic_dump(struct traffic* traffic) {
	printf("%s",inet_ntoa(traffic->iphdr->ip_src));

	if(traffic->proto == P_TCP) 
		printf(":%d",htons(traffic->tcphdr->th_sport));

	if(traffic->proto == P_UDP) 
		printf(":%d",htons(traffic->udphdr->uh_sport));

	printf("\t-->\t");

	printf("%s",    inet_ntoa(traffic->iphdr->ip_dst));
	if(traffic->proto == P_TCP) 
		printf(":%d",htons(traffic->tcphdr->th_dport));
	if(traffic->proto == P_UDP) 
		printf(":%d",htons(traffic->udphdr->uh_dport));

	if(traffic->proto == P_TCP) {
		printf(" Flags: (");
		if(traffic->tcphdr->th_flags & TH_SYN) {
			printf("S");
		}
		if(traffic->tcphdr->th_flags & TH_ACK) {
			printf("A");
		}
		if(traffic->tcphdr->th_flags & TH_RST) {
			printf("R");
		}
		if(traffic->tcphdr->th_flags & TH_URG) {
			printf("U");
		}
		if(traffic->tcphdr->th_flags & TH_PUSH) {
			printf("P");
		}
		if(traffic->tcphdr->th_flags & TH_FIN) {
			printf("F");
		}
		printf(")");
		
	}

	printf(" proto: %d",traffic->proto);
	printf(" size: %d (payload: %d)", traffic->dsize, traffic->psize);
	printf(" hash: %ld\n", traffic->hashkey);
}

//
// Packet to traffic hash
//

struct traffic * pcap_to_traffic(void *packet, const struct pcap_pkthdr* pkthdr) {

	int psize = pkthdr->caplen;
        // Add the traffic to the list so it can be examined
        struct traffic* traffic = (struct traffic*) allocMem(sizeof(struct traffic));
        DEBUGF("Captured: %d bytes\n",psize);

        if(traffic == NULL || (traffic->data = (void *)allocMem(psize)) == NULL) {
                fatal_error("Unable to allocate memory for packet");
                return NULL;
        }

	memcpy(traffic->data,packet,psize);
	memcpy(&traffic->pkthdr,pkthdr,sizeof(struct pcap_pkthdr));

        traffic->ethhdr    = (struct ether_header *) traffic->data;
        traffic->iphdr     = (struct iphdr*)(traffic->data + sizeof(struct ether_header));
        traffic->dsize     = psize;
        traffic->proto     = traffic->iphdr->ip_p;
        traffic->psize     = psize - ((traffic->iphdr->ip_hl * 4) + sizeof(struct ether_header));
        traffic->signature = NULL;
        traffic->tcphdr    = NULL;
        traffic->udphdr    = NULL;
        traffic->latency   = 0;
        traffic->icmphdr = NULL;

	return traffic;
}

struct traffic * divert_to_traffic(void *packet, int psize) {

	int ethsize = sizeof(struct ether_header);

        // Add the traffic to the list so it can be examined
        struct traffic* traffic = (struct traffic*) allocMem(sizeof(struct traffic));

	// Create the pcap pkthdr
	memset(&traffic->pkthdr,0,sizeof(struct pcap_pkthdr));
	traffic->pkthdr.caplen = psize;
	traffic->pkthdr.len = psize;
	gettimeofday(&traffic->pkthdr.ts,NULL);


	psize += ethsize;
        DEBUGF("Captured: %d bytes\n",psize);
                        
        if(traffic == NULL || (traffic->data = (void *)allocMem(psize)) == NULL) {
                fatal_error("Unable to allocate memory for packet");
                return NULL;
        }
 
	memset(traffic->data,0,psize);
        memcpy(traffic->data + ethsize,packet,psize - ethsize);

        traffic->ethhdr    = (struct ether_header*)traffic->data;
        traffic->iphdr     = (struct iphdr*)(traffic->data + sizeof(struct ether_header));
        traffic->dsize     = psize;
        traffic->proto     = traffic->iphdr->ip_p;
        traffic->psize     = psize - ((traffic->iphdr->ip_hl * 4) + sizeof(struct ether_header));
        traffic->signature = NULL;
        traffic->tcphdr    = NULL;
        traffic->udphdr    = NULL;
        traffic->latency   = 0;
        //traffic->icmphdr = NULL;

        return traffic;
}

//
// Traffic to file
//

extern pcap_t *handle;

int traffic_to_file(char *file, struct traffic *traf) {

	FILE *fp = NULL;
	struct pcap_file_header pfh;

	// Check if file exists
	if(access(file,F_OK) != 0) {
		fp = fopen(file,"w");

		if(fp == NULL) {
			fatal_error("Unable to open file: %s",file);
		}

		//write the pcap header
		memset(&pfh,0,sizeof(struct pcap_file_header));

		pfh.version_major = 2;
		pfh.version_minor = 4;
		pfh.snaplen = 65535;
		pfh.magic = 0xa1b2c3d4;
		pfh.linktype = 1;

		fwrite(&pfh,sizeof(struct pcap_file_header),1,fp);

	} else {
		fp = fopen(file,"a");
		if(fp == NULL) {
			fatal_error("Unable to open file: %s",file);
		}
	}

	fwrite(&traf->pkthdr,sizeof(struct pcap_pkthdr),1,fp);
	fwrite(traf->data,traf->dsize,1,fp);

	fclose(fp);
	return 0;
}

void traffic_free(struct traffic *traf) {
	freeMem(traf->data);
	freeMem(traf);
}

/*
int traffic_respond_tcp(struct *traffic traf ){

	// Packet without ether
	unsigned char packet[40];
	struct iphdr  *iphdr;
	struct tcphdr *tcphdr;

	memset(packet,0,sizeof(packet));

	iphdr  = (struct iphdr *)packet;
	tcphdr = (struct tcphdr *)(packet + sizeof(struct iphdr));

	if(traf->proto != P_TCP)
		return 1;

	iphdr->ip_src.s_addr = traf->iphdr->ip_dst.s_addr;
	iphdr->ip_dst.s_addr = traf->iphdr->ip_src.s_addr;
	iphdr->ip_id  = traf->iphdr->ip_id;
	iphdr->ip_ttl = 64;
	iphdr->ip_p   = P_TCP;
	iphdr->ip_len = 40;
	iphdr->ip_hl  = 4;
	iphdr->ip_sum = 0;

	tcphdr->th_sport = traf->tcphdr->th_sport;
	tcphdr->th_dport = traf->tcphdr->th_dport;
	tcphdr->th_flags = TH_RST;

	tcphdr->th_ack   = traf->tcphdr->th_ack;
	tcphdr->th_seq   = traf->tcphdr->th_seq + 1;

	return 0;
}
*/

