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

// From main.h
extern struct linked_list *trafficlist;
extern int loop_sniffer;


//
// Little wrapper to put the loop routine in a thread
//

void pcap_listen_loop(void *handle) {
        // Loop !
        log_info("Sniffer thread started: examining traffic");
	// Initialize TCP stream structure
	// Start sniffing
        pcap_loop((pcap_t*)handle,-1,pcap_callback,NULL);
	log_info("Pcap loop is done reading");
	loop_sniffer=0;

        pthread_exit(0);
}

//
// This is the callback function that will register new connections
// these connections are put into the linked list
//

void pcap_callback(u_char *burb,const struct pcap_pkthdr* pkthdr,const u_char* packet) {

	// Put the packet in the traffic struct
	struct traffic * traffic = pcap_to_traffic((void *)packet,pkthdr);

	stats_increase_cnt(CNT_QUEUE_PUSH,1);

	//Check IP fragmentation
	if(ntohs(traffic->iphdr->ip_off) & IP_MF || ntohs(traffic->iphdr->ip_off) & IP_OFFMASK) {
		push_ip_frag(traffic);
		return;
	} 

	traffic->type = TRAFFIC_TYPE_PCAP;

	//TODO seperate transport header from data
        pushListEntry(traffic,trafficlist);
	return;
}

//
// Open a network device
//

pcap_t * pcap_open_device(char *dev, char *filter) {

	struct bpf_program filter_str;
	char errbuf[PCAP_ERRBUF_SIZE];
        bpf_u_int32 mask;
        bpf_u_int32 net;

	pcap_t *handle = NULL;

	log_info("Opening network device: %s",dev);

	// Option parsing is finished
	if(dev == NULL && (dev = pcap_lookupdev(errbuf)) == NULL) {
		fatal_error("Use -d to specify the device: %s",errbuf);
	}

	// Lookup netmask and ip of the device
	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		log_warn("Unable to lookup device info: %s",errbuf);
	}

	if((handle = pcap_open_live(dev, SNAPLEN, 1, 5, errbuf)) == NULL) {
		fatal_error("Unable to open device: %s",errbuf);
	}

	// Compile the filter
	if(pcap_compile(handle, &filter_str, filter, 0, net) == -1) {
		fatal_error("Filter compile error!");
	}

	// Set the filter
	if(pcap_setfilter(handle, &filter_str) == -1) {
		fatal_error("Filter set error!");
	}

	return handle;
}

pcap_t * pcap_open_file(char *infile, char *filter) {

	pcap_t *handle = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter_str;

	log_info("Opening offline file: %s",infile);

	if((handle = pcap_open_offline(infile,errbuf)) == NULL) {
		fatal_error("Unable to read from input file: %s ",errbuf);
	}

        // Compile the filter
        if(pcap_compile(handle, &filter_str, filter, 0, 0) == -1) {
                fatal_error("Filter compile error!");
        }

        // Set the filter
        if(pcap_setfilter(handle, &filter_str) == -1) {
                fatal_error("Filter set error!");
        }

	return handle;
}

char * pcap_return_device () {

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs = NULL;
	pcap_if_t *dev;

	if(pcap_findalldevs(&alldevs, errbuf) < 0 || alldevs == NULL) {
		return 0;
	}

	dev = alldevs;

	do {

	if(strcmp(dev->name,"lo0") != 0)
		return dev->name;
		
	} while((dev = dev->next) != NULL);

	return NULL;
}

