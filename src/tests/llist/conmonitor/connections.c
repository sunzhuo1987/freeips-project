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

#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <signal.h>

#include <list.h>
#include <memory.h>
#include <connections.h>

struct linked_list *list;
int keeprunning = 1;

int main(int argc, char **argv)  {

	int arg;
	char *filter = "tcp";
	char *dev = NULL;

	// pcap stuff
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct bpf_program filter_str;
	pcap_t *handle;
	pthread_t tid;
	pthread_t did;

	// Set the signal handlers
	signal(SIGHUP, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGQUIT,sighandler);

	// Create the list
	list = getNewList();

	// Register the destructor
	registerListDestructor(destructor_callback,list);
	registerListIterator(simpleprint_callback,list);
	printf("After destructor\n");

	while ((arg = getopt (argc, argv, "d:f:")) != -1){
		switch (arg){
			case 'f':
				filter = optarg;	
				break;
			case 'd':
				dev = optarg;
				break;

			default:
				break;
		}
	}

	// Option parsing is finished.
	if(dev == NULL) { 
		dev = pcap_lookupdev(errbuf);
	}

	// Lookup netmask and ip of the device
	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Unable to lookup device info\n");
		exit(1);
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 5, errbuf);

	// Compile the filter
	if(pcap_compile(handle, &filter_str, filter, 0, net) == -1) {
		fprintf(stderr, "Filter compile error!\n");
		exit(1);
	}

	// Set the filter
	if(pcap_setfilter(handle, &filter_str) == -1) {
		fprintf(stderr, "Filter set error!\n");
		exit(1);
	}

	pthread_create(&tid,NULL,(void*)pcap_listen_loop,handle);
	pthread_create(&did,NULL,(void*)simple_display,NULL);

	//pthread_join(tid,NULL);
	pthread_join(did,NULL);

	// Free the list. 
	freeList(list,1);

	return 0;
}

//
// Little wrapper to put the loop routine in a thread
//

void pcap_listen_loop(void *handle) {
	// Loop !
	pcap_loop((pcap_t*)handle,-1,pcap_callback,NULL);
	pthread_exit(0);
}

//
// This is the callback function that will register new connections
// these connections are put into the linked list
//

void pcap_callback(u_char *burb,const struct pcap_pkthdr* pkthdr,const u_char* packet) {

	struct iphdr* ip = (struct iphdr*)(packet + sizeof(struct ether_header));

	// Check if entry already exists
        struct list_entry* ret;
	struct connection* con;

        ret = list->start;
        while ( ret != NULL) {
		con = ret->data;
		
		if(con->ip_src.s_addr == ip->ip_src.s_addr && 
			con->ip_dst.s_addr == ip->ip_dst.s_addr) {
			return;
		}
                ret = ret->next;
        }

	// If we get here we need to add the device
	con = (struct connection*) allocMem(sizeof(struct connection));
	con->ip_src = ip->ip_src;
	con->ip_dst = ip->ip_dst;

	con->name_src = resolve_ip((char *) &con->ip_src.s_addr);
	con->name_dst = resolve_ip((char *) &con->ip_dst.s_addr);

	pushListEntry(con,list);
}

//
// Simple display function. Iterate the connections and 
// dump them on the screen
//

void simple_display() {

	while(keeprunning) {
		iterateList(list);
		sleep(5);
		printf("\n\n");
	}

	pthread_exit(0);
}

int simpleprint_callback(void *data,struct list_entry *entry) {
	struct connection *con = (struct connection *)data;

	printf("CONNECTION: ");
	printf("%s", con->name_src != NULL ? (char*) con->name_src : (char*)inet_ntoa(con->ip_src));
	printf("\t\t\t");
	printf("%s", con->name_dst != NULL ? (char*) con->name_dst : (char*)inet_ntoa(con->ip_dst));
	printf("\n");
	return 0;
}

//
// Resolve the ip/hostname
//

char * resolve_ip (char *ip) {

	struct hostent* hs;
	char *ret = NULL;
        // Try to resolve the dest name
        hs=gethostbyaddr(ip,4,2);
        if(hs != NULL && hs->h_name  != NULL) {
		ret = (char *)allocMem(DNS_NAME_SIZE);
		strncpy(ret,hs->h_name,DNS_NAME_SIZE);
        }

	return ret;
}

//
// The signal handler. Set the loop variable to 0 to 
// stop the output thread
//

void sighandler() {
	printf("\nReceived signal. Stopping now\n");
	keeprunning=0;
}

//
// The list entry destructor.. free resolved DNS names
//

int destructor_callback (void *data,struct list_entry *entry) {
	struct connection* con = (struct connection*)data;

	if(con->name_src != NULL) {
		freeMem(con->name_src);
	}
	if(con->name_dst != NULL) {
		freeMem(con->name_dst);
	}
	return 0;
}
		

