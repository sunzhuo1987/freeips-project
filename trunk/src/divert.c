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
//


#include <util.h>

int divert_fd = -1;
int divert_enable = 0;
extern struct linked_list *trafficlist;
extern int loop_sniffer;

//
// Loop until sigint is received
//

void divert_listen_loop() {
	
	struct traffic *traf;
	unsigned char packet[DIVERT_PACKET_SIZE];
	int slen=sizeof(struct sockaddr_in);
	struct sockaddr_in sin;
	fd_set sockset;
	int rsize=0;

	while(loop_sniffer == 1) {

                FD_ZERO(&sockset);
                FD_SET(divert_fd,&sockset);

		// Blocking select.. do nothing until we receive data
		select(divert_fd + 1, &sockset, NULL, NULL, 0);

		rsize=recvfrom(divert_fd, packet, DIVERT_PACKET_SIZE, 0, (struct sockaddr *)&sin, (socklen_t *)&slen);

		if(rsize == -1) {
			log_error("Received -1 on recvfrom()");
			continue;
		}

		// Create the struct
		traf = divert_to_traffic(packet,rsize);

		traf->type = TRAFFIC_TYPE_DIVERT;

		// Copy sockaddr, needed for re-injection.. optimize?
		memcpy(&traf->saddr,&sin,sizeof(struct sockaddr));

		//Check IP fragmentation
		if(ntohs(traf->iphdr->ip_off) & IP_MF || ntohs(traf->iphdr->ip_off) & IP_OFFMASK) {
			traf->free = 0;
			push_ip_frag(traf);
			return;
		}

		//TODO seperate transport header from data
		pushListEntry(traf,trafficlist);
	}
}

//
// Put the traffic back on the line
//

int divert_inject( struct traffic *traf) {

	int bytes;
	int offset = sizeof(struct ether_header);

	//switch(traf->proto) {
	//	case P_TCP:
	//		break;
	//	case P_UDP:
	//		break;
	//	case P_ICMP:
	//		break;
	//}

	bytes=sendto(divert_fd, traf->data + offset, traf->dsize - offset, 0, 
		&traf->saddr, sizeof(traf->saddr));

	// Check if an error occured
	if(bytes == -1) {
		perror("woop");
		log_error("divert_inject() failed: size: %d",traf->dsize - offset);
	}

	return bytes;

}

//
// Start listening on the socket
//

void divert_open_socket(int port) {
	struct sockaddr_in addr;
	divert_fd =  socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);

	if(divert_fd == -1) {
		fatal_error("Unable to open divert socket (port: %d)",port);
		return;
	}

	addr.sin_addr.s_addr = 0;
	addr.sin_family      = AF_INET;
	addr.sin_port        = htons(port);

	if(bind(divert_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) != 0) {
		fatal_error("Unable to bind divert socket (port: %d)",port);
		return;
	}

	log_info("Opened DIVERT socket: %d",port);

	return;
}
