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

struct socom_udp {
	unsigned char type;
	unsigned char  size;
	unsigned char  reserved;
	// array[0] + (array[1] << 8); 
	unsigned char id[4];
	unsigned char *data;
};

// 0 is success

int hook_socom(struct signature *sig,struct traffic *traffic) {

	int i,a=0;
	struct socom_udp *socom_udp = (struct socom_udp *)traffic->payload;

	if(CONFIG_LOG_VERBOSE == 3) {
		printf("%s:%d",inet_ntoa(traffic->iphdr->ip_src),htons(traffic->udphdr->uh_sport));
		printf(" > ");
		printf("%s:%d ",inet_ntoa(traffic->iphdr->ip_dst),htons(traffic->udphdr->uh_dport));

		printf(" T:%02x L:%d ID:%02x%02x%02x%02x D:",socom_udp->type,(int)socom_udp->size,socom_udp->id[0], socom_udp->id[1],socom_udp->id[2],socom_udp->id[3]);

		// Not using struct data pointer for now... instead add offset to 'i'
		for(i=7;i<traffic->psize;i++) {

			printf("%02x",((unsigned char *)traffic->payload)[i]);
			a++;

			// Break if too large
			if(i==75) {
				i=traffic->psize;
				printf( "..");
			}
		}

		printf( "( size=%d)\n",a);

	}

	return 1;
}


// 0 is success
// 1 is failure

int hook_socom_options(char *key, char *val, struct signature *sig) {

	return 0;
}


