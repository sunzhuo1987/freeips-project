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

extern struct linked_list *trafficlist;
extern HashTable *session;


// 0 is success

int hook_latency(struct signature *sig,struct traffic *traffic) {

	TcpSession *tsess;

	// Session already marked?
	//
	// -1 = NO

        if((tsess = getHashValue(session,traffic)) == NULL) {
		printf("Latency: Packet not in session yet\n");
                return 1;
        } 

	if(tsess->latency == 0) {
		printf("Latency: Setting session latency: %d\n", sig->latency);
		tsess->latency = sig->latency;
	}

	return 1;
}

// 0 is success
// 1 is failure

int hook_latency_options(char *key, char *val, struct signature *sig) {

	int latency = atoi(val);
	if(latency > 600 || latency < 0) {
		log_error("Insane latency value: %d", latency);
		return 1;
	}
		
	//printf("Latency: Option function, set to %d\n",latency);
	sig->latency = latency;

	return 0;
}


