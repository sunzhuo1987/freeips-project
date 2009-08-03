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

extern HashTable *session;

// 0 is match

int hook_flow(struct signature *sig,struct traffic *traffic) {

	TcpSession *tsess = NULL;

	// Get the session
	if(session == NULL || (tsess = getHashValue(session,traffic)) == NULL) {
		return 0;
	}

	// Check the direction the dst_ip of the session if the server while the
	// src_ip is the one that initialized the session
	if(sig->direction != -1) {
		switch(sig->direction) {
			case DIRECTION_TO_SERVER:
				if(traffic->iphdr->ip_dst.s_addr != tsess->ip_dst.s_addr) {
					return 0;
				}
				break;

			case DIRECTION_TO_CLIENT:
				if(traffic->iphdr->ip_dst.s_addr != tsess->ip_src.s_addr) {
					return 0;
				}
				break;
		}
	}

	if(sig->connection_state != -1 && sig->connection_state != tsess->state) {
		DEBUG(stdout,"No correct connection state\n");
		return 0;
	}

	return 1;
}


// 0 is success
// 1 is failure

int hook_flow_options(char *key, char *val, struct signature *sig) {

	char *tokens[10];
	char *token, *tptr = strdup(val);
	int tokenindex = 0;

	tokens[0] = strtok(tptr,",");
	while((token = strtok(NULL,",")) != NULL && tokenindex < 10) {
		tokens[++tokenindex] = token;
	}

	for(; tokenindex >= 0; tokenindex--) {
		if(strcmp(tokens[tokenindex],"to_server") == 0 || strcmp(tokens[tokenindex],"from_client") == 0) {
			sig->direction = DIRECTION_TO_SERVER;
			continue;
		} else {
			if(strcmp(tokens[tokenindex],"to_client") == 0 || strcmp(tokens[tokenindex],"from_server") == 0) {
				sig->direction = DIRECTION_TO_CLIENT;
				continue;
			}
		}

		//TODO!
		if(strcmp(tokens[tokenindex],"established") == 0)  {
			sig->connection_state = TCPS_ESTABLISHED;
		}

		//printf("token --> %d %s (%d)\n",tokenindex, cleanup_char(tokens[tokenindex]),sig->direction);
	}
	return 0;
}


