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

int hook_tcp_flags(struct signature *sig,struct traffic *traffic) {
	
	// Strip off the optional flags 
	int tmpflags = traffic->tcphdr->th_flags & (0xFF ^ sig->tflags_ignore.flags);

	switch(sig->tflags.flags) {
		case TCPFLAGS_ANYO:
			break;

		case TCPFLAGS_ANY:
			break;

		case TCPFLAGS_NOT:
			// Match the first flags
			if((sig->tflags.flags ^ tmpflags) == tmpflags) {
				return 1;
			}	

			break;

		default:
		
			// Match the first flags
			if((sig->tflags.flags ^ tmpflags) == 0) {
				return 1;
			}	

			break;
	}

	return 0;
}


// 0 is success
// 1 is failure

int hook_tcp_flags_options(char *key, char *val, struct signature *sig) {
	char *strptr = NULL;

	// Check for multiple flag fields (sucks)
	if((strptr = index(val,',')) == NULL) {
		hook_tcp_flags_parse(val,&sig->tflags);
	} else {
		// Parse the first part
		hook_tcp_flags_parse(val,&sig->tflags);

		// Parse the second string
		hook_tcp_flags_parse(strptr + 1,&sig->tflags_ignore);
	}
	
	return 0;
}

int hook_tcp_flags_parse(char *flagstr,TcpFlags *tflags) {

	int i;
	//printf("Parsing \"%s\"\n",flagstr);
	for(i=0; i<strlen(flagstr);i++){
		//printf("TCP flag: %c\n",flagstr[i]);
		switch(flagstr[i]) {
			case '+':
				tflags->options = TCPFLAGS_ANYO;
				break;
			case '*':
				tflags->options = TCPFLAGS_ANY;
				break;
			case '!':
				tflags->options = TCPFLAGS_NOT;
				break;
			case 'F':
				tflags->flags |= TH_FIN;
				break;
			case 'S':
				tflags->flags |= TH_SYN;
				break;
			case 'R':
				tflags->flags |= TH_RST;
				break;
			case 'P':
				tflags->flags |= TH_PUSH;
				break;
			case 'A':
				tflags->flags |= TH_ACK;
				break;
			case 'U':
				tflags->flags |= TH_URG;
				break;
			case '1':
				tflags->flags |= TH_ECE;
				break;
			case '2':
				tflags->flags |= TH_CWR;
				break;
			case '0':
				// nothing.. 
				tflags->flags=0;
				return 0;
				break;
			case ',':
				// Comma reached.. time to stop the
				// parsing.. we only get here when there
				// are multiple flag strings
				return 0;
				break;
			default:
				// Todo: needs review
				//log_verbose("Unknown TCP flag: %c",flagstr[i]);
				return 1;
				break;
		}
	}

	return 0;
}


