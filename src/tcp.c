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

HashTable *session = NULL;

struct timeval tm_now;
struct timeval tm_last;


int tcp_stream_init() {
	gettimeofday( &tm_now, NULL );
	gettimeofday( &tm_last, NULL );

	// Start a new hashtable and use the compare_session function to find
	// a session when there is a collision
	if((session = createHashTable((HASH_PRIM * 2) + (65535 *2), compare_session)) == NULL) {
		log_error("Unable to initialize TCP session monitoring");
		return 1;
	}
	return 0;
}

int tcp_stream_add(struct traffic *traffic) {
	TcpSession *tsess = (TcpSession *)allocMem(sizeof(TcpSession));
	gettimeofday( &tsess->starttime, NULL );
	gettimeofday( &tsess->seentime, NULL );

	// Copy adresses and ports
	tsess->ip_src.s_addr = traffic->iphdr->ip_src.s_addr;
	tsess->ip_dst.s_addr = traffic->iphdr->ip_dst.s_addr;
	tsess->th_sport      = traffic->tcphdr->th_sport;
	tsess->th_dport      = traffic->tcphdr->th_dport;
	tsess->state         = -1;
	tsess->stream        = NULL;
	tsess->stream_size   = 0;
	tsess->stream_pkts   = NULL;
	tsess->timeout       = TCPS_TIMEOUT_INITIAL;

#ifdef TCP_SESSION_DEBUG
	printf("START %ld ",traffic->hashkey);
	tcp_stream_dump(tsess,stdout);
#endif
	setHashEntry(session,traffic,tsess);

	stats_increase_cnt(CNT_SESSION_TOTAL,1);

	return 0;
}

int tcp_stream_check(struct traffic *traffic) {
	// Todo make sure things are sanatized before we get here. e.g. all
	// flags set should be detected sooner.

	TcpSession *tsess;
	u_char flags;

	// If we receive a SYN ACK then the server accepts the session
	// which makes it more probable that it's worth to create a session

	switch(traffic->tcphdr->th_flags) {
		case (TH_SYN): 
			tcp_stream_add(traffic);	
			return 0;
			break;
	}

	
	if((tsess = getHashValue(session,traffic)) == NULL) {
		// Not part of an existing session, perhaps this connection
		// already existed when we fired up the IPS.. so add it anyway
		// unless we're inline and TCP_STRICT is set to 1
		if(CONFIG_TCP_STRICT==1 && CONFIG_DIVERT_ENABLE==1) {
			return 1;
		} else { 
			//printf("Adding stream (CONFIG_TCP_STRICT=0)\n");
			tcp_stream_add(traffic);	
			return 0;
		}
	}

	// Stream reassembly
	
	//Update the seentime (for timeout)
	gettimeofday( &tsess->seentime, NULL );

	// Cleanup the flags
	flags = traffic->tcphdr->th_flags;
	flags &= ~TH_PUSH;
	flags &= ~TH_URG;

	switch(tsess->state) {
		case TCPS_NEW:
			switch(flags) {
				case (TH_SYN) + (TH_ACK) :
					tsess->state = TCPS_SYN_RECEIVED;
					break;
				case (TH_RST) :
					tcp_stream_del(traffic);
					break;
				default:
					//TODO
					break;
			}
			break;
		case TCPS_SYN_RECEIVED:
                        switch(flags) {
                                case (TH_ACK) :
					tsess->timeout = TCPS_TIMEOUT_ESTABLISHED;
                                        tsess->state = TCPS_ESTABLISHED;
				default:
					//TODO
					break;
			}
			break;
		case TCPS_ESTABLISHED: 
                        switch(flags) {
                                case (TH_FIN):
                                case (TH_FIN) + (TH_ACK) :
                                        tsess->state = TCPS_CLOSING;
					tsess->timeout = TCPS_TIMEOUT_CLOSING;
                                        break;
				default:
					//TODO check if ok

					tsess->timeout = TCPS_TIMEOUT_CONNECTION;
					break;
			}
			break;
		case TCPS_CLOSING:
                        switch(flags) {
                                case (TH_FIN):
                                case (TH_FIN) + (TH_ACK):
                                case (TH_RST):
                                        tsess->state = TCPS_LAST_ACK;
                                        break;
				default:
					//TODO
					break;
			}
			break;
		case TCPS_LAST_ACK:
                        switch(flags) {
                                case (TH_ACK) :
                                        tsess->state = TCPS_CLOSED;
					tcp_stream_del(traffic);
                                        break;
				default:
					//TODO
					break;
			}
			break;
		default:
			break;
	}

	return 0;
}

int tcp_new_session(struct traffic *traffic) {
	return 0;
}

int tcp_stream_del(struct traffic *traffic) {

	TcpSession *tsess = popHashValue(session,traffic);
	if(tsess == NULL) 
		return 1;

#ifdef TCP_SESSION_DEBUG
	printf("END  ");
	tcp_stream_dump(tsess,stdout);
#endif
	//Free the session
	freeMem(tsess);
	return 0;
}

void tcp_stream_dump(TcpSession *tsess, FILE *fd) {
	struct timeval endtime;
	gettimeofday( &endtime, NULL );

	fprintf(fd,"%s:%d",inet_ntoa(tsess->ip_src),htons(tsess->th_sport));
	fprintf(fd," --> ");
	fprintf(fd,"%s:%d",inet_ntoa(tsess->ip_dst),htons(tsess->th_dport));
        fprintf(fd," mins act: %d",(int)(endtime.tv_sec - tsess->starttime.tv_sec) / 60);
	fprintf(fd," timeout %d secs (val: %d)",(int)(tsess->timeout  - (endtime.tv_sec - tsess->seentime.tv_sec)),tsess->timeout);

	switch(tsess->state) {
		case TCPS_NEW:
			fprintf(fd,"TCPS_NEW");
			break;
		case TCPS_SYN_RECEIVED:
			fprintf(fd,"TCPS_SYN_RECEIVED");
			break;
		case TCPS_ESTABLISHED:
			fprintf(fd,"TCPS_ESTABLISHED");
			break;
		case TCPS_CLOSING:
			fprintf(fd,"TCPS_CLOSING");
			break;
		case TCPS_LAST_ACK:
			fprintf(fd,"TCPS_LAST_ACK");
			break;
		case TCPS_CLOSED:
			fprintf(fd,"TCPS_CLOSED");
			break;
		default:
			fprintf(fd,"UNKNOWN");
	}

	fprintf(fd,"\n");

}

void tcp_clean_sessions() {
        long i;
        TcpSession *tsess;
	struct traffic dummy;
        gettimeofday( &tm_now, NULL );

	if(tm_now.tv_sec - tm_last.tv_sec > 10 && session->entries != 0) {
		for(i=0;i < session->size;i++) {
			if(session->table[i] == NULL)
				continue;

			tsess = (TcpSession *)session->table[i]->data;
			if(tm_now.tv_sec - tsess->starttime.tv_sec > tsess->timeout) {
#ifdef TCP_SESSION_DEBUG
				fprintf(stdout,"TCP session timed out: ");
				tcp_stream_dump(tsess,stdout);
#endif

				dummy.hashkey = i;
				tsess= (TcpSession *)popHashValue(session,&dummy);
				freeMem(tsess);
				session->table[i] = NULL;
				
			}
		}
		gettimeofday( &tm_last, NULL );
	}

}

void tcp_dump_sessions(FILE *fd) {
	long i;
	TcpSession *tsess;
	fprintf(fd,"\nDumping active TCP sessions \n");
	fprintf(fd,"---------------------------------------------------------------------\n\n");

	for(i=0;i < session->size;i++) {
		if(session->table[i] == NULL)
			continue;

		tsess = (TcpSession *)session->table[i]->data;
		tcp_stream_dump(tsess,fd);
	}
	fprintf(fd,"\n---------------------------------------------------------------------\n\n");
	gettimeofday( &tm_last, NULL );
}

//
// Compare session against traffic
//
// 0 = match
// 1 = no match
//
// One = session
// Two = traffic
//

int compare_session(void *one, void *two) {
	TcpSession *tsess = (TcpSession *)one;
	Traffic    *traf  = (Traffic *)two;

	// Match the protocol
	if(traf->proto != P_TCP)
		return 1;

	// Match the src IP
	if(traf->iphdr->ip_src.s_addr != tsess->ip_src.s_addr) 
		return 1;

	// Match the dst IP
	if(traf->iphdr->ip_dst.s_addr != tsess->ip_dst.s_addr) 
		return 1;

	// Match the src ports..
	if(traf->tcphdr->th_sport != tsess->th_sport) 
		return 1;

	// Match the src ports..
	if(traf->tcphdr->th_dport != tsess->th_dport) 
		return 1;
	
	// Match 
	return 0;
}

//
// Check TCP header field
//

int tcp_check_packet(struct traffic *traf) {

	// Perform header length check
	if((traf->tcphdr->th_off * 4) < 20) {
		//TODO: alert
		log_error("TCP header length field not reliable: %d",(traf->tcphdr->th_off * 4));
		return 1;
	}

	//TODO: checksum test

	return 0;
}
