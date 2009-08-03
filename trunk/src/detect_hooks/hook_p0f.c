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

int   p0f_socket      = -1;
char *p0f_socket_file = "/tmp/p0f.sock";

//
// 0 = OS match
//

int hook_p0f(struct signature *sig,struct traffic *traffic) {
        return 1;
}


// 0 is success
// 1 is failure

int hook_p0f_options(char *key, char *val, struct signature *sig) {
	return 1;
}

//
// p0f a session and identify the operating system
//

int p0f_query(TcpSession *tsess) {

	struct p0f_query pquery;
	struct p0f_response presponse;

	pquery.magic    = P0F_QUERY_MAGIC;
	pquery.id       = 0x12345678;
	pquery.src_ad   = tsess->ip_src.s_addr;
	pquery.dst_ad   = tsess->ip_dst.s_addr;
	pquery.src_port = tsess->th_sport;
	pquery.dst_port = tsess->th_dport;;

	if(p0f_socket == -1) {
		log_error("p0f socket is not connected");
		return 1;
	}

	if(write(p0f_socket,&pquery,sizeof(pquery)) != sizeof(pquery)) {
		log_error("p0f query write to socket failed");
		return 1;
	}

	if(read(p0f_socket,&presponse,sizeof(presponse)) != sizeof(presponse)) {
		log_error("p0f response read from socket failed");
		return 1;
	}

	if(presponse.magic != P0F_QUERY_MAGIC) {
		log_error("p0f query magic does not match");
		return 1;
	}

	if(presponse.type != P0F_RESP_BADQUERY) {
		log_error("p0f query was rejected");
		return 1;
	}

	if(presponse.type != P0F_RESP_NOMATCH) {
		log_warn("p0f query returned no match");
		return 1;
	}

	//if (presponse.genre[0]) {
	    printf("Genre    : %s\n",presponse.genre);
	    printf("Details  : %s\n",presponse.detail);
	//}

	return 0;
}

//
// Connect to the p0f unix socket
//

int p0f_connect_socket() {

	struct sockaddr_un saddr;

	if((p0f_socket = socket(PF_UNIX,SOCK_STREAM,0)) < 0) {
		log_error("Unable to create p0f socket");
		return 1;
	}

	saddr.sun_family=AF_UNIX;
	strncpy(saddr.sun_path,p0f_socket_file,P0F_MAX_SOCK_SIZE);

	if(connect(p0f_socket,(struct sockaddr*)&saddr,sizeof(saddr)) == -1) {
		log_error("Unable to connect to p0f socket: %s",p0f_socket_file);
		return 1;
	}

	log_info("Connected to p0f socket");

	// Connected
	return 0;
}

int p0f_disconnect_socket() {
	int ret = 0;
	if(shutdown(p0f_socket,SHUT_RDWR) == 1) {
		log_error("Unable to disconnect from p0f properly");
		ret = 1;
	}
	close(p0f_socket);
	return ret;
}
