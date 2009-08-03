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

int hook_icmp_itype(struct signature *sig,struct traffic *traffic) {

	int type;
	if(traffic->icmphdr == NULL)
		return 0;

	type = (int)traffic->icmphdr->icmp_type;
	
	//printf("Comparing ICMP: %d -> %d\n",type, sig->icmp_type);
	if(type == sig->icmp_type) {
		return 1;
	}
	
	return 0;
}


// 0 is success
// 1 is failure

int hook_icmp_itype_options(char *key, char *val, struct signature *sig) {
	int type = atoi(val);

	if(sig->proto != P_ICMP) {
		log_error("The itype keyword is for ICMP only" );
		return 1;
	}
	
	if(type > 255 || type < 0) {
		log_error("Invalid value for ICMP type" );
		return 1;
	}
		
	//printf("ICMP type ---> %d\n",type);
	sig->icmp_type = type;
	return 0;
}


