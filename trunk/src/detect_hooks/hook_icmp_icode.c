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

int hook_icmp_icode(struct signature *sig,struct traffic *traffic) {

	int code;
	if(traffic->icmphdr == NULL)
		return 0;

	code = (int)traffic->icmphdr->icmp_code;
	
	//printf("Comparing ICMP: %d -> %d\n",code, sig->icmp_code);
	if(code == sig->icmp_code) {
		return 1;
	}
	
	return 0;
}


// 0 is success
// 1 is failure

int hook_icmp_icode_options(char *key, char *val, struct signature *sig) {
	int code = atoi(val);

	if(sig->proto != P_ICMP) {
		log_error("The icode keyword is for ICMP only" );
		return 1;
	}
	
	if(code > 255 || code < 0) {
		log_error("Invalid value for ICMP code" );
		return 1;
	}
		
	//printf("ICMP code ---> %d\n",code);
	sig->icmp_code = code;
	return 0;
}


