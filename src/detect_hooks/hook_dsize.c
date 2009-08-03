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

// 0 is success

int hook_dsize(struct signature *sig,struct traffic *traffic) {

	// Compare the ID's
	switch(sig->dsize_type) {
		case DSIZE_BIGGER:
			if(sig->dsize < traffic->psize)
				return 0;

		case DSIZE_SMALLER:
			if(sig->dsize > traffic->psize)
				return 0;

		default:
			if(sig->dsize == traffic->psize)
				return 0;
	}

	return 1;
}


// 0 is success
// 1 is failure

int hook_dsize_options(char *key, char *val, struct signature *sig) {

	char *ptr = val;

	if(index(val,',') != NULL) {
		// multiple values not supported atm
		return 1;
	}

	switch(ptr[0]) {
		case '<':
			sig->dsize_type = DSIZE_SMALLER;
			break;
		case '>':
			sig->dsize_type = DSIZE_BIGGER;
			break;
		default:
			sig->dsize_type = DSIZE_BIGGER;
			break;

	}

	// spaces?

	sig->dsize = atoi(val);

	return 0;
}


