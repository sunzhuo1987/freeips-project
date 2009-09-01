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

// 0 is no match
// 1 is match

int hook_content(struct signature *sig,struct traffic *traffic) {

	struct payload_opts *popts = (struct signature *) sig->content[sig->content_idx];

	if(popts == NULL) {
		fatal_error("Content reference not present, still requested: %d",sig->content_idx);
	}

	// Increase the index in case we get called again
	sig->content_idx++;

        if(new_payload_compare(sig,traffic,popts)) {
		return 1;
	}

	return 0;
}


// 0 is success
// 1 is failure

int hook_content_options(char *key, char *val, struct signature *sig) {

	char *tptr, *tmpstr=strdup(val);
	char converted;
	int i,cindex,tmpi=0;
	struct payload_opts *popts;

	val = cleanup_char(val);
	tptr=val;

	// Find a slot to put the content struct into
	for(cindex=0;cindex<SIG_MAX_CONTENT;cindex++) {
		if(sig->content[cindex] == NULL) {
			break;
		}
	}

	if(cindex == SIG_MAX_CONTENT) {
		log_error("Signature has more then 10 content's");
		return 1;
	}
        
	// Create the content struct
	sig->content[cindex] = (struct content*) allocMem(sizeof(struct content));
	memset(sig->content[cindex],0,sizeof(struct content));

	popts = (struct payload_opts*)sig->content[cindex];
	popts->offset   = -1;
	popts->depth    = -1;
	popts->within   = -1;
	popts->distance = -1;
	popts->nocase   = -1;
	popts->isdataat = -1;
	popts->test     = CONTENT_TEST_FOUND;
	sig->content[cindex]->replace  = NULL;

	if(val[0] == '!') {
		tmpstr = val = cleanup_char(tmpstr + 1);
		popts->test = CONTENT_TEST_NOT_FOUND;
	}

	// Look for HEX values and convert them to
	// normal bytes.. this to allow a memcmp

	for(i=0;i<strlen(val);) {
		// Look for a pipe
		if(val[i] != HEX_VAL_PIPE) {
			tmpstr[tmpi++] = val[i++];
		} else {

			// If escaped then just add the character. Otherwise, we have
			// a hex value that needs to be parsed.
			if(i != 0 && val[i - 1] == HEX_VAL_BSLASH) {
				tmpstr[tmpi++] = val[i++];
			} else {

				i++; // skip the |
				do {    
					if(val[i] == HEX_VAL_SPACE)
						i++;

					converted = hex2char(val + i);
					tmpstr[tmpi++] = converted;
					i += 2;
				} while(val[i] == HEX_VAL_SPACE);
				i++; // skip the |
			}
		}
	}

	// Terminate the string
	tmpstr[tmpi] = '\0';

	popts->matchstr_size = tmpi;
	popts->matchstr = tmpstr;
	return 0;
}


