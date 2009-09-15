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

int hook_pcre(struct signature *sig,struct traffic *traffic) {
	if(match_pcre(sig->regex,traffic->payload,traffic->psize) == 0) {
		if(sig->regex->test == PCRE_TEST_FOUND) {
			return 1;
		}
	} else { 

		if(sig->regex->test == PCRE_TEST_NOT_FOUND) {
			return 1;
		}
	}
	return 0;
}

int hook_pcre_options(char *key, char *val, struct signature *sig) {

	if((sig->regex = (PcreRegex *)allocMem(sizeof(PcreRegex))) == NULL) {
		fatal_error("Unable to alloc mem for PcreRegex");
	}

	return compile_pcre(sig->regex,cleanup_char(val));
}

int compile_pcre (PcreRegex *regex, char *string) {
	const char *error;
	int erroroffset;

	if((string = prepare_pcre_string(regex,string)) == NULL ) {
		if(CONFIG_LOG_VERBOSE > 1)
			log_error("Unable to prepare PCRE string");

		return 1;
	}

	// Compile the match string
	regex->matchstr = pcre_compile(string,0,&error,&erroroffset,NULL);
	if(regex->matchstr == NULL) {
		log_error("Unable to compile PCRE string");
		return 1;
	}
	return 0;
}

char * prepare_pcre_string(PcreRegex *regex, char *word) {
 
        int i = 0;
	int o = 0;
	int escape = 0;
        char *str, *ptr;
	char sep = '/';

	// Set test to be performed (should there be a match or not)
        if(word[0] == '!') {
                word = cleanup_char(word + 1);
		regex->test = PCRE_TEST_NOT_FOUND;
        } else {
		regex->test = PCRE_TEST_FOUND;
	}

	if((str = strdup(word)) == NULL) {
		fatal_error("prepare_pcre_string() Unable to allocate memory\n");
		return NULL;
	}

	// A different seperator then / can be used. In that
	// case, register the seperator.
	if(word[i] == 'm' && word[++i] != '\0') {
		sep = word[i];
		//printf("Sep: %c\n",sep);
	}

	ptr = word + (i + 1);

	//Now extract the match string
	while(word[i++] != '\0') {
		o++;

		if(i >= strlen(word)) {
			printf("End of word reached..\n");
			return NULL;
		}

		// Check if this is an escaped character
		// meaning we should sckip the next
		if(word[i] == HEX_VAL_BSLASH && escape == 0) {
			escape = 1;
			continue;
		}

		// If the word is escaped then skip it and
		// continue
		if(escape == 1) {
			escape = 0;
			continue;
		}

		if(word[i] == sep)
			break;
        }

	memset(str,0,strlen(str));
	strncpy(str,ptr,o);

	// Now parse the options..
	regex->compile_options = 0;
	while(word[++i] != '\0') {
		switch(word[i]) {
			case 'i':
				regex->compile_options |= PCRE_CASELESS;
				break;
			case 's':
				regex->compile_options |= PCRE_DOTALL;
				break;
			case 'm':
				regex->compile_options |= PCRE_MULTILINE;
				break;
			case 'x':
				regex->compile_options |= PCRE_EXTENDED;
				break;
			case 'A':
				regex->compile_options |= PCRE_ANCHORED;
				break;
			case 'E':
				regex->compile_options |= PCRE_DOLLAR_ENDONLY;
				break;
			case 'G':
				regex->compile_options |= PCRE_UNGREEDY;
				break;

			// The ones below are snort specific..
			case 'R':
				// TODO
				break;
			case 'U':
				// TODO
				break;
			case 'B':
				// TODO
				break;
			default:
				//printf("Unknown pcre option: %c\n",word[i]);
				return NULL;
				// TODO
				break;
		}
	}
	return str;
}

int match_pcre (PcreRegex *regex, char *data, int dsize) {

	int rc = pcre_exec(
	  regex->matchstr,      /* the compiled pattern */
	  NULL,                 /* no extra data - we didn't study the pattern */
	  data,                 /* the subject string */
	  dsize,                /* the length of the subject */
	  0,                    /* start at offset 0 in the subject */
	  0,       /* default options */
	  NULL,                 /* output vector for substring information */
	  0);                   /* number of elements in the output vector */

	DEBUGF("PCRE Return value = %d\n",rc); 
	return rc;
}




