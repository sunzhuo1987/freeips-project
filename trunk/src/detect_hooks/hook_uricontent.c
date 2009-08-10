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

int hook_uricontent(struct signature *sig,struct traffic *traffic) {

	char *tmp,*ptr,*uri,*request;
	int uritype = 0;

	// If already looked at, and no URI is present.. then just
	// "forget about it"
	if(traffic->http_processed == 1 && traffic->http_uri == NULL) {
		return 0;
	}

	// If URI is already available, go and compare immediate
	// instead of doing all the processing..
	if(traffic->http_uri != NULL) {
		return payload_compare(sig,traffic->http_uri,strlen(traffic->http_uri),TYPE_URICONTENT);
	}

	// Set the processed flag
	traffic->http_processed = 1;

	// Rediculous size..
	if(traffic->psize < 0) {
		return 0;
	}

	// Check if this could be HTTP traffic
	if(strstr(traffic->payload, "HTTP/1.") == NULL) {
		return 0;
	}

	if((tmp = strstr(traffic->payload, "\r\n\r\n")) == NULL) {
		return 0;
	}

	// Terminate, we only look at the HTTP headers
	*tmp = '\0';

	//printf("Detected HTTP traffic\n");

	// Possible issue here if ptruest is without \r's
	// Need to be tested and extended
	if((ptr = strtok(traffic->payload, "\r\n")) == NULL) {
		//printf("did not find \\r\\n");
		return 0;	
	}

	//Crawl to the first G P C or H
	while(*ptr != 'G' && *ptr != 'P' && *ptr != 'C' && *ptr != 'H') {
		//printf("In loop ptr %c!\n",*ptr);
		// And continue;
		if(++ptr == NULL) {
			//printf("False alarm..\n");		
			return 0;	
		}
	} 

	if (strncmp(ptr, "GET ", 4) == 0) {
		uritype = URI_REQUEST_GET;
		request = ptr;
		uri = strchr(ptr, ' ');
	} else if(strncmp(ptr, "POST ", 5) == 0) {
		uritype = URI_REQUEST_POST;
		request = ptr;
		uri = strchr(ptr, ' ');
	} else if(strncmp(ptr, "CONNECT ", 8) == 0) {
		uritype = URI_REQUEST_CONNECT;
		request = ptr;
		uri = strchr(ptr, ' ');
	} else if(strncmp(ptr, "HEAD ", 5) == 0) {
		uritype = URI_REQUEST_HEAD;
		request = ptr;
		uri = strchr(ptr, ' ');
	} else {
		//It didn't work out ;p
		return 0;
	}

	// The below stuff might not be the best way for processing.. it 
	// all depends on whether the METHOD and HTTP/x.x should be part of
	// signature matching..

	uri++;			// First space
	tmp = strchr(uri, ' '); // Find last space
	*tmp++ = '\0';		// And terminate (HTTP/1.)

	//printf("Got URI %d:     \"%s\"\n",uritype,uri);
	//printf("Got REQUEST %d: \"%s\"\n",uritype,request);

	//printf("Going into while loop\n");
	while(ptr != NULL) {
		// Get header info..
		//printf("got also: %s\n",ptr);
		ptr = strtok(NULL, "\r\n");
	}

	traffic->http_uri = uri;

	// Ok and now the processing can start.  First the content needs to
	// be normalized before doing a signature match.
	

	// uri = normalize_uri(uri)
	//printf("Going to test URI: %s\n",uri);
	return payload_compare(sig,uri,strlen(uri),TYPE_URICONTENT);
}


// 0 is success
// 1 is failure

int hook_uricontent_options(char *key, char *val, struct signature *sig) {

        int cindex;
	struct payload_opts *popts;
                                
        val = cleanup_char(val);
	//printf("VAL: \"%s\"\n", val);
                                                    
	// Find a slot to put this struct into
        for(cindex=0;cindex<SIG_MAX_CONTENT;cindex++) {
                if(sig->uricontent[cindex] == NULL) {
                        break;
                }
        }

        if(cindex == SIG_MAX_CONTENT) {
                log_error("Signature has more then %d uricontent's",SIG_MAX_CONTENT);
                return 1;
        }

        // Create the uricontent struct
        sig->uricontent[cindex] = (struct uricontent*) allocMem(sizeof(struct uricontent));
        memset(sig->uricontent[cindex],0,sizeof(struct uricontent));

	// This allows manipulation of the payload_opts struct which is part of
	// the uricontent struct
	popts = (struct payload_opts*) sig->uricontent[cindex];
        sig->uricontent[cindex]->urilen = -1;
        popts->test   = CONTENT_TEST_FOUND;
        popts->nocase   = -1;
        popts->isdataat = -1;
        popts->offset   = -1;
        popts->depth    = -1;
        popts->within   = -1;
        popts->distance = -1;

        if(val[0] == '!') {
                val = cleanup_char(val + 1);
                popts->test = URICONTENT_TEST_NOT_FOUND;
        }

	// In the 'content' code, this is where hex values would be converted
	// I left it out here intentionally. AFAIK hex is not supported in this keyword
	// and otherwise we'll have to add it later ;p. 

	//printf("URICONTENT: matchstr_size = %d\n",strlen(val));
	//printf("URICONTENT: matchstr = \"%s\"\n",val);

        popts->matchstr_size = strlen(val);
        popts->matchstr = (char *)allocMem(strlen(val)+1);
	
	memset(popts->matchstr,0,strlen(val)+1);
	strncpy(popts->matchstr,val,strlen(val));

	return 0;
}
