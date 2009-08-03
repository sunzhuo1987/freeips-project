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
#include <sys/types.h>
#include <pwd.h>

// from main.c
extern int loop_control;
extern int loop_analyzer;
extern int loop_sniffer;
extern int loop_main;
extern pthread_t t_control;
extern pcap_t *handle;


//
// memcmp that allows case insensitive compares
//

int mymemcmp(const void *str1, const void *str2,int size,int nocase) {
	const unsigned char *a = (const unsigned char*) str1;
	const unsigned char *b = (const unsigned char*) str2;
	if(nocase == -1) {
		while(--size >= 0) {
			if(*a++ != *b++) 
				return -1;	
		}

	} else {
		while(--size >= 0) {
			if(tolower(*a++) != tolower(*b++)) 
				return -1;	
		}
	}
	return 0;
}

// Drop privileges for security reasons..
int drop_privileges(char *user) {

	struct passwd *pw = getpwnam(user);

	if (pw == NULL) {
		log_error("Cannot drop privileges to user %s", user);
		return -1;
	}

	// Set group privileges
	if (setegid(pw->pw_gid) == -1 || setgid(pw->pw_gid) == -1) {
		log_error("Privilege dropping error: Unable to set GID to %d",pw->pw_gid);
		return -1;
	}

	// Set user privileges
	if(seteuid(pw->pw_uid) == -1 || setuid(pw->pw_uid)) {
		log_error("Privilege dropping error: Unable to set UID to %d",pw->pw_uid);
		return -1;
	}

	log_info("Dropped privileges to user \"%s\" (UID: %d)",user,getuid());
	return 0;
}

void fork_to_background() {
	int child;
	if((child = fork()) == -1) {
		log_error("Unable to fork process..\n");
		exit(1);
	}
    
	if(child != 0) { 
		exit(0);
	}
}

// convert a hex value to char
char hex2char (char *hex)
{
  char mychar;
  mychar = (hex[0] >= 'A' ? ((hex[0] & 0xdf) - 'A') + 10 : (hex[0] - '0'));
  mychar *= 16;
  mychar += (hex[1] >= 'A' ? ((hex[1] & 0xdf) - 'A') + 10 : (hex[1] - '0'));
  return (mychar);
}


// Dump the buffer in hex value
void dumphex(void *data, int size) {

	char *hex = (char *)data;
	char asarray[20];
	char hxarray[64];
	int starta=0,starth=0;
	int i=0;

	memset(hxarray,0x20,sizeof(hxarray) -1);
	memset(asarray,0x20,sizeof(asarray) -1);

	printf("------------------------------------------------------------------------------------------------------\n");
	for (i=0;i<size;i++) {
		if(iswalpha((int)hex[i])) {
			asarray[starta++] = ((unsigned char*)hex)[i];
		} else {
			asarray[starta++] = '.';
		}

		sprintf(hxarray + starth,"%02x ",((unsigned char *)hex)[i]);
		
		if(starta == 19) {
			asarray[starta] = '\0';
			printf("%s |  %s\n",hxarray,asarray);
			memset(hxarray,0x20,sizeof(hxarray) -1);
			memset(asarray,0x20,sizeof(asarray) -1);
			starth=starta=0;
		} else {
			starth += 3;
		}
	}
	
	asarray[starta] = '\0';
	printf("%57s | %s\n",hxarray,asarray);
	printf("------------------------------------------------------------------------------------------------------\n");
}

// TODO add dynamic payload signature matching (perhaps pcre?)

//
// Usage information
//

void usage() {
	printf("\n\n");
	printf("\n------------------------------------------------------\n");
	printf("                     %s (version: %s)\n",PROGNAME, VERSION);
	printf("------------------------------------------------------\n");
	printf("\n");
	printf("Options:\n");
	printf("   -c  <conf file>   # Configuration\n");
	printf("   -i  <device>      # Read from device (online)\n");
	printf("   -v                # Verbosity\n");
	printf("   				\n");
	printf("   -q                # Quiet mode\n");
	printf("   -d                # Tcpdump mode\n");
	printf("   -s                # Syslog mode\n");
	printf("   -f  <filter>      # Specify the pcap filter\n");
	printf("   -r  <pcap file>   # Read from pcap file (offline)\n");
	printf("   -P  <divert port> # Divert socket\n");
	printf("   -I                # Inline mode\n");
	printf("   -S  <sig file>    # File with signatures\n");
	printf("   -l  <dir>         # Directory for packet dumps\n");
	printf("   -u  <user>        # Run as user\n");
	printf("   -D                # Daemon mode\n");
	printf("   -T                # Disable strict TCP\n");
	printf("\n\n");
}

//
// Cleanup characters
//

// Cleanup a string (remove spaces)Impact on memory?
char * cleanup_char(char *word) {
 
        int i;
        char *ptr = word;
        for(i=0; i<strlen(word); i++) {
                //printf("hex: %x\n",word[i]);
                if(word[i] == HEX_VAL_SPACE) {
                        ptr = word + (i + 1);
                        continue;
                }

                if(word[i] == HEX_VAL_QUOTES) {
                        ptr = word + (i + 1);
                }

                break;
        }

        word = ptr;
        //printf("Word: \"%s\"\n",word);
        for(i=strlen(word) -1; i >= 0; i--) {
                if(word[i] == HEX_VAL_SPACE) {
                        word[i] = '\0';
                        continue;
                }

                if(word[i] == HEX_VAL_QUOTES)
                        word[i] = '\0';

                break;
        }
        return word;
}

int is_file(char *file)  {

	struct stat sbuf;
	if (stat(file, &sbuf) != 0) {
		return 0;
	}
	if (!S_ISREG(sbuf.st_mode)) {
		return 0;
	}

    return 1;
}

int is_dir(char *file) {
	struct stat sbuf;
	if (stat(file, &sbuf) != 0) {
		return 0;
	}
	if (!S_ISDIR(sbuf.st_mode)) {
		return 0;
	}
	return 1;
}


// Signal handles
void sigquit_handler () {
        printf("\n");
        log_info("Received signal..");

        loop_sniffer = 0;
        loop_analyzer = 0;
        loop_control = 0;
        loop_main = 0;

        // Get all messages
        pop_all_messages();

	if(handle != NULL) 
		pcap_breakloop(handle);
	
	//close files
	logfiles_close();

}

// Signal handles
void sighup_handler () {
        printf("\n");
        log_info("Received HUP signal");
	
//      log_info("Stopping control thread..");
//	loop_control = 0;

	// Wait for it to end
//	pthread_join(t_control,NULL);

	// Reload signatures
	reloadSignatures();

	// Start new control thread
//       log_info("Starting new control thread..");
//	loop_control = 1;
//	pthread_create(&t_control,NULL,(void*)control_loop,NULL);
}

//
// String match routing, used by uricontent and content
//
// 0 --> no match possible (e.g. error)
// 1 --> match  
// 2 --> no match

int payload_compare(struct signature *sig, char *data, int psize,int ptype) {

        int i,cindex,strfound = 0,matches=0, breakbool = 0;
        int offset=0, lmatch=0;
	struct payload_opts *popts = NULL;

        for(cindex=0;cindex <SIG_MAX_CONTENT;cindex++) {

		// Loop content or loop uricontent
		if(ptype == TYPE_CONTENT) {
			popts = (struct payload_opts*)sig->content[cindex];
		} else {
			popts = (struct payload_opts*)sig->uricontent[cindex];
		}

		// If below is true then we're done processing the content or
		// uricontent payload options and can check if this signature
		// was a match or not.

                if(popts == NULL) {
                        //printf("matches: %d cindex: %d\n",matches,cindex);
                        if(cindex > 0 && matches == cindex) {
                                return 1;
                        }
                        return 0;
                }

                if(popts->offset > 0) {
                        if(popts->offset >= psize) {
                                DEBUG(stdout,"Offset exceeds data size");
                                return 0;
                        }
                        offset = popts->offset;
                }

		// Distance if an offset that is relative to the 
		// last match..
                if(popts->distance != -1)
                        offset = lmatch + popts->distance;
                if(popts->within != -1)
                        offset = lmatch;

                DEBUGF("Going to inspect %d bytes\n",psize);
                strfound = CONTENT_TEST_NOT_FOUND;
                for (i=offset; i<(psize - popts->matchstr_size) + 1 && breakbool == 0 ;i++) {

                        if(popts->distance != -1)
                                breakbool = 1;

			// If depth was used then only look the amount of bytes
                        // as specified by it

			if(popts->depth > 0 && popts->depth > i)
                                return 0;

                        // within check
                        if(lmatch != 0) {
                                // If 'i' is larger then lmatch + within then the
                                // next string is not within "within" bytes ;p
                                if(popts->within != -1 && i > (lmatch + popts->within)){
                                                break; //  Test.. break instead of return
                                                //return 0;
                                }
                        }

                        // Potential start
                        if(data[i] != ((char *)popts->matchstr)[0])
                                continue;

                        // Check if the is data at "isdataat", relatively to the point
                        // of the last match. isdataat without "relative" is not supported and
                        // can be replaced with dsize.

                        //printf("if(%d != -1 && %d < %d)\n",popts->isdataat,(psize - (i + popts->matchstr_size)),popts->isdataat);
                        if(popts->isdataat != -1 && (psize - (i + popts->matchstr_size)) < popts->isdataat) {
                                return 0;
                        }

                        // Match
                        if(mymemcmp(data + i,popts->matchstr,popts->matchstr_size,popts->nocase) == 0) {

                                // Continue searching ater match
                                i = (i + popts->matchstr_size);


                                // Last matchpointer
                                lmatch = i;
                                strfound = CONTENT_TEST_FOUND;
                                break;
                        }
                }

                if(popts->test == strfound)
                        matches++;
        }
        // No match
        return 2;
}


int base64_encode(char *input,char *output) {

	unsigned char alphabet[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	
	int i,bits, char_count;
	int a = 0;
	char_count = 0;
	bits = 0;
	for (i=0;i<strlen(input) && input[i] != '\0'; i++) {
		bits += input[i];
		char_count++;
		if (char_count == 3) {
			output[a++] = alphabet[bits >> 18];	
			output[a++] = alphabet[(bits >> 12) & 0x3f];	
			output[a++] = alphabet[(bits >> 6) & 0x3f];	
			output[a++] = alphabet[bits & 0x3f];	
			bits = 0;
			char_count = 0;
		} else {
			bits <<= 8;
		}
	}
	if (char_count != 0) {
		bits <<= 16 - (8 * char_count);
		output[a++] = alphabet[bits >> 18];
		output[a++] = alphabet[(bits >> 12) & 0x3f];

		if (char_count == 1) {
			output[a++] = '=';
			output[a++] = '=';
		} else {
			output[a++] = alphabet[(bits >> 6) & 0x3f];
			output[a++] = '=';
		}
	}

	// Terminate
	output[a] = '\0';
	return 0;
}



