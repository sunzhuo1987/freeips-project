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

extern HashTable *session;
extern DetectHook *DetectHooks[DETECT_HOOK_MAX_CNT];
int siginit = 0;
int sigcount = 0;

// Load the signature list. Right now sort them per protocol in the signature array. The sigs can
// then dynamicly be sorted on their *hits* to make sure we get the most popular signatures first
// while iterating the list.

int load_signatures(char *sigfile) {

	char sigline[MAX_SIG_LINE];
	char *ptr;
	FILE *fp;
	int i=0,lcount = 0;
	struct signature *sigstruct;

	// If this is a directory then parse all files in it
	// this makes it easier to organize the signatures

	if(is_dir(sigfile)) {
		return read_sig_dir(sigfile);
	}

	// initialize one
	if(siginit++ == 0) {
		// First initialize the signature array with NULL:w
		for(i=0;i<SIG_ARRAY_SIZE;i++) {
			sigarray[i] = NULL;
		}
	}

	if ((fp = fopen(sigfile, "r")) == NULL){
		fprintf(stderr, "Unable to open file %s!\n", sigfile);
		return -1;
	}

	log_verbose("Parsing signature file: %s",sigfile);

	while(fgets(sigline,MAX_SIG_LINE,fp) != NULL) {
		ptr = sigline;
		lcount++;

		// Skip comments and unreasonable small lines
		if (strncmp(sigline,"#",1) == 0 || strlen(sigline) < 10) 
			continue;

		DEBUGF("Going to process signature: %s\n",sigline);
		sigstruct = getSignatureStruct();
		if(sigparse(sigline,sigstruct) == 1) {
			if(CONFIG_LOG_VERBOSE > 2) {
				log_warn("Signature error #%d: %s\n",lcount,sigline);
			}
			freeMem(sigstruct);
			continue;
		}

		// Sort the hooks
		sort_hooks(sigstruct);

		if(validateSignature(sigstruct)) {
			log_verbose("Invalid signature at line %d: %s",lcount,sigline);
			freeMem(sigstruct);
			continue;
		}

#ifdef TCP_DEBUG_SIGNATURE
		dumpSignature(sigstruct);
#endif

		// Check if we need to initialize the new proto list
		if(sigstruct->proto < SIG_ARRAY_SIZE && sigarray[sigstruct->proto] == NULL) {
			DEBUGF("Initializing signature list for protocol: %d\n",sigstruct->proto);
			sigarray[sigstruct->proto] = getNewList();
		}
		
		DEBUGF("Read signature: %s \n",sigstruct->msg);
		pushListEntry(sigstruct,sigarray[sigstruct->proto]);
		sigcount++;
	}

	return sigcount;
}

int freeSignatures() {

	if(sigarray[P_UNKNOWN] != NULL)
		freeList(sigarray[P_UNKNOWN],1);

	if(sigarray[P_UNKNOWN] != NULL)
		freeList(sigarray[P_ICMP],1);

	if(sigarray[P_UNKNOWN] != NULL)
		freeList(sigarray[P_TCP],1);

	if(sigarray[P_UNKNOWN] != NULL)
		freeList(sigarray[P_UDP],1);

	// ensure fresh start..
	siginit=0;

	return 1;
}

int read_sig_dir(char *dir) {

	DIR *d;
	struct dirent *p;
	char path[MAX_PATH];
	int count  = 0;
	int scount = 0;

	if ((d = opendir(dir)) == NULL){
		log_error("Opendir failed ! %s\n", dir);
		return 0;
	} 
	p = readdir(d); // skip .
	p = readdir(d); // skip ..

	while ((p = readdir(d)) != NULL) {
		snprintf(path,MAX_PATH,"%s/%s",dir,p->d_name);
		if(is_file(path)) {
			scount = load_signatures(path);
			count += scount;
		}
	}
	closedir(d);
	return count;
}

void sigparse_defaults(char *string, struct signature *sig) {

	char *token, *str;
	int strcnt = 0;

	if((str = strdup(string)) == NULL) 
		fatal_error("Unable to duplicate string!\n");

	token = strtok(str," ");
	while((token = strtok(NULL," ")) != NULL) {
		switch(++strcnt) {
			case 1:
				if(strcmp(token,"tcp") == 0) {
					sig->proto = P_TCP;
				} else if(strcmp(token,"udp") == 0) {
					sig->proto = P_UDP;
				} else if(strcmp(token,"icmp") == 0) {
					sig->proto = P_ICMP;
				}
 
				break;
			case 2:
				// from
				break;
			case 3:
				sig->srcport = parseport(token);
				break;
			case 4:
				// ->
				break;
			case 5:
				// to
				break;
			case 6:
				sig->dstport = parseport(token);
				break;
		}
	}

	//free the duplicated string
	free(str);
}

int parseport(char *token) {
	int notflag = 0;
	int ret;

	if(token[0] == '!') {
		notflag = 1;
		(*token)++;
	}

	if(strcmp(token,"any") == 0) {
		ret = -1;
	} else if(strcmp(token,"$HTTP_PORTS") == 0) {
		ret = 80;
	} else if(strcmp(token,"$SSH_PORTS") == 0) {
		ret = 22;
	} else if(strcmp(token,"$HTTPS_PORTS") == 0) {
		ret = 443;
	} else if(index(token,HEX_VAL_COL) != NULL) {
		//Todo
		ret = -1;
	} else {
		ret = atoi(token);
	}

	// Todo better port validating
	if(ret > 65535 || ret < -1) 
		log_error("Invalid port: %d",ret);

	return ret;
}

// Parse the rule and initialize the signature struct
//
// 0 is OK
// 1 is failure

int sigparse (char *string,struct signature *sig) {

        char buf[MAX_SIG_PART_SIZE];
        int quoted=0;
        int count=0;
        char *ptr,*lineptr,*vptr;

	// Reset the popts pointer
	sig->popts = NULL;

	// Parse the first part of the line
	sigparse_defaults(string,sig);

        // Go to the start.
        if((ptr = index(string,HEX_VAL_BRACKET)) == NULL) {
		return 1;
	}

        lineptr = ++ptr;

        for(;*ptr != '\0';ptr++) {

                count++;
                if(*ptr==HEX_VAL_BSLASH) {
                        // Escaped char, skip next
                        count++;
                        ptr++;
                        continue;
		}

                // Keep track of whether were in a
                // quoted part..
                if(*ptr == HEX_VAL_QUOTES) {
                        if(quoted == 0) {
                                quoted = 1;
                        } else {
                                quoted = 0;
                        }
                        continue;
                }

                // If this is true, then we reached the end
                // And can try to parse key, value
                if(*ptr == HEX_VAL_COL && quoted == 0) {

			// Space means nothing.. not sure if this is a clean
			// way to do.. please review and comment.
			while(*lineptr == HEX_VAL_SPACE && count != 0) {
				lineptr++;
				count--;
			}

			if(count > MAX_SIG_PART_SIZE) { 
				log_error("Signature parsing error (max buf size reached)");
				return 1;
			}

                        // Parse, -1 to get rid of the ;
                        memset(buf,0,MAX_SIG_PART_SIZE);
                        strncpy(buf, lineptr, count -1);

                        if((vptr = index(buf,':')) == NULL) {
                                // Keyword only..
				vptr = NULL;
                        } else {
                                // Key, val pair.. split
                                *vptr = '\0';
                                vptr++;
                        }

			//printf("KEY \"%s\" VAL: \"%s\"\n",buf, vptr);
                        if(parseOption(buf,vptr,sig) == 1) {
                                return 1;
                        }

                        //Then update line pointer
                        lineptr += count;
                        count = 0;
                }
        }

	return 0;
}


// Get the options from the signature
int parseOption(char *name, char *val, struct signature *sig) {

	struct content* content;
	DetectHook *hook;
	int count;

        if(strncmp(name,"nocase",6) == 0) {
		if(sig->popts == NULL) {
			log_error("Found nocase without (uri)content first\n");
			return 1;
		}
                sig->popts->nocase = 1;
                return 0;
        }

        if(strncmp(name,"metadata",8) == 0) {
		return 0;
	}

	// The options below require a value so bail out
	// is no value has been given
        if(val == NULL) 
                return 0;

	// Loop over the detection hooks
	for(count=0;count<DETECT_HOOK_MAX_CNT;count++) {
		if(DetectHooks[count] == NULL)
			break;

		if(strcmp(name,DetectHooks[count]->name) == 0) {
			// Link the detection hook
			if((hook = detect_hook_link(sig,name)) != NULL) {
				if(hook->hook_parse_option(name,cleanup_char(val),sig) == 1) {
					log_error("Signature parsing error: %s (%s)\n",sig->msg,name);
					return 1;
				}

				// if its "content" or "uricontent" then sig->popts must point to the right
				// structure in order to set the payload options such as offset, nocase ..
				// Todo: optimize.. perhaps a pointer in the signature struct ?

				if(strcmp(name,"content") == 0) {
					sig->popts = (struct payload_opts*)get_last_content(sig);
				}

				if(strcmp(name,"uricontent") == 0) {
					sig->popts = (struct payload_opts*)get_last_uricontent(sig);
				}
			}
			return 0;
		}
	}

        if(strncmp(name,"action",6) == 0) {

		val = cleanup_char(val);
		//printf("Action --> \"%s\"\n",val);

		if(strcmp(val,"drop") == 0) {
			sig->action = SIG_ACTION_DROP;
		}

		if(strcmp(val,"pass") == 0) {
			sig->action = SIG_ACTION_PASS;
		}

                return 0;
        }

        if(strncmp(name,"msg",3) == 0) {
                sig->msg = strdup(val);
                return 0;
        }

        if(strncmp(name,"classtype",9) == 0) {
                sig->classtype = strdup(val);
                return 0;
        }

        if(strncmp(name,"sid",3) == 0) {
                sig->sid = atoi(val);
                return 0;
        }

        if(strncmp(name,"rev",3) == 0) {
                sig->rev = atoi(val);
                return 0;
        }

        if(strncmp(name,"depth",5) == 0) {
		if(sig->popts == NULL) {
			log_error("Found depth keyword without (uri)content first\n");
			return 1;
		}
	
		if(sig->popts->depth != -1) {
			log_error("Found second depth for (uri)content?!\n");
			return 1;
		}

                sig->popts->depth = atoi(val);
                return 0;
        }

        if(strncmp(name,"isdataat",10) == 0) {
		if(index(val,',') == NULL) {
			// Todo, this error is not correct.. well atleast not
			// from a Snort perspective (usage of isdataat in conjunction with
			// distance 
			log_error("isdataat without relative.. use dsize instead");
			return 1;
		}

		if (sig->popts == NULL) {
			log_error("Found isdataat without (uri)content first \n");
			return 1;
		}

		if((val = strtok(val,",")) == NULL) {
			log_error("stroken error at isdataat ");
			return 1;
		}

                sig->popts->isdataat = atoi(val);
                return 0;
        }

        if(strncmp(name,"offset",6) == 0) {
		if(sig->popts == NULL) {
			log_error("Found offset keyword without (uri)content first\n");
			return 1;
		}

		// Check if already initialized
		if(sig->popts->offset != -1) {
			log_error("Found second offset for (uri)content?!\n");
			return 1;
		}
                sig->popts->offset = atoi(val);
                return 0;
        }

        if(strncmp(name,"within",6) == 0) {
		if(sig->popts == NULL) {
			log_error("Found within keyword without (uri)content first\n");
			return 1;
		}
                sig->popts->within = atoi(val);
                return 0;
        }

	// Replace is fun ;p but BROKEN
        if(strncmp(name,"replace",7) == 0) {
		if((content = get_last_content(sig)) == NULL) {
			log_error("Found replace keyword without content first\n");
			return 1;
		}
                content->replace = strdup(val);
                return 0;
        }


        if(strncmp(name,"distance",8) == 0) {
		if(sig->popts == NULL) {
			log_error("Found distance keyword without (uri)content first\n");
			return 1;
		}
                sig->popts->distance = atoi(val);
                return 0;
        }

        if(strncmp(name,"reference",9) == 0) {
                sig->reference = strdup(val);
                return 0;
        }

	if(CONFIG_LOG_VERBOSE > 2) {
		log_info("Unsupported option: %s --> %s\n",name,val);
	}

	if(CONFIG_SIG_STRICT_LOAD == 1) {
		return 1;
	} else {
		return 0;
	}
}

struct content* get_last_content(struct signature *sig) {
	int cindex;
	struct content *last = NULL;
	for(cindex=0;cindex<SIG_MAX_CONTENT;cindex++) {
		if(sig->content[cindex] == NULL) {
			break;
		}
		last = sig->content[cindex];
	}

	if(last == NULL)
		printf("NULL!!!!\n");

	return last;
}

struct uricontent* get_last_uricontent(struct signature *sig) {
	int cindex;
	struct uricontent *last = NULL;
	for(cindex=0;cindex<SIG_MAX_CONTENT;cindex++) {
		if(sig->uricontent[cindex] == NULL) {
			break;
		}
		last = sig->uricontent[cindex];
	}
	if(last == NULL)
		printf("NULL!!!!\n");

	return last;
}


// Match signature. Return 1 if it matched a signature..
struct signature* match_signature(struct traffic* traffic) {

	// Bail out if we have no signatures for this protocol
	if(sigarray[traffic->proto] == NULL)
		return NULL;

	// TODO: add locking
        struct list_entry* ret = sigarray[traffic->proto]->start;
	struct signature* sret;
	int count, retval;

	// Return if 0
	if(ret == NULL)
		return NULL; 

	do {
		sret = (struct signature*)ret->data;

		if(sret->proto != traffic->proto)
			continue;

		if(traffic->proto == P_TCP) {
			if(sret->srcport != -1 && sret->srcport != htons(traffic->tcphdr->th_sport)) {
				continue;
			}
			if(sret->dstport != -1 && sret->dstport != htons(traffic->tcphdr->th_dport)) {
				continue;
			}
		}

		if(traffic->proto == P_UDP) {
			if(sret->srcport != -1 && sret->srcport != htons(traffic->udphdr->uh_sport)) {
				continue;
			}
			if(sret->dstport != -1 && sret->dstport != htons(traffic->udphdr->uh_dport)) {
				continue;
			}
		}

		// Fire off the detection hooks
		for(count=0; count<DETECT_HOOK_MAX_CNT;count++) {
			if(sret->DetectHooks[count] == NULL)
				break;

			// 0 means no match, 1 means bingo
			retval = sret->DetectHooks[count]->hook(sret,traffic);
			//printf("Hook %s returned %d\n",sret->DetectHooks[count]->name,retval);
			if(retval == 0) {
				break;
			}			
		}

		// Check the last return value.. if its 0 then continue to the
		// next signature
		if(retval == 0) {
			continue;
		}

		// Reached the end.. this means the packet matches all requirements and
		// thus we can return the signature.

		stats_increase_cnt(CNT_SIG_MATCH,1);
		return sret;

	} while((ret = ret->next) != NULL);

	return NULL;
}

//
// Dump signature
//

void dumpSignature(struct signature *sig) {

	//int i;
	printf("\n\n ======> SID: %d\n",sig->sid);
	printf("Message:     %s\n",sig->msg);
//	printf("Matchstr:    \"%s\"\n",sig->matchstr);
	//printf("Matchstr:    Hex: \"");

	//for(i =0; i < sig->matchstr_size;i++) {
//		printf("%x ",sig->matchstr[i]);
//	}
//	printf("\b\"\n");

	
	printf("Proto:       %d\n",sig->proto);
	printf("Srcport:     %d\n",sig->srcport);
	printf("Dstport:     %d\n",sig->dstport);
	//printf("Classtype:   %s\n",sig->classtype);
	//printf("Conn state:  %s\n",sig->connection_state);

}


int validateSignature(struct signature *sig) {
	if(sig->msg == NULL)
		return 1;

	if(sig->proto == P_TCP || sig->proto == P_UDP || sig->proto == P_ICMP)
		return 0;
	
	return 1;
}

//
// Based on the sort routing in llist
//

void signatureSort(void *ptr) {

        // bubble bubble
        struct list_entry* first;
        struct list_entry* second;
        struct signature* ssig;
        struct signature* fsig;
        struct linked_list* list = (struct linked_list*)ptr;
        int change=1;

        DEBUG(stdout, "SORTER: Going to sort !");

        // TODO Lock the list
        while(change != 0) {
                change=0;
                first = list->start;
                while (first != NULL && first->next != NULL) {
                        second = first->next;
                        //printf("Comparing %d --> %d \n",second->hits,first->hits);

                        ssig =  (struct signature*) first->data;
                        fsig =  (struct signature*) second->data;

                        if(ssig->hits > fsig->hits) {
                                change++;
                                swap(second,first);
                        }

                        first = first->next;
                }

                first = list->stop;
                while (first != NULL && first->prev != NULL) {
                        second = first->prev;
                        //printf("Comparing %d --> %d \n",second->hits,first->hits);
                        if(second->hits < first->hits) {
                                change++;
                                swap(second,first);
                        }

                        first = first->prev;
                }
                DEBUGF("SORTER: This sort run changed: %d\n", change);
        }
}


//
// This is a cheat.. this swap only swaps the structs entry
// data and hist members.. If you read this and feel like taking
// a challenge.. implement a merge sort or some other more performant
// algorithm, then send it to me
//

void swap (struct list_entry *one, struct list_entry *two) {
        void *data = one->data;
        int hits   = one->hits;
        int id     = one->id;

        one->data = two->data;
        two->data = data;

        one->hits = two->hits;
        two->hits = hits;

        one->id = two->id;
        two->id = id;
}

//
// Get a new signature struct with the correct default values
//

struct signature * getSignatureStruct() {

                struct signature * sigstruct = (struct signature*) allocMem(sizeof(struct signature));
		int i;
		if(sigstruct == NULL) {
			log_error("Unable to allocate new signature struct");
			return NULL;
		}

		memset(sigstruct,0,sizeof(sigstruct));
                sigstruct->direction = -1;
                sigstruct->dsize_type = DSIZE_EQUAL;
                sigstruct->dsize = 0;
		sigstruct->connection_state = -1;
		sigstruct->regex  = NULL;

		// Default actoin is drop. Todo: make this configurable
		sigstruct->action = SIG_ACTION_DROP;

		sigstruct->tflags.flags = 0;
		sigstruct->tflags_ignore.flags = 0;

		for(i=0;i < SIG_MAX_CONTENT;i++) 
			sigstruct->content[i] = NULL;

		for(i=0;i < SIG_MAX_CONTENT;i++) 
			sigstruct->uricontent[i] = NULL;

		for(i=0;i <DETECT_HOOK_MAX_CNT;i++) 
			sigstruct->DetectHooks[i] = NULL;

		return sigstruct;
}



