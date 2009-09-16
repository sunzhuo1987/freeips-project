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


#ifdef WITH_SYSLOG
#include <syslog.h>
#include <stdarg.h>
#endif

#include <util.h>

int initsyslog = 0;

struct linked_list *logqueue = NULL;
FILE *logfd = NULL;

// Todo add syslog stuff here aswell
void logoutputs_init() {

	int i;
	for(i=0;i<LOG_FILE_NAME_CNT;i++) {
		logoutputs[i].enable = 0;
		logoutputs[i].fd = NULL;
	}
}


void logoutputs_close() {

        int i;
        for(i=0;i<LOG_FILE_NAME_CNT;i++) {
		if(logoutputs[i].fd != NULL)
			fclose(logoutputs[i].fd);
        }
}


void push_message(int type, char *string, va_list ap, struct traffic *data) {
	Message *msg;
	if((msg =(Message *)allocMem(sizeof(Message))) == NULL) {
		fprintf(stderr,"Unable to allocate memory for message\n");
		exit(1);
	}

	if(logqueue == NULL) 
		logqueue = getNewList();

	msg->traffic = data;
	msg->type = type;
        vsnprintf(msg->msg, LOG_MAX_SIZE, string, ap);

	// Now add it to the list
	pushListEntry(msg,logqueue);
        va_end(ap);
}

void pop_all_messages() {
	while(pop_message() != 0) {
		// do nothin..
	}
}


int pop_message() {
	Message *msg;
	char logfile[128];

	if((msg = (Message *)popListEntry(logqueue)) == NULL) {
		return 0;
	}

	// Check if this is a real alert.. if so then dump
	// the traffic and free it
	if(msg->type == LOG_TYPE_ALERT) {

		if(CONFIG_LOG_STDOUT == 1) {
			if(CONFIG_LOG_VERBOSE > VERBOSE_LEVEL1) {
				// Show some more info..
				traffic_dump(msg->traffic);
			}
			if (CONFIG_LOG_VERBOSE > VERBOSE_LEVEL2) {
				// Show REALLY some more info...
				dumphex(msg->traffic->data,msg->traffic->dsize);
			}
		}
		
		if(msg->traffic != NULL && msg->traffic->signature != NULL) {
			// Create the log file name
			if(CONFIG_LOG_PACKET == 1) {
				snprintf(logfile,LOG_MAX_FILENAME,"%s/%s.%d.dump",CONFIG_LOGDIR,inet_ntoa(msg->traffic->iphdr->ip_dst),msg->traffic->signature->sid);
				traffic_to_file(logfile,msg->traffic);
			}
		}
	
		// Free the memory
		traffic_free(msg->traffic);
	}

	do_log(msg);
	freeMem(msg);	
	return 1;
}

void fatal_error(char *string, ...) {
        va_list ap;
        va_start(ap, string);
	push_message(LOG_TYPE_FATAL,string,ap,NULL);
	stats_increase_cnt(CNT_LOG_TYPE_FATAL,1);
	sleep(5);
	sigquit_handler();
	exit(1);
}

void log_error(char *string, ...) {
        va_list ap;
        va_start(ap, string);
	push_message(LOG_TYPE_ERROR,string,ap,NULL);
	stats_increase_cnt(CNT_LOG_TYPE_ERROR,1);
}

void log_info(char *string, ...) {
        va_list ap;
        va_start(ap, string);
	push_message(LOG_TYPE_INFO,string,ap,NULL);
	stats_increase_cnt(CNT_LOG_TYPE_INFO,1);
}

void log_verbose(int level, char *string, ...) {
        va_list ap;

	// If verbosity is not this high then
	// dont print the message.. just bail out
	if(level > CONFIG_LOG_VERBOSE)
		return;

        va_start(ap, string);
        push_message(LOG_TYPE_VERBOSE,string,ap,NULL);
        stats_increase_cnt(CNT_LOG_TYPE_VERBOSE,1);
}

void log_alert(struct traffic *traf,char *string, ...) {
        va_list ap;
        va_start(ap, string);
	push_message(LOG_TYPE_ALERT,string,ap,traf);
	stats_increase_cnt(CNT_LOG_TYPE_ALERT,1);
}

void log_warn(char *string, ...) {
        va_list ap;
        va_start(ap, string);
	push_message(LOG_TYPE_WARN,string,ap,NULL);
	stats_increase_cnt(CNT_LOG_TYPE_WARN,1);
}

void do_log(Message *msg)
{
	char timebuf[20];
	time_t curtime = time(NULL);
	struct tm *loctime = localtime (&curtime);

	// The log types
	char *logtypes[10] = {
		"ERROR",
		"ALERT",
		"FATAL",
		"INFO",
		"WARN",
		"VERBOSE"
	};

	strftime (timebuf, sizeof(timebuf), "%D %H:%M:%m", loctime);
	if(CONFIG_LOG_STDOUT == 1) {
		printf("%s: %s: %s\n",timebuf,logtypes[msg->type],msg->msg);
	}

	if(logoutputs[msg->type].enable == 1) {
		if(logoutputs[msg->type].fd == NULL) {
			if((logoutputs[msg->type].fd = fopen(logoutputs[msg->type].name,"a")) == NULL) {
				printf("ERROR: unable to write logfile: %s! (permissions?)\n",logoutputs[msg->type].name);
				// It is a choice to NOT exit here..
			}
		} else {
			fprintf(logoutputs[msg->type].fd,"%s: %s: %s\n",timebuf,logtypes[msg->type],msg->msg);	
			fflush(logoutputs[msg->type].fd);
		}
	}

	if(CONFIG_LOG_SYSLOG == 1) {
#ifdef WITH_SYSLOG
		if(initsyslog == 0) { 
			openlog (PROGNAME, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1); 
			initsyslog = 1;
		}

		syslog (LOG_NOTICE, "%s: %s: %s\n",timebuf,logtypes[msg->type],msg->msg);
#endif
	}
}

void alert(struct signature* sig, struct traffic* traffic ) {

	char srcadd[16];
	char dstadd[16];

	strncpy(srcadd, inet_ntoa(traffic->iphdr->ip_src), 16);
	strncpy(dstadd, inet_ntoa(traffic->iphdr->ip_dst), 16);

	if(sig->proto == P_TCP) {
		log_alert(traffic,"Detected signature: %d %s:%d --> %s:%d (%s)",sig->sid,srcadd,htons(traffic->tcphdr->th_sport),dstadd,htons(traffic->tcphdr->th_dport),sig->msg);	
		return;
	}

	if(sig->proto == P_UDP) {
		log_alert(traffic,"Detected signature: %d %s:%d --> %s:%d (%s)",sig->sid,srcadd,htons(traffic->udphdr->uh_sport),dstadd,htons(traffic->udphdr->uh_dport),sig->msg);	
	} else {
		log_alert(traffic,"Detected signature: %d %s --> %s (%s)",sig->sid,srcadd,dstadd,sig->msg);	
	}
}

