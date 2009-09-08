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

struct timeval tm_now;
struct timeval tm_last;
extern struct timeval shutdowntime;
extern struct linked_list *trafficlist;
extern struct linked_list *logqueue;
int lastdata = 0;

extern struct timeval startuptime;

void stats_init() {
        int i=0;
        for(i=0;i<MAX_CNTS;i++) {
                stat_cnts[i] = 0;
        }

	gettimeofday( &tm_last, NULL );
}

void stats_increase_cnt(int id,int val) {
	stat_cnts[id] += val;
}

// downdate ;p
void stats_decrease_cnt(int id,int val) {
	stat_cnts[id] -= val;
}

unsigned int stat_get(int id) {
	return stat_cnts[id];
}

void stats_show_cnt_line() {

	gettimeofday( &tm_now, NULL );
	int secondsrunning = tm_now.tv_sec - tm_last.tv_sec;
	int currentdata = stat_get(CNT_IP_DATA_SIZE);
	char *rname = "Kbps";

	float rate = (((currentdata - lastdata) * 8) / 1024) / secondsrunning;

	if(rate > 1024) {
		rate = rate/1024;
		rname = "Mbps";
	}

	lastdata = currentdata;
	tm_last.tv_sec = tm_now.tv_sec;

	log_info("STATS #1: Rate:%3.2f %s IP:%d (frags:%d) TCP:%d UDP:%d ICMP:%d Matches:%d Sessions:%d TOTAL DATA:%d",rate, rname,
					stat_get(CNT_IP),stat_get(CNT_IP_FRAG), stat_get(CNT_TCP), stat_get(CNT_UDP), stat_get(CNT_ICMP), 
					stat_get(CNT_SIG_MATCH), stat_get(CNT_SESSION_TOTAL),stat_get(CNT_IP_DATA_SIZE)  );

	log_info("STATS #2: Sigs:%d Alloc:%d Free:%d Qpush:%d Qpop:%d ",stat_get(CNT_SIG_LOADED), stat_get(CNT_MEM_ALLOC), 
					stat_get(CNT_MEM_FREE),stat_get(CNT_QUEUE_PUSH),stat_get(CNT_QUEUE_POP)  );

}

void dump_stats(FILE *fd) {


	char *rname = "kbps";
	int secondsrunning = shutdowntime.tv_sec - startuptime.tv_sec;
	float rate = ((stat_get(CNT_IP_DATA_SIZE) * 8) / 1024) / secondsrunning;

	if(rate > 1024) {
		rate = rate/1024;
		rname = "Mbps";
	}


	fprintf(fd,"\n--------------------------------------\n");
	fprintf(fd,"            IDS STATISTICS\n");
	fprintf(fd,"--------------------------------------\n");
	fprintf(fd,"IP                %d\n",stat_get(CNT_IP));
	fprintf(fd,"IP Error          %d\n",stat_get(CNT_IP_ERR));
	fprintf(fd,"IP Queue          %d\n",trafficlist->data_cnt);
	fprintf(fd,"IP Frags          %d\n",stat_get(CNT_IP_FRAG));
	fprintf(fd,"IP Frags Tmout    %d\n",stat_get(CNT_IP_FRAG_TMOUT));
	fprintf(fd,"IP Frags Reass    %d\n",stat_get(CNT_IP_FRAG_REASS));
	fprintf(fd,"IP Frags Queue    %d\n",stat_get(CNT_IP_FRAG_QUEUE));
	fprintf(fd,"IP Ring Buffer    %d\n",trafficlist->entry_cnt);
	fprintf(fd,"TCP               %d\n",stat_get(CNT_TCP));
	fprintf(fd,"UDP               %d\n",stat_get(CNT_UDP));
	fprintf(fd,"ICMP              %d\n",stat_get(CNT_ICMP));
	fprintf(fd,"Sessions cnt      %d (total)\n",stat_get(CNT_SESSION_TOTAL));
	fprintf(fd,"Total data        %d MB\n",stat_get(CNT_IP_DATA_SIZE) / (1024 * 1024));
	fprintf(fd,"Sig match         %d\n",stat_get(CNT_SIG_MATCH));
	fprintf(fd,"Sig count         %d\n",stat_get(CNT_SIG_LOADED));
	fprintf(fd,"Sig tests total   %d\n",stat_get(CNT_SIG_TESTS));
	fprintf(fd,"Sig tests indexed %d\n",stat_get(CNT_SIG_TESTS_INDEX));
	fprintf(fd,"\n");
	fprintf(fd,"Hash map hits     %d\n",stat_get(CNT_HASHMAP_HITS));
	fprintf(fd,"Hash map miss     %d\n",stat_get(CNT_HASHMAP_MISS));
	fprintf(fd,"Mem alloc         %d\n",stat_get(CNT_MEM_ALLOC));
	fprintf(fd,"Mem free          %d\n",stat_get(CNT_MEM_FREE));
	fprintf(fd,"\n");
	fprintf(fd,"Message queue     %d\n",logqueue->entry_cnt);
	fprintf(fd,"Message error     %d\n",stat_get(CNT_LOG_TYPE_ERROR));
	fprintf(fd,"Message alert     %d\n",stat_get(CNT_LOG_TYPE_ALERT));
	fprintf(fd,"Message info      %d\n",stat_get(CNT_LOG_TYPE_INFO));
	fprintf(fd,"Message fatal     %d\n",stat_get(CNT_LOG_TYPE_FATAL));
	fprintf(fd,"Message warn      %d\n",stat_get(CNT_LOG_TYPE_WARN));
	fprintf(fd,"\n");
	fprintf(fd,"Queue push        %d\n",stat_get(CNT_QUEUE_PUSH));
	fprintf(fd,"Queue pop         %d\n",stat_get(CNT_QUEUE_POP));
	fprintf(fd,"\n");
	fprintf(fd,"HTTP processed    %d\n",stat_get(CNT_HTTP_PROCESSED));
	fprintf(fd,"HTTP packets      %d\n",stat_get(CNT_HTTP_ALL));
	fprintf(fd,"\n");
	fprintf(fd,"Average bytes     %3.2f (%s)\n",rate,rname );
	fprintf(fd,"Average packets   %d (p/s)\n",stat_get(CNT_IP) / secondsrunning );
	fprintf(fd,"Average sessions  %d (p/s)\n",stat_get(CNT_SESSION_TOTAL) / secondsrunning );
	fprintf(fd,"Seconds run       %d (versus %d packets)\n", secondsrunning,stat_get(CNT_IP));
	fprintf(fd,"\n");
	fprintf(fd,"Pkts not matching session %d (dropped)\n",stat_get(CNT_SESSION_MISS));
	fprintf(fd,"--------------------------------------\n");

        #dump_signature_index(SIG_INDEX_TCP_DST);
        #dump_signature_index(SIG_INDEX_TCP_SRC);
}

