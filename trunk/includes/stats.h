#ifndef __STATS_H
#define __STATS_H

#define MAX_PORT 65535
#define MAX_CNTS 100
#define STATS_INTERVAL 600

//TODO --> array of structs, with description per struct?

unsigned long stat_cnts[MAX_CNTS];

#define CNT_TCP                 1
#define CNT_UDP                 2
#define CNT_ICMP                3

#define CNT_IP			10
#define CNT_IP_ERR		11
#define CNT_IP_DATA_SIZE	12
#define CNT_IP_QUEUE		13	

#define CNT_MEM_ALLOC		20
#define CNT_MEM_FREE		21

#define CNT_HASHMAP_HITS	30
#define CNT_HASHMAP_MISS	31
#define CNT_HASHMAP_COLL	32

#define CNT_SIG_MATCH		40
#define CNT_SIG_LOADED		41

#define CNT_IP_FRAG		51	
#define CNT_IP_FRAG_TMOUT	52	
#define CNT_IP_FRAG_QUEUE	53	

#define CNT_LOG_TYPE_ERROR      60
#define CNT_LOG_TYPE_ALERT      61
#define CNT_LOG_TYPE_FATAL      62
#define CNT_LOG_TYPE_INFO       63
#define CNT_LOG_TYPE_WARN       64
#define CNT_LOG_TYPE_VERBOSE    65

#define CNT_SESSION_MISS	80
#define CNT_SESSION_TOTAL	81

#define CNT_QUEUE_PUSH		90
#define CNT_QUEUE_POP		91




void stats_increase_cnt(int id,int val);
void stats_decrease_cnt(int id,int val);

void stats_show_cnt_line();
void stats_dump_cnts();
void stats_init();
void dump_stats(FILE *fd);

#endif

