#ifndef __IP3_H
#define __IP3_H

#define FRAG_TIMEOUT 30
#define MAX_DATAGRAM_SIZE 65535
#define MAX_ID_VALUE 65535
#define CLEANER_TIMEOUT 30

struct ip_frag {
	u_short offset;
	u_short ip_len;
	u_short mf;
	u_short id;
	struct traffic* traffic;
};

struct frag_queue {
	int collected;
	int required;
	int fragcnt;
	int ip_hl;
	int id;
	struct timeval time;
	struct linked_list *list;
};


int push_ip_frag(struct traffic* frag);
int assemble_ip_frags(struct frag_queue* fragq);
int cmp_frag(struct ip_frag* fraga, struct ip_frag* fragb);
void frag_cleaner();
void free_frag_queue(struct frag_queue* fragq, int dispatch);
void dump_frag_queues ();

#endif
