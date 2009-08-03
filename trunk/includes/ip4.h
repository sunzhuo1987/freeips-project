#ifndef __IP3_H
#define __IP3_H

#define FRAG_TIMEOUT 30
#define MAX_DATAGRAM_SIZE 65535 + 1
#define MAX_ID_VALUE 65535 + 1
#define CLEANER_TIMEOUT 30

typedef struct ip_frag {
	u_short offset;
	u_short ip_len;
	u_short mf;
	u_short id;
	struct traffic* traffic;
} IPfrag;

typedef struct frag_queue {
	int collected;
	int required;
	int fragcnt;
	int id;
	int ip_hl;
	struct timeval time;
	struct linked_list *list;
	struct frag_queue* next;
	struct frag_queue* prev;
} Fqueue;


int push_ip_frag(struct traffic* frag);
int assemble_ip_frags(Fqueue* fragq);
int cmp_frag(IPfrag* fraga, IPfrag* fragb);
void ip_frag_cleaner();
void free_frag_queue(Fqueue* fragq, int dispatch);
void dump_frag_queues ();
struct frag_queue* new_queue();

#endif
