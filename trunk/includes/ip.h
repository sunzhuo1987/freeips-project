#ifndef __IP_H
#define __IP_H

#define FRAG_TIMEOUT 30
#define MAX_DATAGRAM_SIZE 65535

struct ip_frag {
	u_short offset;
	u_short ip_len;
	u_short mf;
	u_short id;
	struct timeval time;
	struct traffic* traffic;
};

int push_ip_frag(struct traffic* frag);
int assemble_ip_frags(struct ip_frag* frag);
void free_frags(struct ip_frag* frag);
int cmp_frag(struct ip_frag* fraga, struct ip_frag* fragb);
void cleaner(void *ptr);
void remove_frag_entry(struct list_entry* entry);

#endif
