#ifndef __HOOK_TCP_SEQ_H
#define __HOOK_TCP_SEQ_H


int hook_tcp_seq(struct signature *sig,struct traffic *traffic);
int hook_tcp_seq_options(char *key, char *val, struct signature *sig);


#endif
