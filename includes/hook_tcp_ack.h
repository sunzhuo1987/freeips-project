#ifndef __HOOK_TCP_ACK_H
#define __HOOK_TCP_ACK_H


int hook_tcp_ack(struct signature *sig,struct traffic *traffic);
int hook_tcp_ack_options(char *key, char *val, struct signature *sig);


#endif
