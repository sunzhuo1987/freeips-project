#ifndef __HOOK_IP_TOS_H
#define __HOOK_IP_TOS_H


int hook_ip_tos(struct signature *sig,struct traffic *traffic);
int hook_ip_tos_options(char *key, char *val, struct signature *sig);


#endif
