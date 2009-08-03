#ifndef __HOOK_IP_TTL_H
#define __HOOK_IP_TTL_H


int hook_ip_ttl(struct signature *sig,struct traffic *traffic);
int hook_ip_ttl_options(char *key, char *val, struct signature *sig);


#endif
