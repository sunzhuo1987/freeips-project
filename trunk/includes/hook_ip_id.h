#ifndef __HOOK_IP_ID_H
#define __HOOK_IP_ID_H


int hook_ip_id(struct signature *sig,struct traffic *traffic);
int hook_ip_id_options(char *key, char *val, struct signature *sig);


#endif
