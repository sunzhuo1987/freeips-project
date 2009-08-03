#ifndef __HOOK_ICMP_ITYPE_H
#define __HOOK_ICMP_ITYPE_H


int hook_icmp_itype(struct signature *sig,struct traffic *traffic);
int hook_icmp_itype_options(char *key, char *val, struct signature *sig);


#endif
