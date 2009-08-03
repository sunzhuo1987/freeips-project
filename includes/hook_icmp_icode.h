#ifndef __HOOK_ICMP_ICODE_H
#define __HOOK_ICMP_ICODE_H


int hook_icmp_icode(struct signature *sig,struct traffic *traffic);
int hook_icmp_icode_options(char *key, char *val, struct signature *sig);


#endif
