#ifndef __HOOK_LATENCY_H
#define __HOOK_LATENCY_H


int hook_latency(struct signature *sig,struct traffic *traffic);
int hook_latency_options(char *key, char *val, struct signature *sig);

#endif
