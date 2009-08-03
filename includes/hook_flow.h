#ifndef __HOOK_FLOW_H
#define __HOOK_FLOW_H

struct signature;

int hook_flow(struct signature *sig,struct traffic *traffic);
int hook_flow_options(char *key, char *val, struct signature *sig);

#endif
