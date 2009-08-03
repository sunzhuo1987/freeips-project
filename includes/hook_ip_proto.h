#ifndef __HOOK_IP_PROTO_H
#define __HOOK_IP_PROTO_H

int hook_ip_proto(struct signature *sig,struct traffic *traffic);
int hook_ip_proto_options(char *key, char *val, struct signature *sig);

#endif
