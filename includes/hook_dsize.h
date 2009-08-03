#ifndef __HOOK_DSIZE_H
#define __HOOK_DSIZE_H

#define DSIZE_BIGGER  1
#define DSIZE_SMALLER  2
#define DSIZE_EQUAL    3

int hook_dsize(struct signature *sig,struct traffic *traffic);
int hook_dsize_options(char *key, char *val, struct signature *sig);


#endif
