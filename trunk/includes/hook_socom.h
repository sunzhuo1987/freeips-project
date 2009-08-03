#ifndef __HOOK_SOCOM_H
#define __HOOK_SOCOM_H

int hook_socom(struct signature *sig,struct traffic *traffic);
int hook_socom_options(char *key, char *val, struct signature *sig);


#endif
