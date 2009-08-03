#ifndef __HOOK_URICONTENT_H
#define __HOOK_URICONTENT_H

#define URI_REQUEST_GET 1
#define URI_REQUEST_POST 2
#define URI_REQUEST_CONNECT 3
#define URI_REQUEST_HEAD 4

#define URICONTENT_TEST_FOUND     1
#define URICONTENT_TEST_NOT_FOUND 2


struct uricontent {
	struct payload_opts popts;
	int urilen;
};

int hook_uricontent(struct signature *sig,struct traffic *traffic);
int hook_uricontent_options(char *key, char *val, struct signature *sig);
int hook_uricontent_compare(struct signature *sig, char *uri);


#endif
