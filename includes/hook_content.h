#ifndef __HOOK_CONTENT_H
#define __HOOK_CONTENT_H

struct signature;

#define CONTENT_TEST_FOUND     1
#define CONTENT_TEST_NOT_FOUND 2

struct content {
	struct payload_opts popts;
        char *replace;
};

int hook_content(struct signature *sig,struct traffic *traffic);
int hook_content_options(char *key, char *val, struct signature *sig);

#endif
