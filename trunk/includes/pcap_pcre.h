#ifndef __PCAP_PCRE_H
#define __PCAP_PCRE_H

struct signature;

#define PCRE_TEST_FOUND     1
#define PCRE_TEST_NOT_FOUND 2

typedef struct pce_regex {
        pcre *matchstr;
        int compile_options;
	int test;
} PcreRegex;

char * prepare_pcre_string(PcreRegex *regex, char *word);
int compile_pcre (PcreRegex *regex, char *string);
int match_pcre (PcreRegex *regex, char *data, int dsize);
int hook_pcre(struct signature *sig,struct traffic *traffic);
int hook_pcre_options(char *key, char *val, struct signature *sig);

#endif
