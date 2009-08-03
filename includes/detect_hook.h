#ifndef __DETECT_HOOK_H
#define __DETECT_HOOK_H

#include <signature.h>
#include <detect_hook.h>
#include <pcap_pcre.h>
#include <stats.h>
#include <list.h>
#include <memory.h>
#include <mypcap.h>
#include <log.h>
#include <ip4.h>
#include <analyze.h>
#include <tcp.h>
#include <myhash.h>
#include <control.h>


#define DETECT_HOOK_MAX_CNT 64
#define DETECT_HOOK_NAME_SIZE 20

#define HOOK_PRIO_LOW 1
#define HOOK_PRIO_NORMAL 2
#define HOOK_PRIO_HIGH 3

struct signature;

typedef struct detect_hook {
        char name[DETECT_HOOK_NAME_SIZE];
        int options;
	int prio;
        int (*hook)(struct signature *sig, struct traffic *traffic);
	int (*hook_parse_option)(char *key, char *val, struct signature *sig);
} DetectHook;

struct payload_opts {
        int offset;
        int depth;
        int within;
        int distance;
        int nocase;
        int isdataat;
        int test;
        char *matchstr;
        int matchstr_size;
};


DetectHook * detect_hook_get(char *name);
DetectHook * detect_hook_register(char *name, int options, int priority, int(*hook)(struct signature *sig,struct traffic *traffic), int (*hook_parse_option)(char *key, char *val, struct signature *sig));
void detect_hook_init();
DetectHook * detect_hook_link(struct signature *sig, char *name);
void sort_hooks(struct signature *sig);

#endif


