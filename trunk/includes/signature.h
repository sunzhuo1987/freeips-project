#ifndef __SIGNATURE_H
#define __SIGNATURE_H

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


#define MAX_SIG_CNT  8192
#define MAX_SIG_LINE 4096
#define MAX_PATH     1024
#define SIG_ARRAY_SIZE 256

#define P_UNKNOWN	0
#define P_ICMP		1
#define P_TCP		6
#define P_UDP		17

#define CON_STATE_ESTABLISHED     1
#define CON_STATE_NOT_ESTABLISHED 2
#define CON_STATE_STATELESS       3

#define MATCHSTR_TYPE_ASCII 1
#define MATCHSTR_TYPE_HEX   2

#define DIRECTION_TO_SERVER 1
#define DIRECTION_TO_CLIENT 2

#define MAX_SIG_PART_SIZE 1024

#define HEX_VAL_BRACKET 0x28
#define HEX_VAL_COL     0x3b
#define HEX_VAL_SPACE   0x20
#define HEX_VAL_BSLASH  0x5c
#define HEX_VAL_FSLASH  0x2f
#define HEX_VAL_QUOTES  0x22
#define HEX_VAL_PIPE    0x7c
#define HEX_VAL_POUND   0x23

#define SIG_ACTION_DROP 1
#define SIG_ACTION_PASS 2
#define SIG_MAX_CONTENT 16
#define SIG_MAX_BYTETEST 10

#define SIG_INDEX_SIZE  65535 + 1

struct linked_list *siglist;
struct linked_list *sigarray[SIG_ARRAY_SIZE];

struct signature *SIG_INDEX_TCP_SRC[SIG_INDEX_SIZE];
struct signature *SIG_INDEX_TCP_DST[SIG_INDEX_SIZE];
struct signature *SIG_INDEX_UDP_SRC[SIG_INDEX_SIZE];
struct signature *SIG_INDEX_UDP_DST[SIG_INDEX_SIZE];
struct signature *SIG_INDEXES_SRC[SIG_ARRAY_SIZE];
struct signature *SIG_INDEXES_DST[SIG_ARRAY_SIZE];


// Below is needed to support 
// int options such as !, - and :

struct intvalue {
	int start;   // e.g. 80 , 80
	int stop;    // e.g. 80 , 100
	int range;   // 0
	int neg;     // !
};

//
// It would be great to make this dynamic instead
// of one huge struct with unused references
//

struct signature {
        char *msg;
        struct content *content[SIG_MAX_CONTENT];
	int content_idx;

        struct uricontent *uricontent[SIG_MAX_CONTENT];
	int uricontent_idx;

        struct byte_test *byte_test[SIG_MAX_BYTETEST];
	int byte_test_idx;
	struct payload_opts *popts;

        char *classtype;
        char *reference;
        int proto;
        int sid;
        int rev;
        int direction;
        int connection_state;
        struct intvalue srcport;
        struct intvalue dstport;
        int type;

	// TCP specific
	u_int32_t seq;
	u_int32_t ack;

	// ICMP specific
	int icmp_type;
	int icmp_code;

	// Rule action
	int action;

	// IP signature options
	int ip_id;
	int ip_ttl;
	int ip_tos;
	int ip_proto;

	// TCP
	TcpFlags tflags;
	TcpFlags tflags_ignore;

	// Regular expressions
        PcreRegex *regex;

	// Dsize
	int dsize_type;
	int dsize;

	// Latency
	int latency;

	// Detection hook
        DetectHook *DetectHooks[DETECT_HOOK_MAX_CNT];

	// For linking
	struct signature *next;

	// For sorting
        int hits;
	int matches;

};


int load_signatures(char *sigfile);
struct signature* match_signature(struct traffic* traffic);
int sigparse (char *string,struct signature *sig);
int parseOption(char *name, char *val, struct signature *sig);
char * cleanup_char(char *word);
int sigparse_defaults(char *string, struct signature *sig);
void dumpSignature(struct signature *sig);
int validateSignature(struct signature *sig);
int parseport(char *token, struct intvalue *port);
struct signature * getSignatureStruct();
int read_sig_dir(char *dir);
struct content* get_last_content(struct signature *sig);
struct uricontent* get_last_uricontent(struct signature *sig);
int freeSignatures();
struct signature* indexed_match_signature(struct traffic* traffic);
int make_signature_indexes (int proto, struct signature* src_ptr[], struct signature* dst_ptr[]);

int init_signature_indexes();
void dump_signature_index(struct signature* src_ptr[]);
int make_signature_index_conkey (int port, struct signature* src_ptr[]);



#endif 
