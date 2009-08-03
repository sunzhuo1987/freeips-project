#ifndef __HOOK_TCP_FLAGS_H
#define __HOOK_TCP_FLAGS_H

#define TCPFLAGS_ANYO  1 // Any plus others
#define TCPFLAGS_ANY   2 // ANY
#define TCPFLAGS_NOT   3 // Match if not set

typedef struct tcp_flags {
	int flags;
	int options;
} TcpFlags;

int hook_tcp_flags(struct signature *sig,struct traffic *traffic);
int hook_tcp_flags_options(char *key, char *val, struct signature *sig);
int hook_tcp_flags_parse(char *flagstr,TcpFlags *tflags);


#endif
