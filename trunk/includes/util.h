#ifndef __UTIL_H
#define __UTIL_H

#ifdef WITH_DEBUG
#define DEBUG(a,b) fprintf(a,b)
#define DEBUGF(a,b) printf(a,b)
#else
#define DEBUG(a,b) 
#define DEBUGF(a,b)
#endif

// Set the maximum amount of payloads to be stored in memory.
// this allows us to restrict memory usage. Set to the highest
// value possible in order to prevent a performance decrease.
//
// In case you want a maximum of 512MB then:
//
// 512MB = 536870912 bytes. If your MTU is 1500 then each payload 
// element will be 1500 bytes max. So 536870912 / 1500 = 357913
//

#define MAX_LIST_SIZE 357913
#define VERSION  "0.1"
#define PROGNAME "FreeIPS"

#define TYPE_URICONTENT 1
#define TYPE_CONTENT 2

//
// External includes
//

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <dirent.h>
#include <unistd.h>
#include <wctype.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <pcap.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcre.h>

#include <libxml2/libxml/xmlmemory.h>
#include <libxml2/libxml/parser.h>


//
// Internal includes
//


#include <config.h>
#include <traffic.h>
#include <hook_tcp_flags.h>
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
#include <divert.h>
#include <timer.h>
#include <main.h>

#include <hook_flow.h>
#include <hook_content.h>
#include <hook_uricontent.h>
#include <hook_tcp_seq.h>
#include <hook_tcp_ack.h>
#include <hook_ip_id.h>
#include <hook_ip_ttl.h>
#include <hook_ip_tos.h>
#include <hook_ip_proto.h>
#include <hook_p0f.h>
#include <hook_dsize.h>
#include <hook_socom.h>
#include <hook_latency.h>
#include <hook_icmp_itype.h>
#include <hook_icmp_icode.h>


int compare(struct signature *sig, struct traffic *traf);
int drop_privileges(char *user);
void fork_to_background();
void dumphex(void *data, int size);
char hex2char (char *hex);
void usage();
char * cleanup_char(char *word);
int mymemcmp(const void *str1, const void *str2,int size, int nocase);
void sigquit_handler ();
void sighup_handler ();
int is_file(char *file);
int is_dir(char *file);
int payload_compare(struct signature *sig, char *data, int psize,int ptype);
int base64_encode(char *input,char *output) ;



#endif
#include <sys/wait.h>
