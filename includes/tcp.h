#ifndef __TCP_H
#define __TCP_H

#define TCP_MAX_BUFFER_SIZE 4096
#define TCP_MAX_SESSIONS 20000
#define TCP_MAX_STREAM_SIZE 4096

typedef struct tcp_session {
	struct  in_addr ip_src;
	struct  in_addr ip_dst;
	u_short th_sport;
	u_short th_dport;	

	// Stream //

	char           *stream;
	char           *stream_size;
	struct traffic *stream_pkts;

	struct timeval starttime;
	struct timeval seentime;
	struct p0f_response *p0f;
	int latency;
	int timeout;
	int state;

} TcpSession;

int tcp_stream_add(struct traffic *traffic);
int tcp_stream_del(struct traffic *traffic);
void tcp_stream_dump(TcpSession *tsess, FILE *fd); 
int tcp_stream_check(struct traffic *traffic);
void tcp_clean_sessions();
int tcp_stream_init();
void tcp_dump_sessions(FILE *fd);
int compare_session(void *one, void *two);
int tcp_check_packet(struct traffic *traf);



// 
// The states
//

#define TCPS_NEW               -1       /* new */
#define TCPS_CLOSED             0       /* closed */
#define TCPS_LISTEN             1       /* listening for connection */
#define TCPS_SYN_SENT           2       /* active, have sent syn */
#define TCPS_SYN_RECEIVED       3       /* have sent and received syn */
/* states < TCPS_ESTABLISHED are those where connections not established */
#define TCPS_ESTABLISHED        4       /* established */
#define TCPS_CLOSE_WAIT         5       /* rcvd fin, waiting for close */
/* states > TCPS_CLOSE_WAIT are those where user has closed */
#define TCPS_FIN_WAIT_1         6       /* have closed, sent fin */
#define TCPS_CLOSING            7       /* closed xchd FIN; await FIN ACK */
#define TCPS_LAST_ACK           8       /* had fin and close; await FIN ACK */
/* states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN */
#define TCPS_FIN_WAIT_2         9       /* have closed, fin is acked */
#define TCPS_TIME_WAIT          10      /* in 2*msl quiet wait after close */

#define TCPS_TIMEOUT_INITIAL     10   //TODO: review
#define TCPS_TIMEOUT_ESTABLISHED 60   //TODO: review
#define TCPS_TIMEOUT_CONNECTION  300 //TODO: review
#define TCPS_TIMEOUT_CLOSING     30  //TODO: review

#endif
