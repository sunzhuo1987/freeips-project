#ifndef __CONFIG_H
#define __CONFIG_H

//
// Move to config.h
//

#define CONFIG_MAX_CHAR 128

int CONFIG_LOG_SYSLOG;		// default 0
int CONFIG_LOG_PACKET;		// default 0
int CONFIG_LOG_VERBOSE;		// default 0
int CONFIG_LOG_STDOUT;		// default 1
int CONFIG_LOG_PCAP;		// default 0
int CONFIG_SHOW_TRAFFIC;	// default 0

char CONFIG_SIGFILE[CONFIG_MAX_CHAR];		// default "config/anti/" 
char CONFIG_LOGDIR[CONFIG_MAX_CHAR];		// default "logdir/" 
char CONFIG_PCAP_FILTER[CONFIG_MAX_CHAR];	// default "ip" 
char CONFIG_PCAP_DEV[CONFIG_MAX_CHAR];   	// default "0" 

int CONFIG_PACKET_BL_BUFFER;		   	// default 1000;

int CONFIG_SIG_STRICT_LOAD;

// Security related
int  CONFIG_DROP_PRIVILEGES;			// default 1
int  CONFIG_CHROOT_ENABLE;			// default 0
char CONFIG_USER[CONFIG_MAX_CHAR];		// default "0"
char CONFIG_CHROOT_DIR[CONFIG_MAX_CHAR];	// default "0"

// Divert related
int CONFIG_TCP_STRICT;		// default 0
int CONFIG_DIVERT_ENABLE;	// default 0
int CONFIG_DIVERT_PORT;		// default 2222

// Control related
int CONFIG_CONTROL_HTTP_PORT;			// default 3491
int CONFIG_CONTROL_HTTP_ENABLE; 		// default 1
char CONFIG_CONTROL_HTTP_FOOTER[CONFIG_MAX_CHAR]; 	// support/html/footer.html
char CONFIG_CONTROL_HTTP_HEADER[CONFIG_MAX_CHAR]; 	// support/html/header.html
char CONFIG_CONTROL_HTTP_USER[CONFIG_MAX_CHAR]; 	// user
char CONFIG_CONTROL_HTTP_PASS[CONFIG_MAX_CHAR]; 	// letmein
char CONFIG_CONTROL_HTTP_AUTH_CLEAR[CONFIG_MAX_CHAR]; 	// user:letmein
char CONFIG_CONTROL_HTTP_AUTH[CONFIG_MAX_CHAR]; 	// base64(user:letmein)
unsigned long CONFIG_CONTROL_HTTP_IP;			// INADDR_ANY


// Timer parameters

int CONFIG_TIMER_STATS;			// default 600
int CONFIG_TIMER_TCP_CLEANER;		// default 3600
int CONFIG_TIMER_IPFRAG_CLEANER;	// default 10
int CONFIG_TIMER_CLEANUPPBUFFER;	// default 10

// Functions;

int init_config();
void read_config(char *docname);
void parse_logging (xmlDocPtr doc, xmlNodePtr cur);
void parse_general (xmlDocPtr doc, xmlNodePtr cur);
void dump_config();

#define MAX_CONFIG_LINE 1024


#endif
