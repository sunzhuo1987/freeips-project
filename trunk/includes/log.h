#ifndef __LOG_H
#define __LOG_H

struct signature;

#define LOG_FILE_NAME_CNT 8

struct logfilestruct {
	FILE *fd;
	char name[CONFIG_MAX_CHAR];
	int enable;
};

struct logfilestruct logoutputs[LOG_FILE_NAME_CNT];

#define LOG_TYPE_ERROR 0
#define LOG_TYPE_ALERT 1
#define LOG_TYPE_FATAL 2
#define LOG_TYPE_INFO  3
#define LOG_TYPE_WARN  4
#define LOG_TYPE_VERBOSE  5
#define LOG_TYPE_ALL  6
#define LOG_TYPE_OTHER  7
#define LOG_MAX_SIZE   1024
#define LOG_MAX_FILENAME	128

#define VERBOSE_LEVEL1 1
#define VERBOSE_LEVEL2 2
#define VERBOSE_LEVEL3 3

typedef struct message {
        char msg[LOG_MAX_SIZE];
        va_list ap;
	struct traffic *traffic;
        int type;
} Message;

void push_message(int type, char *string, va_list ap,struct traffic *data);
int pop_message();
void pop_all_messages();
void log_info(char *string, ...); 
void do_log(Message *msg);
void log_error(char *string, ...); 
void log_alert(struct traffic *traf, char *string, ...); 
void alert(struct signature* sig, struct traffic* traffic );
void log_warn(char *string, ...);
void fatal_error(char *string, ...);
void log_verbose(int level, char *string, ...);

void logoutputs_init();
void logoutputs_close();

#endif
