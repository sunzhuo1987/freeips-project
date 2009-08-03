#ifndef __TIMER_H
#define __TIMER_H

#define MAX_TIMER_COUNT 32
#define MAX_TIMER_NAME  32 

typedef struct timer_struct {
        int count;
        int interval;
	void(*timerfunc)(void *arg);
	void *timerarg;
        struct timeval lasttime;
	char name[MAX_TIMER_NAME];
} TimerStruct;

int timer_init();
int timer_register_function(int interval,char * name, void(*timerfunc)(void *arg), void *timerarg);
void timer_run() ;
TimerStruct * timer_get_struct();

#endif
