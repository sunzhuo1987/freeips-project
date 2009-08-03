//
// Copyright (c) 2006-2009 Niels Heinen
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#include <util.h>

TimerStruct *timers[MAX_TIMER_COUNT];
int timers_initialized = 0;

//
// Initialize the timer array
//

int timer_init() {
	int i;
	for(i=0;i<MAX_TIMER_COUNT;i++)  {
		timers[i] = NULL;
	}
	timers_initialized=1;
	return 0;
}

//
// Register a function to be executed every X seconds
// TODO: make timer functions return success ??
//

int timer_register_function(int interval,char * name, void(*timerfunc)(void *arg), void *timerarg) {

	// Get the struct
	TimerStruct *tstruct = timer_get_struct();
	int i;

	tstruct->count     = 0;
	tstruct->interval  = interval;
	tstruct->timerfunc = timerfunc;
	tstruct->timerarg  = timerarg;

	// Should it be longer then it just messes up the debugging
	// display. Sane names aren't longer then MAX_TIMER_NAME

	strncpy(tstruct->name,name,MAX_TIMER_NAME);

	// Set the time
        gettimeofday(&tstruct->lasttime, NULL );

	for(i=0;i<MAX_TIMER_COUNT;i++)  {
		if(timers[i] == NULL) {
			timers[i] = tstruct;
			break;
		}
	}

	// Check if we reached the max
	if(i == MAX_TIMER_COUNT) {
		fatal_error("MAX_TIMER_COUNT reached!");
		return 1;
	}
	return 0;
}

//
// Loop the timer array and execute timer functions
// when needed
//

void timer_run() {

	int i;
	struct timeval timenow;
        gettimeofday(&timenow, NULL );

	// Protection against self..
	if(timers_initialized != 1)  {
		fatal_error("Whoa, timers array is not initialized");
	}

	// Iterate the timer list
	for(i=0;i<MAX_TIMER_COUNT;i++)  {
		// NULL means end of list
		if(timers[i] == NULL)
			break;

		// Has it been "interval" seconds ago?
		if((timenow.tv_sec - timers[i]->lasttime.tv_sec) > timers[i]->interval) {
			// TODO: add arg? ret val?
			//printf("Executing timer: %s\n",timers[i]->name);
			timers[i]->timerfunc(timers[i]->timerarg);
			timers[i]->count++;

			// Reset the time
			gettimeofday(&timers[i]->lasttime,NULL);
		}
	}
}

//
// Return an emprty timer struct
//

TimerStruct * timer_get_struct() {
	TimerStruct * tstruct = allocMem(sizeof(TimerStruct));
	if(tstruct == NULL) {
		fatal_error("Unable to allocate memory for timer struct");
	}

	memset(tstruct,0,sizeof(TimerStruct));
	return tstruct;
}


