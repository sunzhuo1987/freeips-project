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


#include <list.h>
#include <stdio.h>
#include <unistd.h>
#include <util.h>
#include <memory.h>

#ifdef WITH_THREAD
#include <pthread.h>
#endif

// The list starting point
struct linked_list *LIST_CHAIN_START = NULL;
struct linked_list *LIST_CHAIN_STOP  = NULL;
int lock = 0;

// Create a new list entry
struct list_entry * newListEntry() {
	struct list_entry *new = (struct list_entry*) allocMem( sizeof(struct list_entry) );
	new->next = NULL;
	new->prev = NULL;
	new->data = NULL;
	new->hits = 0;
	new->popped = 0;
	return new;
}

// Create a new list
struct linked_list * newList() {
	struct linked_list     *new = (struct linked_list*)     allocMem( sizeof(struct linked_list) );
	struct session_handler *ses = (struct session_handler*) allocMem( sizeof(struct session_handler) );

	DEBUG(stdout,"New list newList() called\n");
	new->next  = NULL;
	new->prev  = NULL;
	new->start = NULL;
	new->stop  = NULL;
	new->ptr   = NULL;

	new->entry_max = 0;
	new->entry_cnt = 0;

	new->backlog_max = CONFIG_PACKET_BL_BUFFER;
	new->backlog_cnt = 0;

	ses->destructor = NULL;
	ses->iterator   = NULL;

	new->session_handler = ses;
	return new;
}

// Create a new list
struct linked_list * newLiteList() {
        struct linked_list     *new = (struct linked_list*)     allocMem( sizeof(struct linked_list) );

        DEBUG(stdout,"New list newList() called\n");
        new->next  = NULL;
        new->prev  = NULL;
        new->start = NULL;
        new->stop  = NULL;
        new->ptr   = NULL;

	new->backlog_max = CONFIG_PACKET_BL_BUFFER;
	new->backlog_cnt = 0;

        new->entry_max = 0;
        new->entry_cnt = 0;

        new->session_handler = NULL;
        return new;
}


// Set the maximum element size
void setListSize(int maxsize, struct linked_list *list) {
	list->entry_max = maxsize;
	return;
}

struct linked_list * getNewList() {

	// Prepare the new entry. Allocate memory, set next to NULL Then
	// find a place to put it.
	struct linked_list *list = newList();

	if(LIST_CHAIN_START == NULL) {
		list->id = 1;
		LIST_CHAIN_START = list;
		LIST_CHAIN_STOP  = list;
		DEBUG(stdout,"List chain is initialized!\n");
	} else {
		DEBUG(stdout,"Added new list to chain!\n");
		list->id = LIST_CHAIN_STOP->id + 1;
		LIST_CHAIN_STOP->next = list;
		LIST_CHAIN_STOP       = list;
	}

	return list;
}


int pushListEntry (void *data, struct linked_list* list) {

	// Prepare the new entry. Allocate memory, set next to NULL Then
	// find a place to put it.
	struct list_entry *new = newListEntry();
	new->data = data;

	if(list->entry_max != 0) {
		while(list->entry_cnt > list->entry_max) {
			DEBUG(stdout, "List is full.. waiting before pushing new entry\n");
			sleep(1);
		}
	}

	list->entry_cnt++;

	lockList();
	// Check if this is the first entry
	if(list->start == NULL) {
		DEBUG(stdout, "Started new list !\n");
		list->start = new;
		list->stop  = new;
		new->id    = 1;
		unlockList();
		return 1;
	}

	// Set the ID..
	new->id = list->start->id + 1;

	// First append the new list entry. Then point the new entry->prev
	// to the last one. Finally update te list_stop pointer.

	new->next = list->start;
	list->start->prev = new;
	new->prev = NULL;
	list->start = new;

	DEBUGF("Added new list entry with ID: %d\n", new->id);
	unlockList();
	return new->id;
}

int pushListEntryBack (void *data, struct linked_list* list) {

        // Prepare the new entry. Allocate memory, set next to NULL Then
        // find a place to put it.
        struct list_entry *new = newListEntry();
        new->data = data;

        if(list->entry_max != 0) {
                while(list->entry_cnt > list->entry_max) {
                        DEBUG(stdout, "List is full.. waiting before pushing new entry\n");
                        sleep(1);
                }
        }

        // If the list is locked: wait
	lockList();

        // Check if this is the first entry
        if(list->start == NULL) {
                DEBUG(stdout, "Started new list !\n");
                list->start = new;
                list->stop  = new;
                new->id    = 1;
		unlockList();
                return 1;
        }

        // Set the ID..
        new->id = list->stop->id + 1;

        // First append the new list entry. Then point the new entry->prev
        // to the last one. Finally update te list_stop pointer.

        list->stop->next = new;
        new->prev        = list->stop;
        list->stop       = new;

	unlockList();
        DEBUGF("Added new list entry with ID: %d\n", new->id);
        return new->id;
}


//
// pop list entries. There is a potential problem here because the
// returned data must be free()'d by the functions caller.. something
// thats easy to forget..
//
// LIFO because the list grows -->
//

void * popListEntry(struct linked_list* list) {

	struct list_entry* entry;
	void *ret;

	lockList();

	// Empty list ?
	if(list->stop == NULL) {
		//DEBUG(stderr, "ERROR: popListEntry called on empty list!\n");
		unlockList();
		return NULL;
	}


	// No more entries ?
	entry = list->stop;
	if(list->stop->prev == NULL) {
		list->stop  = NULL;
		list->start = NULL;
	} else {
		list->stop = list->stop->prev;
		// Hold the line ;p
		list->stop->next = NULL;
	}

	ret = entry->data;
	list->entry_cnt--;
	freeListEntry(entry,list);

	unlockList();
	return ret;
}


void * popListEntryPtr(struct linked_list* list) {

        lockList();

        // Empty list ?   
        if(list->stop == NULL) {
                //DEBUG(stderr, "ERROR: popListEntry called on empty list!\n");
                unlockList();
                return NULL;
        }

	if(list->ptr == NULL) {
		list->ptr = list->stop;
	} else if(list->ptr->prev == NULL) {
		unlockList();
		return NULL;
	} else {
		list->ptr = list->ptr->prev;
	}

	list->ptr->popped++;
	list->backlog_cnt++;
	unlockList();
	return list->ptr->data;

}

//
// Below function is to cleanup list entries from memory when the backlog
// becomes too big. Backlog = list entries which have been analyzed already
// but kept in memory for further analysis
//

void   cleanListBacklog(void *arg) {
	int cnt = 0;
	struct traffic* traffic;

	struct linked_list *list = (struct linked_list *)arg;

	//printf("cleanListBacklog called !\n");
	//printf("list->backlog_cnt %d > list->backlog_max %d\n",list->backlog_cnt,list->backlog_max);
	while(list->backlog_cnt > list->backlog_max) {
		traffic = popListEntry(list);
		if(traffic == NULL) { 
			printf("Wowo traffic = NULL?!\n");
			return;
		}

		traffic_free(traffic);
		cnt++;
		list->backlog_cnt--;
	}

	//printf("Cleaned %d entries\n",cnt);
	return;
}


//
// Shift entries... for FIFO
//

void * shiftListEntry(struct linked_list* list) {

        struct list_entry* entry;
        void *ret;
	

	lockList();
        // Empty list ?
        if(list->start == NULL) {
                //DEBUG(stderr, "ERROR: shiftListEntry called on empty list!\n");
		unlockList();
                return NULL;
        }

        entry = list->start;

	// Last entry or not
	if(list->start->next == NULL) {
                list->stop  = NULL;
                list->start = NULL;
        } else {
		printf("Setting list->start->next\n");
                list->start = list->start->next;
                list->start->prev = NULL;
        }

	DEBUGF("Returning data ID: %d\n",entry->id);
        ret = entry->data;

        freeListEntry(entry,list);
	list->entry_cnt--;
	unlockList();
        return ret;
}

void removeEntry(struct list_entry* entry,struct linked_list* list) {
	struct list_entry* prev = entry->prev;
	struct list_entry* next = entry->next;

	freeMem(entry);

	if(prev == NULL) { 
		list->start = next;
	} else {
		prev->next = next;
	}
	
	if(next == NULL) {
		list->stop = prev;
	} else {
		next->prev = prev;
	}
}



//
// Free List entry.. free the memory after calling the list
// destructor on (if any).
//

void freeListEntry (struct list_entry* entry,struct linked_list* list) {

	// Look for the session handler
	if(list->session_handler != NULL) {
	
		//Now look for a destructor
		if(list->session_handler->destructor != NULL) {
			DEBUG(stdout, "Calling destructor..\n");
			(*list->session_handler->destructor)(entry->data,entry);
		}
	}

	// Calling freeMem(entry)
	freeMem(entry);
}

//
// Register destructor. This function, with a prototype similar to
// function(void *data, struct list_entry *entry) can do some finalizing
// on the information in *data. For example, you may need to free some
// pointers or close filedescriptions/socket etc etc
//

void registerListDestructor (int (*callback)(void *data,struct list_entry *entry),struct linked_list* list) {
	if(list->session_handler == NULL) {
		DEBUG(stderr, "Error: no session_handler (destructor)\n");
		return;
	}

	// Exchange 
	list->session_handler->destructor = callback;
}

//
// Register the callback function. Its used to iterate the list.
// XXX todo, support argument ?
//	

void registerListIterator (int (*callback)(void *data,struct list_entry *entry),struct linked_list* list) {
	if(list->session_handler == NULL) {
		DEBUG(stderr, "Error: no session_handler (callback)");
		return;
	}

	// Exchange 
	list->session_handler->iterator = callback;
}

//
// Get one list entry from a specific location in the list
//

void * getListEntry( unsigned int id, struct linked_list* list ) {
	struct list_entry* ret;
	ret = list->start;

	while ( ret != NULL) {
		if(ret->id == id) {
			ret->hits++;
			return ret->data;
		}
		ret = ret->next;
	}
	return NULL;
}


//
// Iterate the list function. This can for example be used to display 
// entries of the list on the terminal.. Check out the example in tests. In
// addition this will be used to cleanup the list (e.g. free()).
//

void iterateListCallback (int (*callback)(void *data,struct list_entry *entry) , struct linked_list* list) {
	struct list_entry* ret;

	ret = list->start;
	while ( ret != NULL) {
		(*callback)(ret->data,ret);
		ret = ret->next;
	}
}

//
// Iterate using the registered callback. 
//

void iterateList (struct linked_list* list) {

	if(list->session_handler == NULL) {
		DEBUG(stderr, "iterateList -> no callback\n");
		return;
	}

	iterateListCallback(list->session_handler->iterator,list);
}

//
// This function can be used to free the list. In addition you can optionally
// let it free the linked data aswell. Note that you have to be careful here 
// not to free things twice..
//

void freeList(struct linked_list* list, int free_data) {
	struct list_entry* entry = list->start;
	struct list_entry* free;

	DEBUG(stdout,"freeList is called !\n");

	while (free_data == 1 && entry != NULL) {
		free = entry;
		entry = entry->next;
		if(free_data == 1) {
			freeMem(free->data);
		}
		freeListEntry(free,list);
	}

	// Session handler always exists..
	if(list->session_handler != NULL) {
		DEBUG(stdout, "Freeing session handler\n");
		freeMem(list->session_handler);
	}

	freeMem(list);
}

//
//
//

void checkLock() {
	while(lock != 0) {
		DEBUG(stdout,"Waiting for list to unlock..\n");
		sleep(1);
	}
}

void lockList() {

	while(lock != 0) {
		DEBUG(stdout,"Waiting for list to unlock..\n");
		sleep(1);
	}
	lock = 1;
}

void unlockList() {
	lock = 0;
}

#ifdef WITH_THREAD

//
// Initialize the sorter thread
//

pthread_t s_thread_id;
int keeprunning = 1;
int sortinitialized = 0;

int initializeSorter(void(*callback)(void *prt), struct linked_list* list, int interval) {

	if(sortinitialized == 1) {
		fprintf(stderr, "Error, sort thread is already initialized!\n");
		return 1;
	}

	if(callback == NULL) {
		callback = bubbleSort;
	}
	
	if(list == NULL) {
		printf("List == NULL!\n");
	}
	if(list->session_handler == NULL) {
		printf("session_handler == NULL\n");
	}


	list->session_handler->sorter = callback;
	list->session_handler->sortinterval = interval;

	// Start thread...
	pthread_create(&s_thread_id,NULL,(void*)listSorter,list);

	sortinitialized = 1;

	return 0;
}

//
// This is the default sort routine.. it uses the hits
// value to sort the items. The most often used items should
// appear at the beginnig of the list.. Actually, this is a
// Cocktail sort ;-))
//

void bubbleSort(void *ptr) {

	// bubble bubble
        struct list_entry* first;
        struct list_entry* second;
        struct linked_list* list = (struct linked_list*)ptr;
	int change=1;

	printf("In bubblesort\n");
	sleep(10);

	// TODO Lock the list

	while(change != 0) {
		change=0;
		first = list->start;
		while (first != NULL && first->next != NULL) {
			second = first->next;
			//printf("Comparing %d --> %d \n",second->hits,first->hits);
			if(second->hits > first->hits) {
				change++;
				swap(second,first);
			}

			first = first->next;
		}

		first = list->stop;
		while (first != NULL && first->prev != NULL) {
			second = first->prev;
			//printf("Comparing %d --> %d \n",second->hits,first->hits);
			if(second->hits < first->hits) {
				change++;
				swap(second,first);
			}

			first = first->prev;
		}



		printf("This run change: %d\n", change);
	}
}

//
// This is a cheat.. this swap only swaps the structs entry
// data and hist members.. If you read this and feel like taking
// a challenge.. implement a merge sort or some other more performant
// algorithm, then send it to me 
//

void swap (struct list_entry *one, struct list_entry *two) {
	void *data = one->data;
	int hits   = one->hits;
	int id     = one->id;
	
	one->data = two->data;
	two->data = data;

	one->hits = two->hits;
	two->hits = hits;

	one->id = two->id;
	two->id = id;
}

//
// Supa dupa list sorter
//

void listSorter(void *ptr) {

	struct timeval s_time;
#ifdef WITH_DEBUG
	struct timeval e_time;
        long secs,msecs;
#endif

        struct linked_list* list = (struct linked_list*)ptr;

	int delay = list->session_handler->sortinterval;
	int nexttimer = (int)time(NULL) + delay;

	while( keeprunning ) {

		if(time(NULL) < nexttimer) {
			pthread_yield();
			sleep(1);
			continue;
		}

		// Call the sorter..
		gettimeofday( &s_time, NULL );
		lockList();
		(*list->session_handler->sorter)(list);
		unlockList();

		nexttimer = (int)time(NULL) + delay;

#ifdef WITH_DEBUG
		gettimeofday( &e_time, NULL );
		secs  = e_time.tv_sec  - s_time.tv_sec;
		msecs = e_time.tv_usec - s_time.tv_usec;
		printf("Time taken : %d.%d seconds\n",(int)secs,(int)msecs);
#endif

	}

}

#endif
