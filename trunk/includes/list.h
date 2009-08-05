#ifndef __LIST_H
#define __LIST_H

#include <stdio.h>

#ifdef WITH_THREAD
#define SORT_INTERVAL	30
#endif

//
// Generic list entry struct. This struct contains a 
// pointer to the actual data that was added to the 
// list
//
// Keep a hit count for the default list sorter. This
// should improve search time when a specific entry is
// popular
//

struct list_entry {
	void *data;
	struct list_entry *next;
	struct list_entry *prev;
	int hits;
	unsigned int id;
};

//
// Struct list
//

struct linked_list {
	struct list_entry *start;
	struct list_entry *stop;
	struct linked_list *next;
	struct linked_list *prev;
	struct list_entry *ptr;
	struct session_handler *session_handler;
	int entry_max;
	int entry_cnt;
	int data_cnt;
	int backlog_max; // defined how much entries are to be kept in
        int backlog_cnt; // memory maximum before getting released in memory
	unsigned int id;
};

//
// The list session handler.. this allows
// an iterator and destructor function ref to 
// be defined (e.g. in case you need to free())
//

struct session_handler {
	int (*destructor)(void *data,struct list_entry *entry);
	int (*iterator)  (void *data,struct list_entry *entry);
	void(*sorter)(void *prt);
	int sortinterval;
};

// List functions
struct list_entry * newListEntry();
struct linked_list *newList();
struct linked_list *getNewList();
int pushListEntry (void *data, struct linked_list* list);
void * popListEntry(struct linked_list* list);
void * getListEntry(unsigned int id, struct linked_list* list );
void * popListEntryPtr(struct linked_list* list);
//void iterateListCallback (int (*callback)(struct list_entry*) , struct linked_list* list);
void iterateList (struct linked_list* list);
void iterateListCallback (int (*callback)(void *data, struct list_entry *entry) , struct linked_list* list);
void freeList(struct linked_list* list, int free_data);
void registerListDestructor (int (*callback)(void *data,struct list_entry *entry),struct linked_list* list);
void registerListIterator (int (*callback)(void *data,struct list_entry *entry),struct linked_list* list);
void freeListEntry (struct list_entry* entry,struct linked_list* list);
int initializeSorter(void(*callback)(void *prt), struct linked_list* list, int interval);
void bubbleSort(void *ptr);
void swap (struct list_entry *one, struct list_entry *two);
void * shiftListEntry(struct linked_list* list);
void listSorter(void *ptr);
void checkLock();
void lockList();
void unlockList();
void setListSize(int maxsize, struct linked_list *list);
void removeEntry(struct list_entry* entry,struct linked_list* list);
int pushListEntryBack (void *data, struct linked_list* list);
struct linked_list * newLiteList();
struct linked_list * getRingBuffer(int entries);
int pushRingData(void *data, struct linked_list* list);
void * popRingData(struct linked_list* list);


#endif
