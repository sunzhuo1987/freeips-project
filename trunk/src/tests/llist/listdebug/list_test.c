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

#include <stdio.h>
#include <stdlib.h>
#include <list.h>
#include <memory.h>

struct list_data {
	char blah[100];
};

int callback(void *data,struct list_entry *entry) {

	struct list_data *ldata = (struct list_data *)data;
	printf("Callback --> %s \n",ldata->blah);
	return 0;
}

int main() {

	struct linked_list *list; 
	struct list_data* entry;
	int i;

	list = getNewList();

	// Making list entries.
	for (i=1; i < 100; i++) {
		entry = (struct list_data*)allocMem(sizeof(struct list_data));
		sprintf(entry->blah,"This is entry %d!\n",i);
		printf( "Before pushListEntry\n");
		pushListEntry(entry,list);
	}

	// Get one item

	entry = (struct list_data *) getListEntry(10,list);
	printf("FETCHED 10 --> %s \n",entry->blah);

	//Iterate
	iterateListCallback(callback,list);

	// Now dumping them.. (disabled for free test)
	/*
	while((entry = (struct list_data*) popListEntry( list ) )) {
		if(entry == NULL || list->stop == NULL) {
			break;
		}
		printf("DATA --> %s \n",entry->blah);
	}
	*/

	freeList(list,1);
	printMemStats();

	// Add some new lists..
	//list = getNewList();
	//list = getNewList();

	printf( "Done !\n" );
	return 0;
}
