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

#include <unistd.h>

struct list_data {
	int number ;
};

int callback(void *data,struct list_entry *entry) {
	printf("Original id: %d (hist: %d) \n",entry->id,entry->hits);
	return 0;
}

int main() {

	struct linked_list *list; 
	struct list_data* entry;
	int i;

	list = getNewList();

	initializeSorter(NULL, list, 1);

	for (i=0; i < 15; i++) {
		entry = (struct list_data*)allocMem(sizeof(struct list_data));
		pushListEntry(entry,list);
	}

	// Get one item a few times..
	entry = (struct list_data *) getListEntry(10,list);
	entry = (struct list_data *) getListEntry(10,list);
	entry = (struct list_data *) getListEntry(10,list);
	entry = (struct list_data *) getListEntry(12,list);
	entry = (struct list_data *) getListEntry(12,list);

	printf("List order before sort..\n");
	iterateListCallback(callback,list);

	printf("Waiting for sort to kick in.. \n");
	sleep(6);
	printf("List order after sort\n");
	iterateListCallback(callback,list);

	freeList(list,1);
	printMemStats();

	printf( "Done !\n" );
	return 0;
}
