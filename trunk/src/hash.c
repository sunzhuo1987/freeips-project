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


#include <util.h>

HashTable *createHashTable (long size, int (*coll_handler)(void *one,void *two)) {

	HashTable *hash    = (HashTable *) allocMem(sizeof(HashTable));
	hash->table        = (HashEntry **)allocMem(sizeof(HashEntry) * size);
	hash->entries      = 0;
	hash->size         = size;
	hash->coll_handler = coll_handler;

	if(hash->table == NULL) {
		log_error("Unable to get memory for hashtable");
		stats_increase_cnt(CNT_HASHMAP_MISS,1);
		return NULL;
	}

	//Zero out 
	memset(hash->table, 0, size * sizeof(HashEntry));
	return hash;
}


HashEntry * getHashEntry(HashTable *hash, struct traffic* traf) {
	HashEntry *hentry  = NULL;
	if(traf->hashkey < 0 && traf->hashkey > hash->size) {
		log_error("Out of bound hashtable request");
		stats_increase_cnt(CNT_HASHMAP_MISS,1);
		return NULL;
	}

	// Check if there was a collision
	if(hash->table[traf->hashkey]->next != NULL) {
		hentry = hash->table[traf->hashkey];
		do {
			if( (*hash->coll_handler)(hentry->data,traf) == 0) {
				return hentry;
			}  
			hentry  = hentry->next;
		} while(hentry != NULL);

		stats_increase_cnt(CNT_HASHMAP_MISS,1);
		return NULL;
	} 

	stats_increase_cnt(CNT_HASHMAP_HITS,1);
	return hash->table[traf->hashkey];

}

int hasHashEntry(HashTable *hash,struct traffic* traf) {
	if(hash->table[traf->hashkey] != NULL) {
		stats_increase_cnt(CNT_HASHMAP_HITS,1);
		return 1;
	}
	stats_increase_cnt(CNT_HASHMAP_MISS,1);
	return 0;
}

HashEntry * popHashEntry(HashTable *hash, long key) {
	void *ptr = hash->table[key];
	hash->table[key] = NULL;
	hash->entries--;
	stats_increase_cnt(CNT_HASHMAP_HITS,1);
	return ptr;
}

void * popHashValue(HashTable *hash, struct traffic *traf) {
        //printf("popHashValue %ld\n",traf->hashkey);
	hash->entries--;
	return fetchHashValue(hash,traf,1);
}

void * getHashValue(HashTable *hash, struct traffic *traf) {
        //printf("getHashValue %ld\n",traf->hashkey);
	return fetchHashValue(hash,traf,0);
}


void * fetchHashValue(HashTable *hash, struct traffic *traf,int free) {
        void *ptr = hash->table[traf->hashkey];
	HashEntry *hentry  = NULL;
	HashEntry *phentry = NULL;

        // Check if exists
        if(hash->table[traf->hashkey] == NULL) {
                //log_error("popHashValue() no such data");
		stats_increase_cnt(CNT_HASHMAP_MISS,1);
                return NULL;
        }

        if((hentry = hash->table[traf->hashkey]->next) != NULL) {
		phentry = NULL;
		do {
			if( (*hash->coll_handler)(hentry->data,traf) == 0) {
				ptr = hentry->data;
				break;
			}  
			phentry = hentry;
			hentry  = hentry->next;
		} while(hentry != NULL);
        } else {
		ptr = hash->table[traf->hashkey]->data;
	}

        //free the session struct
	if(free == 1) {
		if(phentry == NULL) {
			freeMem(hash->table[traf->hashkey]);
			hash->table[traf->hashkey] = NULL;
		} else {
			phentry = hentry->next;
			freeMem(hentry);

		}
	}

	stats_increase_cnt(CNT_HASHMAP_HITS,1);
        return ptr;
}



long setHashEntry(HashTable *hash, struct traffic *traf,void *value ) {
	HashEntry *newentry = (HashEntry *)allocMem(sizeof(HashEntry));
	HashEntry *entryptr;
	int subindex  = 0;

	hash->entries++;
	if(hash->table[traf->hashkey] != NULL) {
		stats_increase_cnt(CNT_HASHMAP_COLL,1);
		DEBUG(stderr, "Hash collision.. ");
		do {
			entryptr = hash->table[traf->hashkey];
			subindex++;
		} while(entryptr->next != NULL);
		entryptr->next = newentry;
	} else {
		hash->table[traf->hashkey] = newentry;
	}

	hash->table[traf->hashkey]->subindex = subindex;
	hash->table[traf->hashkey]->data     = value;
	hash->table[traf->hashkey]->next     = NULL;
	return 0;
}

long seedToKey(KeyVals *keyv) {
	keyv->key =  (keyv->vals[0] % HASH_PRIM) + (keyv->vals[1] % HASH_PRIM) + keyv->vals[2] + keyv->vals[3];
	return keyv->key;
}

long ipToKey(struct iphdr *hdr) {
	return (hdr->ip_src.s_addr % HASH_PRIM) + (hdr->ip_dst.s_addr % HASH_PRIM);
}

long setTrafficHash(struct traffic *traf) {
	if(traf->proto == P_TCP) {
		traf->hashkey = (traf->iphdr->ip_src.s_addr % HASH_PRIM);
		traf->hashkey += (traf->iphdr->ip_dst.s_addr % HASH_PRIM);
		traf->hashkey += htons(traf->tcphdr->th_sport) + htons(traf->tcphdr->th_dport);
	} else {
		traf->hashkey =  (traf->iphdr->ip_src.s_addr % HASH_PRIM);
		traf->hashkey += (traf->iphdr->ip_dst.s_addr % HASH_PRIM);
	}

	return traf->hashkey;
}

