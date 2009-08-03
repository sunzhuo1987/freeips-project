#ifndef __MYHASH_H
#define __MYHASH_H

#define HASH_PRIM 786433

typedef struct hashtable {
	struct hashentry **table;
	int (*coll_handler)(void *one,void *two);
	long entries;
	long size;
} HashTable;

typedef struct hashentry {
	void      *data;
	struct hashentry *next;
	int       subindex;
	// Orig key??
} HashEntry;

typedef struct keyvals {
	long vals[4];
	long key;

} KeyVals;


HashTable *createHashTable (long size, int (*coll_handler)(void *one,void *two));
void * getHashValue(HashTable *hash, struct traffic *traf);
void * popHashValue(HashTable *hash, struct traffic *traf);
long setHashEntry(HashTable *hash, struct traffic *traf,void *value );
int hasHashEntry(HashTable *hash,struct traffic* traf);
HashEntry * getHashEntry(HashTable *hash, struct traffic* traf);
HashEntry * popHashEntry(HashTable *hash, long key);
void * fetchHashValue(HashTable *hash, struct traffic *traf,int free);
long seedToKey(KeyVals *keyv);
long ipToKey(struct iphdr* hdr);
long setTrafficHash(struct traffic *traf);
long seedToKey(KeyVals *keyv);



#endif
