/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

#ifndef __HASH_H__
#define __HASH_H__

/* hash bucket structure */
typedef struct _HashTableBucket {
    void *data;
    u_int16_t size;
    struct _HashTableBucket *next;
} HashTableBucket;

/* hash table structure */
typedef struct _HashTable {
    HashTableBucket **array;
    u_int32_t array_size;
    u_int32_t (*Hash)(struct _HashTable *, void *, u_int16_t);
    void (*Free)(void *);
} HashTable;

/* prototypes */
HashTable* HashTableInit(u_int32_t, u_int32_t (*Hash)(struct _HashTable *, void *, u_int16_t), void (*Free)(void *));
void HashTableFree(HashTable *);
void HashTablePrint(HashTable *);
int HashTableAdd(HashTable *, void *, u_int16_t);
int HashTableRemove(HashTable *, void *, u_int16_t);
void *HashTableLookup(HashTable *, void *, u_int16_t);
u_int32_t HashTableGenericHash(HashTable *, void *, u_int16_t);


#endif /* __HASH_H__ */

