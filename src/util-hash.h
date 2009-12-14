/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

#ifndef __HASH_H__
#define __HASH_H__

/* hash bucket structure */
typedef struct HashTableBucket_ {
    void *data;
    uint16_t size;
    struct HashTableBucket_ *next;
} HashTableBucket;

/* hash table structure */
typedef struct HashTable_ {
    HashTableBucket **array;
    uint32_t array_size;
#ifdef UNITTESTS
    uint32_t count;
#endif
    uint32_t (*Hash)(struct HashTable_ *, void *, uint16_t);
    char (*Compare)(void *, uint16_t, void *, uint16_t);
    void (*Free)(void *);
} HashTable;

/* prototypes */
HashTable* HashTableInit(uint32_t, uint32_t (*Hash)(struct HashTable_ *, void *, uint16_t), char (*Compare)(void *, uint16_t, void *, uint16_t), void (*Free)(void *));
void HashTableFree(HashTable *);
void HashTablePrint(HashTable *);
int HashTableAdd(HashTable *, void *, uint16_t);
int HashTableRemove(HashTable *, void *, uint16_t);
void *HashTableLookup(HashTable *, void *, uint16_t);
uint32_t HashTableGenericHash(HashTable *, void *, uint16_t);
char HashTableDefaultCompare(void *, uint16_t, void *, uint16_t);

void HashTableRegisterTests(void);

#endif /* __HASH_H__ */

