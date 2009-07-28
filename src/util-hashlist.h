/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

#ifndef __HASHLIST_H__
#define __HASHLIST_H__

/* hash bucket structure */
typedef struct HashListTableBucket_ {
    void *data;
    u_int16_t size;
    struct HashListTableBucket_ *bucknext;
    struct HashListTableBucket_ *listnext;
    struct HashListTableBucket_ *listprev;
} HashListTableBucket;

/* hash table structure */
typedef struct HashListTable_ {
    HashListTableBucket **array;
    HashListTableBucket *listhead;
    HashListTableBucket *listtail;
    u_int32_t array_size;
    u_int32_t (*Hash)(struct HashListTable_ *, void *, u_int16_t);
    char (*Compare)(void *, u_int16_t, void *, u_int16_t);
    void (*Free)(void *);
} HashListTable;

/* prototypes */
HashListTable* HashListTableInit(u_int32_t, u_int32_t (*Hash)(struct HashListTable_ *, void *, u_int16_t), char (*Compare)(void *, u_int16_t, void *, u_int16_t), void (*Free)(void *));
void HashListTableFree(HashListTable *);
void HashListTablePrint(HashListTable *);
int HashListTableAdd(HashListTable *, void *, u_int16_t);
int HashListTableRemove(HashListTable *, void *, u_int16_t);
void *HashListTableLookup(HashListTable *, void *, u_int16_t);
u_int32_t HashListTableGenericHash(HashListTable *, void *, u_int16_t);
HashListTableBucket *HashListTableGetListHead(HashListTable *);
#define HashListTableGetListNext(hb) (hb)->listnext
#define HashListTableGetListData(hb) (hb)->data
char HashListTableDefaultCompare(void *, u_int16_t, void *, u_int16_t);

void HashListTableRegisterTests(void);

#endif /* __HASHLIST_H__ */

