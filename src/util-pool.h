/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

#ifndef __UTIL_POOL_H__
#define __UTIL_POOL_H__

/* pool bucket structure */
typedef struct _PoolBucket {
    void *data;
    struct _PoolBucket *next;
} PoolBucket;

/* pool structure */
typedef struct _Pool {
    PoolBucket *alloc_list;
    u_int32_t alloc_list_size;

    PoolBucket *empty_list;
    u_int32_t empty_list_size;

    void *(*Alloc)(void *);
    void *AllocData;
    void (*Free)(void *);
} Pool;

/* prototypes */
Pool* PoolInit(u_int32_t, u_int32_t, void *(*Alloc)(void *), void *, void (*Free)(void *));
void PoolFree(Pool *);
void PoolPrint(Pool *);
void *PoolGet(Pool *);

void PoolRegisterTests(void);

#endif /* __UTIL_POOL_H__ */

