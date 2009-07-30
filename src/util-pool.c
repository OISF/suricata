/* Copyright (c) 2008 by Victor Julien <victor@inliniac.net> */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#include "util-pool.h"

#include "util-unittest.h"

Pool *PoolInit(u_int32_t size, u_int32_t prealloc_size, void *(*Alloc)(void *), void *AllocData, void (*Free)(void *))
{
    Pool *p = NULL;

    if (Alloc == NULL) {
        //printf("ERROR: PoolInit no Hash function\n");
        goto error;
    }

    if (prealloc_size > size)
        goto error;

    /* setup the filter */
    p = malloc(sizeof(Pool));
    if (p == NULL)
        goto error;

    memset(p,0,sizeof(Pool));

    p->max_buckets = size;
    p->Alloc = Alloc;
    p->AllocData = AllocData;
    p->Free  = Free;

    /* alloc the buckets and place them in the empty list */
    u_int32_t u32 = 0;
    for (u32 = 0; u32 < size; u32++) {
        /* populate pool */
        PoolBucket *pb = malloc(sizeof(PoolBucket));
        if (pb == NULL)
            goto error;

        memset(pb, 0, sizeof(PoolBucket));
        pb->next = p->empty_list;
        p->empty_list = pb;
        p->empty_list_size++;
    }

    /* prealloc the buckets and requeue them to the alloc list */
    for (u32 = 0; u32 < prealloc_size; u32++) {
        PoolBucket *pb = p->empty_list;
        if (pb == NULL)
            goto error;

        p->empty_list = pb->next;
        p->empty_list_size--;

        pb->data = p->Alloc(p->AllocData);
        p->allocated++;

        pb->next = p->alloc_list;
        p->alloc_list = pb;
        p->alloc_list_size++;
    }

    return p;

error:
    /* XXX */
    return NULL;
}

void PoolFree(Pool *p) {
    if (p == NULL)
        return;

    while (p->alloc_list != NULL) {
        PoolBucket *pb = p->alloc_list;
        p->alloc_list = pb->next;
        p->Free(pb->data);
        free(pb);
    }

    while (p->empty_list != NULL) {
        PoolBucket *pb = p->empty_list;
        p->empty_list = pb->next;
        free(pb);
    }

    free(p);
}

void PoolPrint(Pool *p) {
    printf("\n----------- Hash Table Stats ------------\n");
    printf("Buckets:               %u\n", p->empty_list_size + p->alloc_list_size);
    printf("-----------------------------------------\n");
}

void *PoolGet(Pool *p) {
    PoolBucket *pb = p->alloc_list;
    if (pb != NULL) {
        /* pull from the alloc list */
        p->alloc_list = pb->next;
        p->alloc_list_size--;

        /* put in the empty list */
        pb->next = p->empty_list;
        p->empty_list = pb;
        p->empty_list_size++;
    } else {
        if (p->allocated < p->max_buckets) {
            p->allocated++;
            return p->Alloc(p->AllocData);
        } else {
            return NULL;
        }
    }

    void *ptr = pb->data;
    pb->data = NULL;
    return ptr;
}

void PoolReturn(Pool *p, void *data) {
    PoolBucket *pb = p->empty_list;
    if (pb == NULL) {
        printf("ERROR: trying to return data %p to the pool %p, but no more buckets available.\n", data, p);
        return;
    }

    /* pull from the alloc list */
    p->empty_list = pb->next;
    p->empty_list_size--;

    /* put in the alloc list */
    pb->next = p->alloc_list;
    p->alloc_list = pb;
    p->alloc_list_size++;

    pb->data = data;
    return;
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

void *PoolTestAlloc(void *allocdata) {
    return malloc(10);
}
void *PoolTestAllocArg(void *allocdata) {
    size_t len = strlen((char *)allocdata) + 1;
    char *str = malloc(len);
    strncpy(str,(char *)allocdata,len);
    return (void *)str;
}

void PoolTestFree(void *ptr) {
    free(ptr);
}

static int PoolTestInit01 (void) {
    Pool *p = PoolInit(10,5,PoolTestAlloc,NULL,PoolTestFree);
    if (p == NULL)
        return 0;

    PoolFree(p);
    return 1;
}

static int PoolTestInit02 (void) {
    int retval = 0;

    Pool *p = PoolInit(10,5,PoolTestAlloc,NULL,PoolTestFree);
    if (p == NULL)
        goto end;

    if (p->alloc_list == NULL || p->empty_list == NULL) {
        printf("list(s) not properly initialized (a:%p e:%p): ",
            p->alloc_list, p->empty_list);
        retval = 0;
        goto end;
    } else {
        retval = 1;
    }

    if (p->Alloc != PoolTestAlloc) {
        printf("Alloc func ptr %p != %p: ",
            p->Alloc, PoolTestAlloc);
        retval = 0;
        goto end;
    } else {
        retval = 1;
    }

    if (p->Free != PoolTestFree) {
        printf("Free func ptr %p != %p: ",
            p->Free, PoolTestFree);
        retval = 0;
        goto end;
    } else {
        retval = 1;
    }
end:
    if (p != NULL)
        PoolFree(p);
    return retval;
}

static int PoolTestInit03 (void) {
    int retval = 0;

    Pool *p = PoolInit(10,5,PoolTestAlloc,NULL,PoolTestFree);
    if (p == NULL)
        goto end;

    void *data = PoolGet(p);
    if (data == NULL) {
        printf("PoolGet returned NULL: ");
        retval = 0;
        goto end;
    }

    if (p->alloc_list_size != 4) {
        printf("p->alloc_list_size 4 != %u: ", p->alloc_list_size);
        retval = 0;
        goto end;
    }

    if (p->empty_list_size != 6) {
        printf("p->empty_list_size 6 != %u: ", p->empty_list_size);
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    if (p != NULL)
        PoolFree(p);
    return retval;
}

static int PoolTestInit04 (void) {
    int retval = 0;

    Pool *p = PoolInit(10,5,PoolTestAllocArg,(void *)"test",PoolTestFree);
    if (p == NULL)
        goto end;

    char *str = PoolGet(p);
    if (str == NULL) {
        printf("PoolGet returned NULL: ");
        retval = 0;
        goto end;
    }

    if (strcmp(str, "test") != 0) {
        printf("Memory not properly initialized: ");
        retval = 0;
        goto end;
    }

    if (p->alloc_list_size != 4) {
        printf("p->alloc_list_size 4 != %u: ", p->alloc_list_size);
        retval = 0;
        goto end;
    }

    if (p->empty_list_size != 6) {
        printf("p->empty_list_size 6 != %u: ", p->empty_list_size);
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    if (p != NULL)
        PoolFree(p);
    return retval;
}

static int PoolTestInit05 (void) {
    int retval = 0;

    Pool *p = PoolInit(10,5,PoolTestAlloc,NULL,PoolTestFree);
    if (p == NULL)
        goto end;

    void *data = PoolGet(p);
    if (data == NULL) {
        printf("PoolGet returned NULL: ");
        retval = 0;
        goto end;
    }

    if (p->alloc_list_size != 4) {
        printf("p->alloc_list_size 4 != %u: ", p->alloc_list_size);
        retval = 0;
        goto end;
    }

    if (p->empty_list_size != 6) {
        printf("p->empty_list_size 6 != %u: ", p->empty_list_size);
        retval = 0;
        goto end;
    }

    PoolReturn(p, data);
    data = NULL;

    if (p->alloc_list_size != 5) {
        printf("p->alloc_list_size 5 != %u: ", p->alloc_list_size);
        retval = 0;
        goto end;
    }

    if (p->empty_list_size != 5) {
        printf("p->empty_list_size 5 != %u: ", p->empty_list_size);
        retval = 0;
        goto end;
    }

    retval = 1;
end:
    if (p != NULL)
        PoolFree(p);
    return retval;
}


void PoolRegisterTests(void) {
    UtRegisterTest("PoolTestInit01", PoolTestInit01, 1);
    UtRegisterTest("PoolTestInit02", PoolTestInit02, 1);
    UtRegisterTest("PoolTestInit03", PoolTestInit03, 1);
    UtRegisterTest("PoolTestInit04", PoolTestInit04, 1);
    UtRegisterTest("PoolTestInit05", PoolTestInit05, 1);
}

