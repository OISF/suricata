#ifndef __HOST_H__
#define __HOST_H__

#include "decode.h"

#include "util-hash.h"
#include "util-bloomfilter-counting.h"

typedef struct HostTable_ {
    pthread_mutex_t m;

    /* storage & lookup */
    HashTable *hash;
    BloomFilterCounting *bf;

    u_int32_t cnt;
} HostTable;

typedef struct Host_ {
    pthread_mutex_t m;

    Address addr;
    u_int8_t os;
    u_int8_t reputation;

    u_int64_t bytes;
    u_int32_t pkts;
} Host;

#define HOST_OS_UNKNOWN 0
/* XXX define more */

#define HOST_REPU_UNKNOWN 0
/* XXX see how we deal with this */

#endif /* __HOST_H__ */

