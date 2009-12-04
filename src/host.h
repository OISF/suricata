#ifndef __HOST_H__
#define __HOST_H__

#include "decode.h"
#include "util-hash.h"
#include "util-bloomfilter-counting.h"

typedef struct HostTable_ {
    SCMutex m;

    /* storage & lookup */
    HashTable *hash;
    BloomFilterCounting *bf;

    uint32_t cnt;
} HostTable;

typedef struct Host_ {
    SCMutex m;

    Address addr;
    uint8_t os;
    uint8_t reputation;

    uint64_t bytes;
    uint32_t pkts;
} Host;

#define HOST_OS_UNKNOWN 0
/* XXX define more */

#define HOST_REPU_UNKNOWN 0
/* XXX see how we deal with this */

#endif /* __HOST_H__ */

