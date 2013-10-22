

#ifndef __UTIL_IPWATCHLIST_H__
#define __UTIL_IPWATCHLIST_H__


#include "suricata-common.h"
#include "reputation.h"

typedef struct IPWatchListCtx_ {
    /** Radix trees that holds the host reputation information */
    SCRadixTree *watchListIPV4_tree;
    SCRadixTree *watchListIPV6_tree;

    /** Mutex to support concurrent access */
    SCMutex watchlistIPV4_lock;
    SCMutex watchlistIPV6_lock;
}IPWatchListCtx;

#define MAX_WACTCH_LIST_MSG 25

typedef struct WatchListData_ {
    char* msgs[MAX_WACTCH_LIST_MSG]; /**< array of strings */
    uint8_t blacklisted; /**< 0 == true **/
    int msg_cnt;
} WatchListData;


IPWatchListCtx* _ipwatchlistCtx = NULL;

 int CreateIpWatchListCtx();
 void SCWatchListFreeData(void *);



#endif  /*__UTIL_IPWATCHLIST_H__*/
