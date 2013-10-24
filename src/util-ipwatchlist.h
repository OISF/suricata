

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
    Signature* sig;
    int ref_count;
    int inited;
} WatchListData;





 int CreateIpWatchListCtx();
 int CreateIpWatchListCtxFree();
 void SCWatchListFreeData(void *);
 int IpStrToINt(const char* ip, Address* a);
 Signature * isIPWatched(uint8_t* addr, char ipType,char* msgHeader);
 int addIpaddressesToWatchList(char * msg,  char* adr[], int len);
 WatchListData * getWatchListData(char * ip) ;

#endif  /*__UTIL_IPWATCHLIST_H__*/
