#include "util-ipwatchlist.h"
#include "util-ip.h"

int
CreateIpWatchListCtx()
{
    if (_ipwatchlistCtx == NULL)
        {
            _ipwatchlistCtx = (IPWatchListCtx *) SCMalloc(
                    sizeof(IPWatchListCtx));
            if (unlikely(_ipwatchlistCtx == NULL))
                goto error;

            memset(_ipwatchlistCtx, 0, sizeof(IPWatchListCtx));

            _ipwatchlistCtx->watchListIPV4_tree = SCRadixCreateRadixTree(
                    SCWatchListFreeData, NULL);
            if (_ipwatchlistCtx->watchListIPV4_tree == NULL)
                {
                    SCLogDebug(
                            "Error initializing STIX IP Watchlist IPV4 module");
                    return NULL;
                }

            SCLogDebug("STIX IP Watchlist IPV4 module initialized");

            _ipwatchlistCtx->watchListIPV6_tree = SCRadixCreateRadixTree(
                    SCWatchListFreeData, NULL);
            if (_ipwatchlistCtx->watchListIPV6_tree == NULL)
                {
                    SCLogDebug(
                            "Error initializing STIX IP Watchlist IPV6 module");
                    return NULL;
                }

            SCLogDebug("STIX IP Watchlist IPV6 module initialized");
            if (SCMutexInit(&_ipwatchlistCtx->watchlistIPV4_lock, NULL) != 0)
                {
                    SCLogError(SC_ERR_MUTEX, "Mutex not correctly initialized");
                    exit(EXIT_FAILURE);
                }
            if (SCMutexInit(&_ipwatchlistCtx->watchlistIPV6_lock, NULL) != 0)
                {
                    SCLogError(SC_ERR_MUTEX, "Mutex not correctly initialized");
                    exit(EXIT_FAILURE);
                }

        }
    return 0;

    error:
    SCFree(_ipwatchlistCtx);
    _ipwatchlistCtx = NULL;
    return -1;
}

int
CreateIpWatchListCtxFree()
{
    SCRadixReleaseRadixTree(_ipwatchlistCtx->watchListIPV4_tree);
    SCRadixReleaseRadixTree(_ipwatchlistCtx->watchListIPV6_tree);
    SCMutexDestroy(_ipwatchlistCtx->watchlistIPV4_lock);
    SCMutexDestroy(_ipwatchlistCtx->watchlistIPV6_lock);
    SCFree(_ipwatchlistCtx);
    _ipwatchlistCtx = NULL;
    return 1;
}

int
addIpaddressesToWatchList(const char * msg, const char** adr)
{
    WatchListData *data = NULL;
    WatchListData * data = SCMalloc(sizeof(WatchListData));
    memset(data, 0, sizeof(WatchListData));
    Signature* s = SCMalloc(sizeof(Signature));
    memset(data, 0, sizeof(Signature));
    data->sig = s;
    data->sig->msg = msg;
    addIpaddressToWatchList(adr, data)
}
/**
 * \brief Converts an IP address into a int, subnet masking is ignored
 *
 * \param ip char string that contains IP
 * * \param a Address struct that ouput will be stored in. Caller must alloc and free this struct.
 */
int
IpStrToINt(const char* ip, Address* a)
{

    if (a == NULL)
        return 1;

    if (strchr(ip, ':') != NULL)
        {
            a->family = AF_INET6;
            if (inet_pton(AF_INET6, ip, a->address) <= 0)
                {
                    return 1;
                }
        }
    else
        {
            a->family = AF_INET;
            if (inet_pton(AF_INET, adr, a->address) <= 0)
                {
                    return 1;
                }
        }
    return 0;

}

static int
addIpaddressToWatchList(const char* adr, const WatchListData* data)
{
    int returnVal = 0;
    if (_ipwatchlistCtx == NULL)
        {
            SCLogWarning(
                    "STIX Add to IP Watch List was called when Context was Null %s",
                    ".");
            return 0;
        }
    SCMutex mutex = NULL;

    Address * a = SCMalloc(sizeof(Address));
    IpStrToINt(adr, a );
    /* IPV6 or IPV4? */

    switch(a->family)
    {
    case AF_INET6:
            mutex = _ipwatchlistCtx->watchlistIPV6_lock;
            SCMutexLock(mutex);
            SCRadixNode* node = SCRadixFindKeyIPV6ExactMatch(
                    (uint8_t *) a->address.address_un_data32,
                    _ipwatchlistCtx->watchListIPV6_tree);
            if (node == NULL)
                {
                    data->ref_count++;

                    if (SCRadixAddKeyIPV6String(adr,
                            _ipwatchlistCtx->watchListIPV6_tree, data) == NULL)
                        {
                            SCLogWarning(SC_ERR_INVALID_VALUE, "STIX failed to "
                                    "add %s to watch list, ignoring", adr);
                            returnVal = 1;
                        }
                }
            break;
    case AF_INET:
            SCLogDebug("STIX IP Watch Lust adding ipv4 address %s", adr);
            mutex = _ipwatchlistCtx->watchlistIPV6_lock;

            SCMutexLock(mutex);
            SCRadixNode* node = SCRadixFindKeyIPV4ExactMatch(
                    (uint8_t *) a->address.address_un_data32,
                    _ipwatchlistCtx->watchListIPV4_tree);
            if (node == NULL)
                {
                    data->ref_count++;

                    if (SCRadixAddKeyIPV4String(adr,
                            _ipwatchlistCtx->watchListIPV4_tree, data) == NULL)
                        {
                            SCLogWarning(SC_ERR_INVALID_VALUE, "STIX failed "
                                    "to add ipv4 server %s, ignoring", adr);
                            returnVal = 1;
                        }
                }
        }

    SCMutexUnlock(mutex);
    SCFree(a);
    return returnVal;
}

void
SCWatchListFreeData(void * user)
{
    WatchListData * data = (WatchListData *) user;
    data->ref_count--;
    if (data->ref_count == 0)
        {
            SCFree(data->sig);
            data->sig = NULL;
        }
    else if (unlikely(data->ref_count < 0 && data->sig != NULL))
        {
            SCLogDebug(SC_ERR_INVALID_VALUE,
                    "Freeing STIX IP Watch List ref count of %i with non NULL sig",
                    data->ref_count);
            SCFree(data->sig);
            data->sig = NULL;
            data->ref_count = 0;
        }
    else if (unlikely(data->ref_count < 0 && data->sig == NULL))
        {
            SCLogDebug(SC_ERR_INVALID_VALUE,
                    "Freeing STIX IP Watch List ref count of %i with NULL sig",
                    data->ref_count);
            data->ref_count = 0;
        }

}

char *
isIPWatched(uint8_t* addr, char* ipType)
{
    switch (ipType)
        {
    case AF_INET:
        SCRadixNode *node = SCRadixFindKeyIPV4BestMatch(addr,
                _ipwatchlistCtx->watchListIPV4_tree);
        if (node != NULL)
            {
                return SC_RADIX_NODE_USERDATA(node, WatchListData)->msgs[0];
            }
        else
            {
                return NULL;
            }
    case AF_INET6:
        SCRadixNode *node = SCRadixFindKeyIPV4BestMatch(addr,
                _ipwatchlistCtx->watchListIPV6_tree);
        if (node != NULL)
            {
                return SC_RADIX_NODE_USERDATA(node, WatchListData)->msgs[0];
            }
        else
            {
                return NULL;
            }
        }
    return NULL;
}

int
DetectMatch(Packet *p)
{
    uint8_t * src = GET_IPV4_SRC_ADDR_PTR(p);
    char src_type = p->src->family;
    uint8_t * dst = GET_IPV4_DST_ADDR_PTR(p)
    char dst_type = p->dst->family;

    if (isIPWatched(src, src_type) != NULL)
        {
            return 1;
        }

    if (isIPWatched(dst, dst_type) != NULL)
        {
            return 1;
        }

    return 0;
}
