/* Copyright (C) 2007-2014 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "util-ipwatchlist.h"
#include "util-ip.h"

IPWatchListCtx* _ipwatchlist_ctx = NULL;

static int AddIpaddressToWatchList(const char* adr, WatchListData* data);

int CreateIpWatchListCtx()
{
    if (_ipwatchlist_ctx == NULL) {
        _ipwatchlist_ctx = (IPWatchListCtx *) SCMalloc(sizeof(IPWatchListCtx));
        if (unlikely(_ipwatchlist_ctx == NULL))
            goto error;

        memset(_ipwatchlist_ctx, 0, sizeof(IPWatchListCtx));

        _ipwatchlist_ctx->watch_list_ipv4_tree = SCRadixCreateRadixTree(SCWatchListFreeData, NULL);
        if (_ipwatchlist_ctx->watch_list_ipv4_tree == NULL) {
            SCLogDebug("Error initializing STIX IP Watchlist IPV4 module");
            return 1;
        }

        SCLogDebug("STIX IP Watchlist IPV4 module initialized");

        _ipwatchlist_ctx->watch_list_ipv6_tree = SCRadixCreateRadixTree(
                SCWatchListFreeData, NULL);
        if (_ipwatchlist_ctx->watch_list_ipv6_tree == NULL) {
            SCLogDebug("Error initializing STIX IP Watchlist IPV6 module");
            return 1;
        }

        SCLogDebug("STIX IP Watchlist IPV6 module initialized");
        if (SCMutexInit(&_ipwatchlist_ctx->watch_list_ipv4_lock, NULL) != 0) {
            SCLogError(SC_ERR_MUTEX, "Mutex not correctly initialized");
            exit(EXIT_FAILURE);
        }
        if (SCMutexInit(&_ipwatchlist_ctx->watch_list_ipv6_lock, NULL) != 0) {
            SCLogError(SC_ERR_MUTEX, "Mutex not correctly initialized");
            exit(EXIT_FAILURE);
        }

    }
    return 0;

    error:
        SCFree(_ipwatchlist_ctx);
        _ipwatchlist_ctx = NULL;

    return 0;
}


int CreateIpWatchListCtxFree()
{
    SCRadixReleaseRadixTree(_ipwatchlist_ctx->watch_list_ipv4_tree);
    SCRadixReleaseRadixTree(_ipwatchlist_ctx->watch_list_ipv6_tree);
    SCMutexDestroy(&_ipwatchlist_ctx->watch_list_ipv4_lock);
    SCMutexDestroy(&_ipwatchlist_ctx->watch_list_ipv6_lock);
    SCFree(_ipwatchlist_ctx);
    _ipwatchlist_ctx = NULL;
    return 1;
}


int AddIpaddressesToWatchList(char * msg, char* adr[], int len)
{
    WatchListData * data = SCMalloc(sizeof(WatchListData));
    memset(data, 0, sizeof(WatchListData));
    Signature* s = SCMalloc(sizeof(Signature));
    memset(s, 0, sizeof(Signature));
    data->sig = s;
    data->sig->msg = msg;
    for (int i = 0; i < len; i++) {
        AddIpaddressToWatchList(adr[i], data);
    }
    return 0;
}


/**
 * \brief Converts an IP address into a int, subnet masking is ignored
 *
 * \param ip char string that contains IP
 * * \param a Address struct that output will be stored in. Caller must alloc and free this struct.
 */
int IpStrToINt(const char* ip, Address* a)
{
    if (a == NULL)
        return 1;

    if (strchr(ip, ':') != NULL) {
        a->family = AF_INET6;
        if (inet_pton(AF_INET6, ip, a->address.address_un_data32) <= 0) {
            return 1;
        }
    } else {
        a->family = AF_INET;
        if (inet_pton(AF_INET, ip, a->address.address_un_data32) <= 0) {
            return 1;
        }
    }
    return 0;

}


static int AddIpaddressToWatchList(const char* adr, WatchListData* data)
{
    int return_val = 0;
    if (_ipwatchlist_ctx == NULL) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENT, "STIX Add to IP Watch List was called when Context was Null.");
        return 0;
    }
    SCMutex mutex;

    Address * a = SCMalloc(sizeof(Address));
    IpStrToINt(adr, a);
    /* IPV6 or IPV4? */

    switch (a->family) {
        case AF_INET6: {
            mutex = _ipwatchlist_ctx->watch_list_ipv6_lock;
            SCMutexLock(&mutex);
            void *user_data = NULL;
            (void)SCRadixFindKeyIPV6ExactMatch(
                    (uint8_t *) a->address.address_un_data32,
                    _ipwatchlist_ctx->watch_list_ipv6_tree, &user_data);
            if (user_data == NULL) {
                data->ref_count++;

                if (SCRadixAddKeyIPV6String(adr,
                        _ipwatchlist_ctx->watch_list_ipv6_tree, (void *) data)
                        == NULL) {
                    SCLogWarning(SC_ERR_INVALID_VALUE, "STIX failed to add %s to watch list, ignoring", adr);
                    return_val = 1;
                }
            }
            break;
        }
        case AF_INET: {
            SCLogDebug("STIX IP Watch List adding ipv4 address %s", adr);
            mutex = _ipwatchlist_ctx->watch_list_ipv4_lock;

            SCMutexLock(&mutex);
            void *user_data = NULL;
            (void)SCRadixFindKeyIPV4ExactMatch(
                    (uint8_t *) a->address.address_un_data32,
                    _ipwatchlist_ctx->watch_list_ipv4_tree, &user_data);
            if (user_data == NULL) {
                data->ref_count++;

                if (SCRadixAddKeyIPV4String(adr,
                        _ipwatchlist_ctx->watch_list_ipv4_tree, data) == NULL) {
                    SCLogWarning(SC_ERR_INVALID_VALUE, "STIX failed to add ipv4 server %s, ignoring", adr);
                    return_val = 1;
                }
            }
            break;
        }
    }

    SCMutexUnlock(&mutex);
    SCFree(a);
    return return_val;
}

void SCWatchListFreeData(void * user)
{
    WatchListData * data = (WatchListData *) user;
    data->ref_count--;
    if (data->ref_count == 0) {
        SCFree(data->sig);
        data->sig = NULL;
    } else if (unlikely(data->ref_count < 0 && data->sig != NULL)) {
        SCLogDebug(SC_ERR_INVALID_VALUE,
                "Freeing STIX IP Watch List ref count of %i with non NULL sig",
                data->ref_count);
        SCFree(data->sig);
        data->sig = NULL;
        data->ref_count = 0;
    } else if (unlikely(data->ref_count < 0 && data->sig == NULL)) {
        SCLogDebug(SC_ERR_INVALID_VALUE,
                "Freeing STIX IP Watch List ref count of %i with NULL sig",
                data->ref_count);
        data->ref_count = 0;
    }

}

Signature *
InitWatchDataFully(char* msg_header, WatchListData* data)
{
    if (!data->inited) {

        if (msg_header != NULL) {
            int header_len = strlen(msg_header);
            int data_len = strlen(data->sig->msg);
            int size = header_len + data_len + 2 + 1;
            char *msg;
            msg = SCMalloc(sizeof(char) * size);
            memset(msg, 0, sizeof(char) * size);
            memcpy(msg, msg_header, header_len);
            memcpy(msg+header_len, "(", 1);
            memcpy(msg+header_len+1, data->sig->msg, strlen(data->sig->msg));
            memcpy(msg+header_len+1+data_len, ")", 2); // 2 is For ')' and null terminator
            data->sig->msg = msg;
            SCFree(msg);
        }

        data->inited = 1;
    }
    return data->sig;
}

Signature* IsIPWatched(uint8_t* addr, char ip_type, char* msg_header)
{
    switch (ip_type) {
        case AF_INET: {
            void *user_data = NULL;
            (void)SCRadixFindKeyIPV4BestMatch(addr,
                    _ipwatchlist_ctx->watch_list_ipv4_tree, &user_data);
            if (user_data != NULL) {
                return InitWatchDataFully(msg_header, user_data);
            }
            break;
        }
        case AF_INET6: {
            void *user_data = NULL;
            (void)SCRadixFindKeyIPV4BestMatch(addr,
                    _ipwatchlist_ctx->watch_list_ipv6_tree, &user_data);
            if (user_data != NULL) {
                return InitWatchDataFully(msg_header, user_data);
            }
            break;
        }
    }
    return NULL;
}

WatchListData *
GetWatchListData(char * ip)
{
    Address* a = SCMalloc(sizeof(Address));
    IpStrToINt(ip, a);
    void *user_data = NULL;
    (void)SCRadixFindKeyIPV4BestMatch(
            (uint8_t*) a->address.address_un_data32,
            _ipwatchlist_ctx->watch_list_ipv4_tree, &user_data);
    SCFree(a);
    return user_data;
}

#if 0
int DetectMatch(Packet *p)
{
    uint8_t * src = GET_IPV4_SRC_ADDR_PTR(p);
    char src_type = p->src.family;
    uint8_t * dst = GET_IPV4_DST_ADDR_PTR(p);
    char dst_type = p->dst.family;

    if (IsIPWatched(src, src_type) != NULL)
    {
        return 1;
    }

    if (IsIPWatched(dst, dst_type) != NULL)
    {
        return 1;
    }

    return 0;
}
#endif

