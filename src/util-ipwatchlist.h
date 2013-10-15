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

#ifndef __UTIL_IPWATCHLIST_H__
#define __UTIL_IPWATCHLIST_H__


#include "suricata-common.h"
#include "reputation.h"

typedef struct IPWatchListCtx_ {
    /** Radix trees that holds the host reputation information */
    SCRadixTree *watch_list_ipv4_tree;
    SCRadixTree *watch_list_ipv6_tree;

    /** Mutex to support concurrent access */
    SCMutex watch_list_ipv4_lock;
    SCMutex watch_list_ipv6_lock;
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
 Signature * IsIPWatched(uint8_t* addr, char ip_type,char* msg_header);
 int AddIpaddressesToWatchList(char * msg,  char* adr[], int len);
 WatchListData * GetWatchListData(char * ip) ;

#endif  /*__UTIL_IPWATCHLIST_H__*/

