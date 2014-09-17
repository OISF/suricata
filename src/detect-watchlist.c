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

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "threads.h"
#include "flow.h"
#include "flow-bit.h"
#include "flow-util.h"
#include "detect-iprep.h"
#include "util-spm.h"

#include "app-layer-parser.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "detect-watchlist.h"

#include "util-debug.h"
#include "util-radix-tree.h"

#include "util-ipwatchlist.h"
#include "host.h"

#include "util-unittest.h"

int DetectWatchListMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
static int DetectWatchlistSetup(DetectEngineCtx *, Signature *, char *);

void DetectIPWatchListRegister(void)
{
    sigmatch_table[DETECT_STIX_IPWATCH].name = "stixip";
    sigmatch_table[DETECT_STIX_IPWATCH].Match = DetectWatchListMatch;
    sigmatch_table[DETECT_STIX_IPWATCH].Setup = DetectWatchlistSetup;
    sigmatch_table[DETECT_STIX_IPWATCH].Free = NULL;
    sigmatch_table[DETECT_STIX_IPWATCH].RegisterTests = WatchListRegisterTests;
    sigmatch_table[DETECT_STIX_IPWATCH].flags |= SIGMATCH_IPONLY_COMPAT;
}

static int DetectWatchlistSetup(DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    SigMatch *sm = NULL;
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    CreateIpWatchListCtx();
    sm->type = DETECT_STIX_IPWATCH;
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;
error:
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

#define STIX_HEADER "STIX IP Watch List was matched"

char *
MakeAlertMsg(char * header, char* list)
{
    int header_len = strlen(header);
    int list_len = strlen(list);
    int size = header_len + list_len + 2 + 1;
    char *msg;
    msg = SCMalloc(sizeof(char) * size);
    if (unlikely(msg == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Unable to allocate alert message");
        return NULL;
    }

    memcpy(msg, header, header_len);
    memcpy(msg+header_len, "(", 1);
    memcpy(msg+header_len+1, list, strlen(list));
    memcpy(msg+header_len+1+list_len, ")", 2); // For ')' and null terminator
    return msg;
}


int DetectWatchListMatch(ThreadVars * tv, DetectEngineThreadCtx * de_ctx,
        Packet * p, Signature * s, SigMatch *sm)
{
    uint8_t * src = (uint8_t *) GET_IPV4_SRC_ADDR_PTR(p);
    char src_type = p->src.family;
    uint8_t * dst = (uint8_t *) GET_IPV4_DST_ADDR_PTR(p);
    char dst_type = p->dst.family;
    char *sl;
    sl = IsIPWatched(src, src_type, STIX_HEADER);

    if (sl != NULL) {
        return 1;
    }
    sl = IsIPWatched(dst, dst_type, STIX_HEADER);
    if (sl != NULL) {
        return 1;
    }

    return 0;

}

#ifdef UNITTESTS
int AddToWatchListTest01(void)
{
    int result = 1;
    CreateIpWatchListCtx();

    char* addresses[4];

    addresses[0] = "192.168.0.1";
    addresses[1] = "192.168.0.2";
    addresses[2] = "10.0.0.1";
    addresses[3] = "10.0.0.0/16";

    if (AddIpaddressesToWatchList("Test Watch List", addresses, 4))
        result = 0;

    CreateIpWatchListCtxFree();
    return result;
}

int IsInWatchListTest01(void)
{
    int result = 1;
    CreateIpWatchListCtx();

    char* addresses[4];

    addresses[0] = "192.168.0.1";
    addresses[1] = "192.168.0.2";
    addresses[2] = "10.1.0.1";
    addresses[3] = "10.0.0.0/16";

    if (AddIpaddressesToWatchList("Test Watch List", addresses, 4))
        result = 0;

    Address* a = SCMalloc(sizeof(Address));
    if (unlikely(a == NULL)) {
        result = -1;
        goto end;
    }
    IpStrToInt(addresses[0], a);

    if (IsIPWatched((uint8_t*) a->address.address_un_data32, a->family, "Test Header") != NULL)
    {
        result = 1;
    }
    else
    {
        result = 0;
        goto end;
    }
    IpStrToInt("10.0.0.1", a);
    if (IsIPWatched((uint8_t*) a->address.address_un_data32, a->family,
                    "Test Header") != NULL)
    {

        WatchListData *d = GetWatchListData("10.0.0.1");
        if (d == NULL || d->ref_count != 4)
        {
            SCLogDebug("Ref Count was %i", d->ref_count);
            result = -2;
            goto end;
        }
        result = 1;
    }
    else
    {
        result = 0;
        goto end;
    }

end:
    CreateIpWatchListCtxFree();

    return result;
}
#endif

void WatchListRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("AddToWatchList", AddToWatchListTest01, 1);
    UtRegisterTest("IsInWatchListTest01", IsInWatchListTest01, 1);
#endif
}
