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

#include "util-debug.h"
#include "util-radix-tree.h"

#include "util-ipwatchlist.h"
#include "host.h"


#include "util-unittest.h"

#ifdef UNITTESTS
static int addToWatchListTest01(void);
static int isInWatchListTest01(void);
#endif


int
DetectWatchListMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
        Signature *, SigMatch *);
static int
DetectWatchlistSetup(DetectEngineCtx *, Signature *, char *);
void
DetectWatchlistFree(void *);
 static void
WatchListRegisterTests(void);

void
DetectIPWatchListRegister(void)
{
    sigmatch_table[DETECT_STIX_IPWATCH].name = "stixip";
    sigmatch_table[DETECT_STIX_IPWATCH].Match = DetectWatchListMatch;
    sigmatch_table[DETECT_STIX_IPWATCH].Setup = DetectWatchlistSetup;
    sigmatch_table[DETECT_STIX_IPWATCH].Free = NULL;
    sigmatch_table[DETECT_STIX_IPWATCH].RegisterTests = WatchListRegisterTests;
    sigmatch_table[DETECT_STIX_IPWATCH].flags |= SIGMATCH_IPONLY_COMPAT;
}

static int
DetectWatchlistSetup(DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{

    s->msg = "STIX IP Watch List was matched";
    SigMatch *sm = NULL;
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    CreateIpWatchListCtx();
    sm->type = DETECT_STIX_IPWATCH;
    SigMatchAppendSMToList(s, NULL, DETECT_SM_LIST_MATCH);
    return 0;
    error: if (sm != NULL)
        SCFree(sm);
    return -1;

}

int
DetectWatchListMatch(ThreadVars * tv, DetectEngineThreadCtx * de_ctx,
        Packet * p, Signature * s, SigMatch *sm)
{

    uint8_t * src = GET_IPV4_SRC_ADDR_PTR(p);
    char src_type = p->src.family;
    uint8_t * dst = GET_IPV4_DST_ADDR_PTR(p);
    char dst_type = p->dst.family;

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

static void
 WatchListRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("addToWatchList", addToWatchListTest01, 1);
    UtRegisterTest("isInWatchListTest01", isInWatchListTest01, 1);
#endif
}
#ifdef UNITTESTS
int
addToWatchListTest01(void)
{

    int result = 1;
    CreateIpWatchListCtx();

    char* addresses[4];

    addresses[0] = "192.168.0.1";
    addresses[1] = "192.168.0.2";
    addresses[2] = "10.0.0.1";
    addresses[3] = "10.0.0.0/16";

    if (addIpaddressesToWatchList("Test Watch List", addresses,4))
        result = 0;

    CreateIpWatchListCtxFree();
    return result;
}

static int
isInWatchListTest01(void)
{

    int result = 1;
    CreateIpWatchListCtx();

    char* addresses[4];

    addresses[0] = "192.168.0.1";
    addresses[1] = "192.168.0.2";
    addresses[2] = "10.0.0.1";
    addresses[3] = "10.0.0.0/16";

    if (addIpaddressesToWatchList("Test Watch List", addresses, 4))
        result = 0;
    Address* a = SCMalloc(sizeof(Address));
    IpStrToINt(addresses[0], a);

    if (isIPWatched((uint8_t*) a->address.address_un_data32, a->family) != NULL)
        {
            result = 1;

        }
    else
        {
            result = 0;
            goto end;
        }
    IpStrToINt(addresses[3], a);
    if (isIPWatched((uint8_t*)  a->address.address_un_data32, a->family) != NULL)
        {

            WatchListData *d = getWatchListData(addresses[3]);
            if (d->ref_count != 2) {
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

    end: CreateIpWatchListCtxFree();
    return result;
}
#endif
