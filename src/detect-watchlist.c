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

#include "util-ipwatchlist.h"
#include "util-ipwatchlist.h"
#include "host.h"

int
DetectWatchListMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
        Signature *, SigMatch *);
static int
DetectWatchlistSetup(DetectEngineCtx *, Signature *, char *);
void
DetectWatchlistFree(void *);
void
WatchListRegisterTests(void);

void
DetectIPRepRegister(void)
{
    sigmatch_table[DETECT_STIX_IPWATCH].name = "stixip";
    sigmatch_table[DETECT_STIX_IPWATCH].Match = DetectWatchListMatch;
    sigmatch_table[DETECT_STIX_IPWATCH].Setup = DetectWatchlistSetup;
    sigmatch_table[DETECT_STIX_IPWATCH].Free = NULL;
    sigmatch_table[DETECT_STIX_IPWATCH].RegisterTests = NULL; //WatchListRegisterTests;
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

    if (_ipwatchlistCtx == NULL)
        {
            if (unlikely(CreateIpWatchListCtx))
                {
                    goto error;
                }
        }
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
    char src_type = p->src->family;
    uint8_t * dst = GET_IPV4_DST_ADDR_PTR(p);
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

