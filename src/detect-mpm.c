/* Multi pattern matcher */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "decode.h"
#include "detect.h"

#include "detect-mpm.h"
#include "util-mpm.h"

#include "flow.h"
#include "flow-var.h"
#include "detect-flow.h"

#include "detect-content.h"
#include "detect-uricontent.h"

MpmCtx mpm_ctx[MPM_INSTANCE_MAX];

u_int32_t PacketPatternMatch(ThreadVars *t, PatternMatcherThread *pmt, Packet *p) {
    u_int32_t ret;

    ret = mpm_ctx[pmt->mpm_instance].Search(&mpm_ctx[pmt->mpm_instance], &pmt->mpm_ctx[pmt->mpm_instance], p->tcp_payload, p->tcp_payload_len);

    //printf("PacketPatternMatch: ret %u\n", ret);
    return ret;
}

/* cleans up the mpm instance after a match */
void PacketPatternCleanup(ThreadVars *t, PatternMatcherThread *pmt, u_int8_t instance) {
    if (mpm_ctx[pmt->mpm_instance].Cleanup != NULL) {
        mpm_ctx[pmt->mpm_instance].Cleanup(&pmt->mpm_ctx[instance]);
    }
}

void PatternMatchDestroy(void) {
    u_int8_t instance;

    /* intialize contexes */
    for (instance = 0; instance < MPM_INSTANCE_MAX; instance++) {
        mpm_ctx[instance].DestroyCtx(&mpm_ctx[instance]);
    }
}

/*
 *
 * TODO
 *  - determine if a content match can set the 'single' flag
 *
 *
 */
void PatternMatchPrepare(Signature *rootsig)
{
    Signature *s;
    u_int8_t instance = 0;

    u_int32_t id = 0;
    u_int32_t depth = 0;
    u_int32_t offset = 0;
    u_int32_t within = 0;
    u_int32_t distance = 0;
    u_int32_t keywords = 0;

    u_int32_t uri_id = 0;
    u_int32_t uri_depth = 0;
    u_int32_t uri_offset = 0;
    u_int32_t uri_within = 0;
    u_int32_t uri_distance = 0;
    u_int32_t uri_keywords = 0;

    /* intialize contexes */
    for (instance = 0; instance < MPM_INSTANCE_MAX; instance++) {
        MpmInitCtx(&mpm_ctx[instance], MPM_WUMANBER);
    }

    for (s = rootsig; s != NULL; s = s->next) {
        instance = MPM_INSTANCE_BOTH;

        SigMatch *sm;
        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_FLOW) {
                DetectFlowData *fd = (DetectFlowData *)sm->ctx;
                if (fd->flags & FLOW_PKT_TOSERVER)
                    instance = MPM_INSTANCE_TOSERVER;
                else if (fd->flags & FLOW_PKT_TOCLIENT)
                    instance = MPM_INSTANCE_TOCLIENT;

                break;
            }
        }
        //printf("Add sig %u to instance %u\n", s->id, instance);

        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT) {
                DetectContentData *cd = (DetectContentData *)sm->ctx;

                if (cd->depth) depth++;
                if (cd->offset) offset++;
                if (cd->within) within++;
                if (cd->distance) distance++;

                if (instance == MPM_INSTANCE_BOTH) { /* no flow setting in rule */
                    if (cd->flags & DETECT_CONTENT_NOCASE) {
                        mpm_ctx[MPM_INSTANCE_TOSERVER].AddPatternNocase(&mpm_ctx[MPM_INSTANCE_TOSERVER], cd->content, cd->content_len, id);
                        mpm_ctx[MPM_INSTANCE_TOCLIENT].AddPatternNocase(&mpm_ctx[MPM_INSTANCE_TOCLIENT], cd->content, cd->content_len, id);
                    } else {
                        mpm_ctx[MPM_INSTANCE_TOSERVER].AddPattern(&mpm_ctx[MPM_INSTANCE_TOSERVER], cd->content, cd->content_len, id);
                        mpm_ctx[MPM_INSTANCE_TOCLIENT].AddPattern(&mpm_ctx[MPM_INSTANCE_TOCLIENT], cd->content, cd->content_len, id);
                    }
                } else {
                    if (cd->flags & DETECT_CONTENT_NOCASE) {
                        mpm_ctx[instance].AddPatternNocase(&mpm_ctx[instance], cd->content, cd->content_len, id);
                    } else {
                        mpm_ctx[instance].AddPattern(&mpm_ctx[instance], cd->content, cd->content_len, id);
                    }
                }

                cd->id = id;

                id++;
                keywords++;
            } else if (sm->type == DETECT_URICONTENT) {
                DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;

                if (ud->depth) uri_depth++;
                if (ud->offset) uri_offset++;
                if (ud->within) uri_within++;
                if (ud->distance) uri_distance++;

                if (instance == MPM_INSTANCE_BOTH) { /* no flow setting in rule */
                    if (ud->flags & DETECT_URICONTENT_NOCASE) {
                        mpm_ctx[MPM_INSTANCE_TOSERVER + MPM_INSTANCE_URIOFFSET].AddPatternNocase(&mpm_ctx[MPM_INSTANCE_TOSERVER + MPM_INSTANCE_URIOFFSET], ud->uricontent, ud->uricontent_len, uri_id);
                        mpm_ctx[MPM_INSTANCE_TOCLIENT + MPM_INSTANCE_URIOFFSET].AddPatternNocase(&mpm_ctx[MPM_INSTANCE_TOCLIENT + MPM_INSTANCE_URIOFFSET], ud->uricontent, ud->uricontent_len, uri_id);
                    } else {
                        mpm_ctx[MPM_INSTANCE_TOSERVER + MPM_INSTANCE_URIOFFSET].AddPattern(&mpm_ctx[MPM_INSTANCE_TOSERVER + MPM_INSTANCE_URIOFFSET], ud->uricontent, ud->uricontent_len, uri_id);
                        mpm_ctx[MPM_INSTANCE_TOCLIENT + MPM_INSTANCE_URIOFFSET].AddPattern(&mpm_ctx[MPM_INSTANCE_TOCLIENT + MPM_INSTANCE_URIOFFSET], ud->uricontent, ud->uricontent_len, uri_id);
                    }
                } else {
                    if (ud->flags & DETECT_URICONTENT_NOCASE) {
                        mpm_ctx[instance + MPM_INSTANCE_URIOFFSET].AddPatternNocase(&mpm_ctx[instance + MPM_INSTANCE_URIOFFSET], ud->uricontent, ud->uricontent_len, uri_id);
                    } else {
                        mpm_ctx[instance + MPM_INSTANCE_URIOFFSET].AddPattern(&mpm_ctx[instance + MPM_INSTANCE_URIOFFSET], ud->uricontent, ud->uricontent_len, uri_id);
                    }
                }

                ud->id = uri_id;

                uri_id++;
                uri_keywords++;
            }
        }
    }

    for (instance = 0; instance < MPM_INSTANCE_MAX; instance++) {
        if (mpm_ctx[instance].Prepare != NULL) {
            mpm_ctx[instance].Prepare(&mpm_ctx[instance]);
        }
    }

    //printf("Printing info...\n");
    //for (instance = 0; instance < MPM_INSTANCE_MAX; instance++) {
    //    mpm_ctx[instance].PrintCtx(&mpm_ctx[instance]);
    //}

#ifdef DEBUG
    for (instance = 0; instance < MPM_INSTANCE_MAX; instance++) {
        printf("Case sensitive:\n");
        MpmPrintTree(&mpm_ctx[instance].root);
        printf("Case INsensitive:\n");
        MpmPrintTree(&mpm_ctx[instance].nocase_root);
    }
#endif /* DEBUG */
}

int PatternMatcherThreadInit(ThreadVars *t, void **data) {
    u_int8_t mpm_instance = 0;

    PatternMatcherThread *pmt = malloc(sizeof(PatternMatcherThread));
    if (pmt == NULL) {
        return -1;
    }
    memset(pmt, 0, sizeof(PatternMatcherThread));

    /* intialize contexes */
    for (mpm_instance = 0; mpm_instance < MPM_INSTANCE_MAX; mpm_instance++) {
        mpm_ctx[mpm_instance].InitThreadCtx(&mpm_ctx[mpm_instance], &pmt->mpm_ctx[mpm_instance]);
    }

    *data = (void *)pmt;
    //printf("PatternMatcherThreadInit: data %p pmt %p\n", *data, pmt);
    return 0;
}

int PatternMatcherThreadDeinit(ThreadVars *t, void *data) {
    PatternMatcherThread *pmt = (PatternMatcherThread *)data;
    u_int8_t instance;

    /* intialize contexes */
    for (instance = 0; instance < MPM_INSTANCE_MAX; instance++) {
        mpm_ctx[instance].DestroyThreadCtx(&mpm_ctx[instance], &pmt->mpm_ctx[instance]);
    }

    return 0;
}


void PatternMatcherThreadInfo(ThreadVars *t, PatternMatcherThread *pmt) {
    u_int8_t mpm_instance = 0;

    /* intialize contexes */
    for (mpm_instance = 0; mpm_instance < MPM_INSTANCE_MAX; mpm_instance++) {
        mpm_ctx[mpm_instance].PrintThreadCtx(&pmt->mpm_ctx[mpm_instance]);
    }
}

