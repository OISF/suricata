/* Multi pattern matcher */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "decode.h"
#include "detect.h"
#include "detect-engine-siggroup.h"
#include "detect-engine-mpm.h"
#include "util-mpm.h"

#include "flow.h"
#include "flow-var.h"
#include "detect-flow.h"

#include "detect-content.h"
#include "detect-uricontent.h"

u_int32_t PacketPatternScan(ThreadVars *t, PatternMatcherThread *pmt, Packet *p) {
    u_int32_t ret;

    ret = pmt->mc->Search(pmt->mc_scan, &pmt->mtc, p->tcp_payload, p->tcp_payload_len);

    //printf("PacketPatternMatch: ret %u\n", ret);
    return ret;
}

u_int32_t PacketPatternMatch(ThreadVars *t, PatternMatcherThread *pmt, Packet *p) {
    u_int32_t ret;

    ret = pmt->mc->Search(pmt->mc, &pmt->mtc, p->tcp_payload, p->tcp_payload_len);

    //printf("PacketPatternMatch: ret %u\n", ret);
    return ret;
}

/* cleans up the mpm instance after a match */
void PacketPatternCleanup(ThreadVars *t, PatternMatcherThread *pmt) {
    /* content */
    if (pmt->mc != NULL && pmt->mc->Cleanup != NULL) {
        pmt->mc->Cleanup(&pmt->mtc);
    }
    /* uricontent */
    if (pmt->mcu != NULL && pmt->mcu->Cleanup != NULL) {
        pmt->mcu->Cleanup(&pmt->mtcu);
    }
}

/* XXX remove this once we got rid of the global mpm_ctx */
void PatternMatchDestroy(MpmCtx *mc) {
    mc->DestroyCtx(mc);
}

/* TODO remove this when we move to the rule groups completely */
void PatternMatchPrepare(MpmCtx *mc)
{
    MpmInitCtx(mc, MPM_WUMANBER);
}


/* free the pattern matcher part of a SigGroupHead */
void PatternMatchDestroyGroup(SigGroupHead *sh) {
    /* content */
    if (sh->flags & SIG_GROUP_HAVECONTENT && sh->mpm_ctx != NULL &&
        !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
        sh->mpm_ctx->DestroyCtx(sh->mpm_ctx);
        free(sh->mpm_ctx);

        /* ready for reuse */
        sh->mpm_ctx = NULL;
        sh->flags &= ~SIG_GROUP_HAVECONTENT;
    }

    /* uricontent */
    if (sh->flags & SIG_GROUP_HAVEURICONTENT && sh->mpm_uri_ctx != NULL &&
        !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
        sh->mpm_uri_ctx->DestroyCtx(sh->mpm_uri_ctx);
        free(sh->mpm_uri_ctx);

        /* ready for reuse */
        sh->mpm_uri_ctx = NULL;
        sh->flags &= ~SIG_GROUP_HAVEURICONTENT;
    }
}

static int g_content_scan = 0;
static int g_uricontent_scan = 0;
static int g_content_search = 0;
static int g_uricontent_search = 0;
static int g_content_maxdepth = 0;
static int g_content_minoffset = 0;
static int g_content_total = 0;

void DbgPrintScanSearchStats() {
#if 0
    printf(": content scan %d, search %d (%02.1f%%) :\n", g_content_scan, g_content_search,
        (float)(g_content_scan/(float)(g_content_scan+g_content_search))*100);
//    printf(": uricontent scan %d, urisearch %d (%02f%%) :\n", g_uricontent_scan, g_uricontent_search,
//        (float)(g_uricontent_scan/(float)(g_uricontent_scan+g_uricontent_search))*100);
    printf(": content maxdepth %d, total %d (%02.1f%%) :\n", g_content_maxdepth, g_content_total,
        (float)(g_content_maxdepth/(float)(g_content_total))*100);
    printf(": content minoffset %d, total %d (%02.1f%%) :\n", g_content_minoffset, g_content_total,
        (float)(g_content_minoffset/(float)(g_content_total))*100);
#endif
}

/*
 *
 * TODO
 *  - determine if a content match can set the 'single' flag
 *
 *
 * XXX do error checking
 * XXX rewrite the COPY stuff
 */
int PatternMatchPrepareGroup(DetectEngineCtx *de_ctx, SigGroupHead *sh)
{
    Signature *s;
    u_int32_t co_cnt = 0;
    u_int32_t ur_cnt = 0;
    u_int32_t cnt = 0;
    u_int32_t sig;

    /* see if this head has content and/or uricontent */
    for (sig = 0; sig < sh->sig_cnt; sig++) {
        u_int32_t num = sh->match_array[sig];

        s = de_ctx->sig_array[num];
        if (s == NULL)
            continue;

        /* find flow setting of this rule */
        SigMatch *sm;

        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT) {
                co_cnt++;
            } else if (sm->type == DETECT_URICONTENT) {
                ur_cnt++;
            }
        }
    }

    if (co_cnt > 0) {
        sh->flags |= SIG_GROUP_HAVECONTENT;
    }
    if (ur_cnt > 0) {
        sh->flags |= SIG_GROUP_HAVEURICONTENT;
    }

    /* intialize contexes */
    if (sh->flags & SIG_GROUP_HAVECONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
        /* search */
        sh->mpm_ctx = malloc(sizeof(MpmCtx));
        if (sh->mpm_ctx == NULL)
            goto error;

        MpmInitCtx(sh->mpm_ctx, MPM_WUMANBER);

        /* scan */
        sh->mpm_scan_ctx = malloc(sizeof(MpmCtx));
        if (sh->mpm_scan_ctx == NULL)
            goto error;

        MpmInitCtx(sh->mpm_scan_ctx, MPM_WUMANBER);
    }
    if (sh->flags & SIG_GROUP_HAVEURICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
        sh->mpm_uri_ctx = malloc(sizeof(MpmCtx));
        if (sh->mpm_uri_ctx == NULL)
            goto error;

        MpmInitCtx(sh->mpm_uri_ctx, MPM_WUMANBER);

        /* scan */
        sh->mpm_uri_scan_ctx = malloc(sizeof(MpmCtx));
        if (sh->mpm_uri_scan_ctx == NULL)
            goto error;

        MpmInitCtx(sh->mpm_uri_scan_ctx, MPM_WUMANBER);
    }

    u_int16_t mpm_content_scan_maxlen = 65535, mpm_uricontent_scan_maxlen = 65535;
    u_int32_t mpm_content_cnt = 0, mpm_uricontent_cnt = 0;
    u_int16_t mpm_content_maxdepth = 65535, mpm_content_minoffset = 65535;
    u_int16_t mpm_content_maxdepth_one = 65535, mpm_content_minoffset_one = 65535;
    int mpm_content_depth_present = -1;
    int mpm_content_offset_present = -1;

    /* for each signature in this group do */
    for (sig = 0; sig < sh->sig_cnt; sig++) {
        u_int32_t num = sh->match_array[sig];

        s = de_ctx->sig_array[num];
        if (s == NULL)
            continue;

        cnt++;

        u_int16_t content_maxlen = 0, uricontent_maxlen = 0;
        u_int16_t content_minlen = 0, uricontent_minlen = 0;
        u_int16_t content_cnt = 0, uricontent_cnt = 0;
        u_int16_t content_maxdepth = 65535;
        u_int16_t content_maxdepth_one = 65535;
        u_int16_t content_minoffset = 65535;
        u_int16_t content_minoffset_one = 65535;
        SigMatch *sm;

        /* determine the length of the longest pattern */
        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
                DetectContentData *cd = (DetectContentData *)sm->ctx;
                if (cd->content_len > content_maxlen)
                    content_maxlen = cd->content_len;

                if (content_minlen == 0) content_minlen = cd->content_len;
                else if (cd->content_len < content_minlen)
                    content_minlen = cd->content_len;

                mpm_content_cnt++;
                content_cnt++;
            } else if (sm->type == DETECT_URICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
                DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;
                if (ud->uricontent_len > uricontent_maxlen)
                    uricontent_maxlen = ud->uricontent_len;

                if (uricontent_minlen == 0) uricontent_minlen = ud->uricontent_len;
                else if (ud->uricontent_len < uricontent_minlen)
                    uricontent_minlen = ud->uricontent_len;

                mpm_uricontent_cnt++;
                uricontent_cnt++;
            }
        }

        /* determine the min offset and max depth of the longest pattern(s) */
        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
                DetectContentData *cd = (DetectContentData *)sm->ctx;
                if (cd->content_len == content_maxlen) {
                    if (content_maxdepth > cd->depth)
                        content_maxdepth = cd->depth;

                    if (content_minoffset > cd->offset)
                        content_minoffset = cd->offset;
                }
            } else if (sm->type == DETECT_URICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
                DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;
                if (ud->uricontent_len == uricontent_maxlen) {
                }
            }
        }

        int content_depth_atleastone = 0;
        int content_offset_atleastone = 0;
        /* determine if we have at least one pattern with a depth */
        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
                DetectContentData *cd = (DetectContentData *)sm->ctx;
                if (cd->depth) {
                    content_depth_atleastone = 1;

                    if (content_maxdepth_one > cd->depth)
                        content_maxdepth_one = cd->depth;
                }
                if (cd->offset) {
                    content_offset_atleastone = 1;

                    if (content_minoffset_one > cd->offset)
                        content_minoffset_one = cd->offset;
                }
            }
        }

        if (mpm_content_depth_present == -1) mpm_content_depth_present = content_depth_atleastone;
        else if (content_depth_atleastone == 0) {
            mpm_content_depth_present = 0;
        }

        if (mpm_content_offset_present == -1) mpm_content_offset_present = content_offset_atleastone;
        else if (content_offset_atleastone == 0) {
            mpm_content_offset_present = 0;
        }

        if (content_maxdepth == 65535)
            content_maxdepth = 0;
        if (content_maxdepth_one == 65535)
            content_maxdepth_one = 0;
        if (content_minoffset == 65535)
            content_minoffset = 0;
        if (content_minoffset_one == 65535)
            content_minoffset_one = 0;

        if (content_maxdepth != 0) {
            //printf("content_maxdepth %u (sid %u)\n", content_maxdepth, s->id);
        }
        if (content_minoffset != 0) {
            //printf("content_minoffset %u (sid %u)\n", content_minoffset, s->id);
        }

        if (mpm_content_maxdepth > content_maxdepth)
            mpm_content_maxdepth = content_maxdepth;
        if (mpm_content_maxdepth_one > content_maxdepth_one)
            mpm_content_maxdepth_one = content_maxdepth_one;
        if (mpm_content_minoffset > content_minoffset)
            mpm_content_minoffset = content_minoffset;
        if (mpm_content_minoffset_one > content_minoffset_one)
            mpm_content_minoffset_one = content_minoffset_one;

        if (content_cnt) {
            if (sh->mpm_content_maxlen == 0) sh->mpm_content_maxlen = content_maxlen;
            if (sh->mpm_content_maxlen > content_maxlen)
                sh->mpm_content_maxlen = content_maxlen;
        }
        if (uricontent_cnt) {
            if (sh->mpm_uricontent_maxlen == 0) sh->mpm_uricontent_maxlen = uricontent_maxlen;
            if (sh->mpm_uricontent_maxlen > uricontent_maxlen)
                sh->mpm_uricontent_maxlen = uricontent_maxlen;
        }
//#if 0
        /* scan ctx */
        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
                DetectContentData *cd = (DetectContentData *)sm->ctx;
                if (sh->mpm_content_maxlen >= cd->content_len) {

                    if (cd->flags & DETECT_CONTENT_NOCASE) {
                        sh->mpm_scan_ctx->AddPatternNocase(sh->mpm_scan_ctx, cd->content, cd->content_len, cd->id);
                    } else {
                        sh->mpm_scan_ctx->AddPattern(sh->mpm_scan_ctx, cd->content, cd->content_len, cd->id);
                    }
                    break; /* just add one per sig,
                            * TODO see if we can select the best one */
                }
            }
        }
        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_URICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
                DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;
                if (sh->mpm_uricontent_maxlen >= ud->uricontent_len) {

                    if (ud->flags & DETECT_URICONTENT_NOCASE) {
                        sh->mpm_uri_scan_ctx->AddPatternNocase(sh->mpm_uri_scan_ctx, ud->uricontent, ud->uricontent_len, ud->id);
                    } else {
                        sh->mpm_uri_scan_ctx->AddPattern(sh->mpm_uri_scan_ctx, ud->uricontent, ud->uricontent_len, ud->id);
                    }
                    break;
                }
            }
        }
//#endif
        /* search ctx */
        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
                DetectContentData *cd = (DetectContentData *)sm->ctx;

                if (cd->flags & DETECT_CONTENT_NOCASE) {
                    sh->mpm_ctx->AddPatternNocase(sh->mpm_ctx, cd->content, cd->content_len, cd->id);
                } else {
                    sh->mpm_ctx->AddPattern(sh->mpm_ctx, cd->content, cd->content_len, cd->id);
                }
            } else if (sm->type == DETECT_URICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
                DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;

                if (ud->flags & DETECT_URICONTENT_NOCASE) {
                    sh->mpm_uri_ctx->AddPatternNocase(sh->mpm_uri_ctx, ud->uricontent, ud->uricontent_len, ud->id);
                } else {
                    sh->mpm_uri_ctx->AddPattern(sh->mpm_uri_ctx, ud->uricontent, ud->uricontent_len, ud->id);
                }
            }
        }
    }

    /* content */
    if (sh->flags & SIG_GROUP_HAVECONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
        /* search ctx */
        if (sh->mpm_ctx->Prepare != NULL) {
            sh->mpm_ctx->Prepare(sh->mpm_ctx);
        }
        /* scan ctx */
        if (sh->mpm_scan_ctx->Prepare != NULL) {
            sh->mpm_scan_ctx->Prepare(sh->mpm_scan_ctx);
        }

        if (mpm_content_cnt && sh->mpm_content_maxlen > 1) {
            //printf("mpm_content_cnt %u, mpm_content_maxlen %d\n", mpm_content_cnt, mpm_content_maxlen);
            g_content_scan++;
        } else {
            g_content_search++;
        }
        //printf("(sh %p) mpm_content_cnt %u, mpm_content_maxlen %u, mpm_content_minlen %u, mpm_content_scan_maxlen %u\n", sh, mpm_content_cnt, mpm_content_maxlen, sh->mpm_content_minlen, mpm_content_scan_maxlen);

        if (mpm_content_maxdepth) {
//            printf("mpm_content_maxdepth %u\n", mpm_content_maxdepth);
            g_content_maxdepth++;
        }
        if (mpm_content_minoffset) {
//            printf("mpm_content_minoffset %u\n", mpm_content_minoffset);
            g_content_minoffset++;
        }
        g_content_total++;

//        if (mpm_content_depth_present) printf("(sh %p) at least one depth: %d, depth %u\n", sh, mpm_content_depth_present, mpm_content_maxdepth_one);
//        if (mpm_content_offset_present) printf("(sh %p) at least one offset: %d, offset %u\n", sh, mpm_content_offset_present, mpm_content_minoffset_one);

        //sh->mpm_ctx->PrintCtx(sh->mpm_ctx);
    }
    /* uricontent */
    if (sh->flags & SIG_GROUP_HAVEURICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
        if (sh->mpm_uri_ctx->Prepare != NULL) {
            sh->mpm_uri_ctx->Prepare(sh->mpm_uri_ctx);
        }
        if (sh->mpm_uri_scan_ctx->Prepare != NULL) {
            sh->mpm_uri_scan_ctx->Prepare(sh->mpm_uri_scan_ctx);
        }
        if (mpm_uricontent_cnt && sh->mpm_uricontent_maxlen > 1) {
//            printf("mpm_uricontent_cnt %u, mpm_uricontent_maxlen %d\n", mpm_uricontent_cnt, mpm_uricontent_maxlen);
            g_uricontent_scan++;
        } else {
            g_uricontent_search++;
        }

        //sh->mpm_uri_ctx->PrintCtx(sh->mpm_uri_ctx);
    }

    return 0;
error:
    /* XXX */
    return -1;
}

int PatternMatcherThreadInit(ThreadVars *t, void **data) {
    PatternMatcherThread *pmt = malloc(sizeof(PatternMatcherThread));
    if (pmt == NULL) {
        return -1;
    }
    memset(pmt, 0, sizeof(PatternMatcherThread));

    /* XXX we still depend on the global mpm_ctx here
     *
     * Initialize the thread pattern match ctx with the max size
     * of the content and uricontent id's so our match lookup
     * table is always big enough
     */
    mpm_ctx[0].InitThreadCtx(&mpm_ctx[0], &pmt->mtc, DetectContentMaxId());
    mpm_ctx[0].InitThreadCtx(&mpm_ctx[0], &pmt->mtcu, DetectUricontentMaxId());

    *data = (void *)pmt;
    //printf("PatternMatcherThreadInit: data %p pmt %p\n", *data, pmt);
    return 0;
}

int PatternMatcherThreadDeinit(ThreadVars *t, void *data) {
    PatternMatcherThread *pmt = (PatternMatcherThread *)data;

    /* XXX */
    mpm_ctx[0].DestroyThreadCtx(&mpm_ctx[0], &pmt->mtc);
    mpm_ctx[0].DestroyThreadCtx(&mpm_ctx[0], &pmt->mtcu);

    return 0;
}


void PatternMatcherThreadInfo(ThreadVars *t, PatternMatcherThread *pmt) {
    /* XXX */
    mpm_ctx[0].PrintThreadCtx(&pmt->mtc);
    mpm_ctx[0].PrintThreadCtx(&pmt->mtcu);
}

