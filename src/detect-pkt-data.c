/* Copyright (C) 2012 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Xavier Lange <xrlange@gmail.com>
 *
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-pkt-data.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

static int DetectPktDataSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectPktDataTestRegister(void);

/**
 * \brief Registration function for keyword: file_data
 */
void DetectPktDataRegister(void)
{
    sigmatch_table[DETECT_PKT_DATA].name = "pkt_data";
    sigmatch_table[DETECT_PKT_DATA].Match = NULL;
    sigmatch_table[DETECT_PKT_DATA].Setup = DetectPktDataSetup;
    sigmatch_table[DETECT_PKT_DATA].Free  = NULL;
    sigmatch_table[DETECT_PKT_DATA].RegisterTests = DetectPktDataTestRegister;
    sigmatch_table[DETECT_PKT_DATA].flags = SIGMATCH_NOOPT;
}

/**
 * \brief this function is used to parse pkt_data options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "filestore" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectPktDataSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();
    s->init_data->list = DETECT_SM_LIST_NOTSET;

    return 0;
}

#ifdef UNITTESTS

/************************************Unittests*********************************/
static int g_file_data_buffer_id = 0;

static int DetectPktDataTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    SigMatch *sm = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    Signature *sig = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; content:\"in file data\";"
                               " pkt_data; content:\"in pkt data\";)");
    de_ctx->sig_list = sig;
    if (de_ctx->sig_list == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,"could not load test signature");
        goto end;
    }

    /* sm should be in the MATCH list */
    sm = de_ctx->sig_list->sm_lists[g_file_data_buffer_id];
    if (sm == NULL) {
        printf("sm not in g_file_data_buffer_id: ");
        goto end;
    }

    sm = de_ctx->sig_list->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm == NULL) {
        printf("sm not in DETECT_SM_LIST_PMATCH: ");
        goto end;
    }

    if (sm->type != DETECT_CONTENT) {
        printf("sm type not DETECT_AL_HTTP_SERVER_BODY: ");
        goto end;
    }

    if (sm->next != NULL) {
        goto end;
    }


    if (sig->init_data->list != DETECT_SM_LIST_NOTSET) {
        printf("sticky buffer set: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}
#endif

static void DetectPktDataTestRegister(void)
{
#ifdef UNITTESTS
    g_file_data_buffer_id = DetectBufferTypeGetByName("file_data");

    UtRegisterTest("DetectPktDataTest01", DetectPktDataTest01);
#endif
}

