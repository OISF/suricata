/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

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

#include "app-layer.h"

#include "stream-tcp.h"

#include "detect-filestore.h"

int DetectFilestoreMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);
static int DetectFilestoreSetup (DetectEngineCtx *, Signature *, char *);

/**
 * \brief Registration function for keyword: filestore
 */
void DetectFilestoreRegister(void) {
    sigmatch_table[DETECT_FILESTORE].name = "filestore";
    sigmatch_table[DETECT_FILESTORE].Match = NULL;
    sigmatch_table[DETECT_FILESTORE].AppLayerMatch = DetectFilestoreMatch;
    sigmatch_table[DETECT_FILESTORE].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILESTORE].Setup = DetectFilestoreSetup;
    sigmatch_table[DETECT_FILESTORE].Free  = NULL;
    sigmatch_table[DETECT_FILESTORE].RegisterTests = NULL;

	SCLogDebug("registering filestore rule option");
    return;
}

/**
 * \brief match the specified filestore
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectFilestoreData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectFilestoreMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();
    File *file = (File *)state;
    FileStore(file);
    SCReturnInt(1);
}

/**
 * \brief this function is used to parse filestore options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "filestore" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFilestoreSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    SigMatch *sm = NULL;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FILESTORE;
    sm->ctx = NULL;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_FILEMATCH);

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_HTTP) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    AppLayerHtpNeedFileInspection();

    s->alproto = ALPROTO_HTTP;

    s->init_flags |= SIG_FLAG_FILESTORE;
    return 0;

error:
    if (sm != NULL)
        SCFree(sm);
    return -1;
}
