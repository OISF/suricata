/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "conf.h"
#include "conf-yaml-loader.h"

#include "detect-parse.h"
#include "detect-engine-sigorder.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-hcbd.h"
#include "detect-engine-iponly.h"
#include "detect-engine-tag.h"

#include "detect-engine.h"

#include "detect-byte-extract.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-engine-threshold.h"

//#include "util-mpm.h"
#include "util-error.h"
#include "util-hash.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-unittest.h"

#include "util-var-name.h"

#include "tm-threads.h"

#define DETECT_ENGINE_DEFAULT_INSPECTION_RECURSION_LIMIT 3000

static uint8_t DetectEngineCtxLoadConf(DetectEngineCtx *);

DetectEngineCtx *DetectEngineCtxInit(void) {
    DetectEngineCtx *de_ctx;

    ConfNode *seq_node = NULL;
    ConfNode *insp_recursion_limit_node = NULL;
    ConfNode *de_engine_node = NULL;
    char *insp_recursion_limit = NULL;

    de_ctx = SCMalloc(sizeof(DetectEngineCtx));
    if (de_ctx == NULL)
        goto error;

    memset(de_ctx,0,sizeof(DetectEngineCtx));

    if (ConfGetBool("engine.init_failure_fatal", (int *)&(de_ctx->failure_fatal)) != 1) {
        SCLogDebug("ConfGetBool could not load the value.");
    }

    de_engine_node = ConfGetNode("detect-engine");
    if (de_engine_node != NULL) {
        TAILQ_FOREACH(seq_node, &de_engine_node->head, next) {
            if (strcmp(seq_node->val, "inspection-recursion-limit") != 0)
                continue;

            insp_recursion_limit_node = ConfNodeLookupChild(seq_node, seq_node->val);
            if (insp_recursion_limit_node == NULL) {
                SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Error retrieving conf "
                           "entry for detect-engine:inspection-recursion-limit");
                break;
            }
            insp_recursion_limit = insp_recursion_limit_node->val;
            SCLogDebug("Found detect-engine:inspection-recursion-limit - %s:%s",
                       insp_recursion_limit_node->name, insp_recursion_limit_node->val);

            break;
        }
    }

    if (insp_recursion_limit != NULL) {
        de_ctx->inspection_recursion_limit = atoi(insp_recursion_limit);
    } else {
        de_ctx->inspection_recursion_limit =
            DETECT_ENGINE_DEFAULT_INSPECTION_RECURSION_LIMIT;
    }

    if (de_ctx->inspection_recursion_limit == 0)
        de_ctx->inspection_recursion_limit = -1;

    SCLogDebug("de_ctx->inspection_recursion_limit: %d",
               de_ctx->inspection_recursion_limit);

    de_ctx->mpm_matcher = PatternMatchDefaultMatcher();
    DetectEngineCtxLoadConf(de_ctx);

    SigGroupHeadHashInit(de_ctx);
    SigGroupHeadMpmHashInit(de_ctx);
    SigGroupHeadMpmUriHashInit(de_ctx);
    SigGroupHeadSPortHashInit(de_ctx);
    SigGroupHeadDPortHashInit(de_ctx);
    DetectPortSpHashInit(de_ctx);
    DetectPortDpHashInit(de_ctx);
    ThresholdHashInit(de_ctx);
    VariableNameInitHash();
    DetectParseDupSigHashInit(de_ctx);

    de_ctx->mpm_pattern_id_store = MpmPatternIdTableInitHash();
    if (de_ctx->mpm_pattern_id_store == NULL) {
        goto error;
    }

    return de_ctx;
error:
    return NULL;
}

void DetectEngineCtxFree(DetectEngineCtx *de_ctx) {

    if (de_ctx == NULL)
        return;


    /* Normally the hashes are freed elsewhere, but
     * to be sure look at them again here.
     */
    MpmPatternIdTableFreeHash(de_ctx->mpm_pattern_id_store); /* normally cleaned up in SigGroupBuild */

    SigGroupHeadHashFree(de_ctx);
    SigGroupHeadMpmHashFree(de_ctx);
    SigGroupHeadMpmUriHashFree(de_ctx);
    SigGroupHeadSPortHashFree(de_ctx);
    SigGroupHeadDPortHashFree(de_ctx);
    DetectParseDupSigHashFree(de_ctx);
    SCSigSignatureOrderingModuleCleanup(de_ctx);
    DetectPortSpHashFree(de_ctx);
    DetectPortDpHashFree(de_ctx);
    ThresholdContextDestroy(de_ctx);
    SigCleanSignatures(de_ctx);

    VariableNameFreeHash();
    if (de_ctx->sig_array)
        SCFree(de_ctx->sig_array);

    if (de_ctx->class_conf_ht != NULL)
        HashTableFree(de_ctx->class_conf_ht);
    SCFree(de_ctx);
    //DetectAddressGroupPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();
}

/** \brief  Function that load DetectEngineCtx config for grouping sigs
 *          used by the engine
 *  \retval 0 if no config provided, 1 if config was provided
 *          and loaded successfuly
 */
static uint8_t DetectEngineCtxLoadConf(DetectEngineCtx *de_ctx) {
    uint8_t profile = ENGINE_PROFILE_UNKNOWN;
    char *de_ctx_profile = NULL;

    const char *max_uniq_toclient_src_groups_str = NULL;
    const char *max_uniq_toclient_dst_groups_str = NULL;
    const char *max_uniq_toclient_sp_groups_str = NULL;
    const char *max_uniq_toclient_dp_groups_str = NULL;

    const char *max_uniq_toserver_src_groups_str = NULL;
    const char *max_uniq_toserver_dst_groups_str = NULL;
    const char *max_uniq_toserver_sp_groups_str = NULL;
    const char *max_uniq_toserver_dp_groups_str = NULL;

    char *sgh_mpm_context = NULL;

    ConfNode *de_ctx_custom = ConfGetNode("detect-engine");
    ConfNode *opt = NULL;

    if (de_ctx_custom != NULL) {
        TAILQ_FOREACH(opt, &de_ctx_custom->head, next) {
            if (strncmp(opt->val, "profile", 3) == 0) {
                de_ctx_profile = opt->head.tqh_first->val;
            } else if (strcmp(opt->val, "sgh-mpm-context") == 0) {
                sgh_mpm_context = opt->head.tqh_first->val;
            }
        }
    }

    if (de_ctx_profile != NULL) {
        if (strncmp(de_ctx_profile, "low", 3) == 0) {
            profile = ENGINE_PROFILE_LOW;
        } else if (strncmp(de_ctx_profile, "medium", 6) == 0) {
            profile = ENGINE_PROFILE_MEDIUM;
        } else if (strncmp(de_ctx_profile, "high", 4) == 0) {
            profile = ENGINE_PROFILE_HIGH;
        } else if (strncmp(de_ctx_profile, "custom", 4) == 0) {
            profile = ENGINE_PROFILE_CUSTOM;
        }

        SCLogDebug("Profile for detection engine groups is \"%s\"", de_ctx_profile);
    } else {
        SCLogDebug("Profile for detection engine groups not provided "
                   "at suricata.yaml. Using default (\"medium\").");
    }

    /* detect-engine.sgh-mpm-context option parsing */
    if (sgh_mpm_context == NULL || strcmp(sgh_mpm_context, "auto") == 0) {
        /* for now, since we still haven't implemented any intelligence into
         * understanding the patterns and distributing mpm_ctx across sgh */
        if (de_ctx->mpm_matcher == MPM_AC || de_ctx->mpm_matcher == MPM_AC_GFBS)
            de_ctx->sgh_mpm_context = ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE;
        else
            de_ctx->sgh_mpm_context = ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL;
    } else {
        if (strcmp(sgh_mpm_context, "single") == 0) {
            de_ctx->sgh_mpm_context = ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE;
        } else if (strcmp(sgh_mpm_context, "full") == 0) {
            de_ctx->sgh_mpm_context = ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL;
        } else {
           SCLogWarning(SC_ERR_INVALID_YAML_CONF_ENTRY, "You have supplied an "
                        "invalid conf value for detect-engine.sgh-mpm-context-"
                        "%s", sgh_mpm_context);
        }
    }

    opt = NULL;
    switch (profile) {
        case ENGINE_PROFILE_LOW:
            de_ctx->max_uniq_toclient_src_groups = 2;
            de_ctx->max_uniq_toclient_dst_groups = 2;
            de_ctx->max_uniq_toclient_sp_groups = 2;
            de_ctx->max_uniq_toclient_dp_groups = 3;
            de_ctx->max_uniq_toserver_src_groups = 2;
            de_ctx->max_uniq_toserver_dst_groups = 2;
            de_ctx->max_uniq_toserver_sp_groups = 2;
            de_ctx->max_uniq_toserver_dp_groups = 3;
            break;

        case ENGINE_PROFILE_HIGH:
            de_ctx->max_uniq_toclient_src_groups = 15;
            de_ctx->max_uniq_toclient_dst_groups = 15;
            de_ctx->max_uniq_toclient_sp_groups = 15;
            de_ctx->max_uniq_toclient_dp_groups = 20;
            de_ctx->max_uniq_toserver_src_groups = 15;
            de_ctx->max_uniq_toserver_dst_groups = 15;
            de_ctx->max_uniq_toserver_sp_groups = 15;
            de_ctx->max_uniq_toserver_dp_groups = 40;
            break;

        case ENGINE_PROFILE_CUSTOM:
            TAILQ_FOREACH(opt, &de_ctx_custom->head, next) {
                if (strncmp(opt->val, "custom-values", 3) == 0) {
                    max_uniq_toclient_src_groups_str = ConfNodeLookupChildValue
                            (opt->head.tqh_first, "toclient_src_groups");
                    max_uniq_toclient_dst_groups_str = ConfNodeLookupChildValue
                            (opt->head.tqh_first, "toclient_dst_groups");
                    max_uniq_toclient_sp_groups_str = ConfNodeLookupChildValue
                            (opt->head.tqh_first, "toclient_sp_groups");
                    max_uniq_toclient_dp_groups_str = ConfNodeLookupChildValue
                            (opt->head.tqh_first, "toclient_dp_groups");
                    max_uniq_toserver_src_groups_str = ConfNodeLookupChildValue
                            (opt->head.tqh_first, "toserver_src_groups");
                    max_uniq_toserver_dst_groups_str = ConfNodeLookupChildValue
                            (opt->head.tqh_first, "toserver_dst_groups");
                    max_uniq_toserver_sp_groups_str = ConfNodeLookupChildValue
                            (opt->head.tqh_first, "toserver_sp_groups");
                    max_uniq_toserver_dp_groups_str = ConfNodeLookupChildValue
                            (opt->head.tqh_first, "toserver_dp_groups");
                }
            }
            if (max_uniq_toclient_src_groups_str != NULL) {
                if (ByteExtractStringUint16(&de_ctx->max_uniq_toclient_src_groups, 10,
                    strlen(max_uniq_toclient_src_groups_str),
                    (const char *)max_uniq_toclient_src_groups_str) <= 0)
                        de_ctx->max_uniq_toclient_src_groups = 2;
            } else {
                de_ctx->max_uniq_toclient_src_groups = 2;
            }
            if (max_uniq_toclient_dst_groups_str != NULL) {
                if (ByteExtractStringUint16(&de_ctx->max_uniq_toclient_dst_groups, 10,
                    strlen(max_uniq_toclient_dst_groups_str),
                    (const char *)max_uniq_toclient_dst_groups_str) <= 0)
                        de_ctx->max_uniq_toclient_dst_groups = 2;
            } else {
                de_ctx->max_uniq_toclient_dst_groups = 2;
            }
            if (max_uniq_toclient_sp_groups_str != NULL) {
                if (ByteExtractStringUint16(&de_ctx->max_uniq_toclient_sp_groups, 10,
                    strlen(max_uniq_toclient_sp_groups_str),
                    (const char *)max_uniq_toclient_sp_groups_str) <= 0)
                        de_ctx->max_uniq_toclient_sp_groups = 2;
            } else {
                de_ctx->max_uniq_toclient_sp_groups = 2;
            }
            if (max_uniq_toclient_dp_groups_str != NULL) {
                if (ByteExtractStringUint16(&de_ctx->max_uniq_toclient_dp_groups, 10,
                    strlen(max_uniq_toclient_dp_groups_str),
                    (const char *)max_uniq_toclient_dp_groups_str) <= 0)
                        de_ctx->max_uniq_toclient_dp_groups = 2;
            } else {
                de_ctx->max_uniq_toclient_dp_groups = 2;
            }
            if (max_uniq_toserver_src_groups_str != NULL) {
                if (ByteExtractStringUint16(&de_ctx->max_uniq_toserver_src_groups, 10,
                    strlen(max_uniq_toserver_src_groups_str),
                    (const char *)max_uniq_toserver_src_groups_str) <= 0)
                        de_ctx->max_uniq_toserver_src_groups = 2;
            } else {
                de_ctx->max_uniq_toserver_src_groups = 2;
            }
            if (max_uniq_toserver_dst_groups_str != NULL) {
                if (ByteExtractStringUint16(&de_ctx->max_uniq_toserver_dst_groups, 10,
                    strlen(max_uniq_toserver_dst_groups_str),
                    (const char *)max_uniq_toserver_dst_groups_str) <= 0)
                        de_ctx->max_uniq_toserver_dst_groups = 2;
            } else {
                de_ctx->max_uniq_toserver_dst_groups = 2;
            }
            if (max_uniq_toserver_sp_groups_str != NULL) {
                if (ByteExtractStringUint16(&de_ctx->max_uniq_toserver_sp_groups, 10,
                    strlen(max_uniq_toserver_sp_groups_str),
                    (const char *)max_uniq_toserver_sp_groups_str) <= 0)
                        de_ctx->max_uniq_toserver_sp_groups = 2;
            } else {
                de_ctx->max_uniq_toserver_sp_groups = 2;
            }
            if (max_uniq_toserver_dp_groups_str != NULL) {
                if (ByteExtractStringUint16(&de_ctx->max_uniq_toserver_dp_groups, 10,
                    strlen(max_uniq_toserver_dp_groups_str),
                    (const char *)max_uniq_toserver_dp_groups_str) <= 0)
                        de_ctx->max_uniq_toserver_dp_groups = 2;
            } else {
                de_ctx->max_uniq_toserver_dp_groups = 2;
            }
            break;

        /* Default (or no config provided) is profile medium */
        case ENGINE_PROFILE_MEDIUM:
        case ENGINE_PROFILE_UNKNOWN:
        default:
            de_ctx->max_uniq_toclient_src_groups = 4;
            de_ctx->max_uniq_toclient_dst_groups = 4;
            de_ctx->max_uniq_toclient_sp_groups = 4;
            de_ctx->max_uniq_toclient_dp_groups = 6;

            de_ctx->max_uniq_toserver_src_groups = 4;
            de_ctx->max_uniq_toserver_dst_groups = 8;
            de_ctx->max_uniq_toserver_sp_groups = 4;
            de_ctx->max_uniq_toserver_dp_groups = 30;
            break;
    }

    if (profile == ENGINE_PROFILE_UNKNOWN)
        return 0;
    return 1;
}

/*
 * getting & (re)setting the internal sig i
 */

//inline uint32_t DetectEngineGetMaxSigId(DetectEngineCtx *de_ctx) {
//    return de_ctx->signum;
//}

void DetectEngineResetMaxSigId(DetectEngineCtx *de_ctx) {
    de_ctx->signum = 0;
}

TmEcode DetectEngineThreadCtxInit(ThreadVars *tv, void *initdata, void **data) {
    DetectEngineCtx *de_ctx = (DetectEngineCtx *)initdata;
    if (de_ctx == NULL)
        return TM_ECODE_FAILED;

    DetectEngineThreadCtx *det_ctx = SCMalloc(sizeof(DetectEngineThreadCtx));
    if (det_ctx == NULL)
        return TM_ECODE_FAILED;
    memset(det_ctx, 0, sizeof(DetectEngineThreadCtx));

    det_ctx->de_ctx = de_ctx;

    /** \todo we still depend on the global mpm_ctx here
     *
     * Initialize the thread pattern match ctx with the max size
     * of the content and uricontent id's so our match lookup
     * table is always big enough
     */
    PatternMatchThreadPrepare(&det_ctx->mtc, de_ctx->mpm_matcher, DetectContentMaxId(de_ctx));
    PatternMatchThreadPrepare(&det_ctx->mtcs, de_ctx->mpm_matcher, DetectContentMaxId(de_ctx));
    PatternMatchThreadPrepare(&det_ctx->mtcu, de_ctx->mpm_matcher, DetectUricontentMaxId(de_ctx));

    //PmqSetup(&det_ctx->pmq, DetectEngineGetMaxSigId(de_ctx), DetectContentMaxId(de_ctx));
    PmqSetup(&det_ctx->pmq, 0, DetectContentMaxId(de_ctx));
    int i;
    for (i = 0; i < 256; i++) {
        PmqSetup(&det_ctx->smsg_pmq[i], 0, DetectContentMaxId(de_ctx));
    }

    /* IP-ONLY */
    DetectEngineIPOnlyThreadInit(de_ctx,&det_ctx->io_ctx);

    /* DeState */
    if (de_ctx->sig_array_len > 0) {
        det_ctx->de_state_sig_array_len = de_ctx->sig_array_len;
        det_ctx->de_state_sig_array = SCMalloc(det_ctx->de_state_sig_array_len * sizeof(uint8_t));
        if (det_ctx->de_state_sig_array == NULL) {
            return TM_ECODE_FAILED;
        }
        memset(det_ctx->de_state_sig_array, 0,
               det_ctx->de_state_sig_array_len * sizeof(uint8_t));

        det_ctx->match_array_len = de_ctx->sig_array_len;
        det_ctx->match_array = SCMalloc(det_ctx->match_array_len * sizeof(Signature *));
        if (det_ctx->match_array == NULL) {
            return TM_ECODE_FAILED;
        }
        memset(det_ctx->match_array, 0,
               det_ctx->match_array_len * sizeof(Signature *));
    }

    /** alert counter setup */
    det_ctx->counter_alerts = SCPerfTVRegisterCounter("detect.alert", tv,
                                                      SC_PERF_TYPE_UINT64, "NULL");
    tv->sc_perf_pca = SCPerfGetAllCountersArray(&tv->sc_perf_pctx);
    SCPerfAddToClubbedTMTable((tv->thread_group_name != NULL) ? tv->thread_group_name : tv->name,
                              &tv->sc_perf_pctx);

    /* this detection engine context belongs to this thread instance */
    det_ctx->tv = tv;

    det_ctx->bj_values = SCMalloc(sizeof(*det_ctx->bj_values) * byte_extract_max_local_id);
    if (det_ctx->bj_values == NULL) {
        return TM_ECODE_FAILED;
    }

    *data = (void *)det_ctx;

    return TM_ECODE_OK;
}

TmEcode DetectEngineThreadCtxDeinit(ThreadVars *tv, void *data) {
    DetectEngineThreadCtx *det_ctx = (DetectEngineThreadCtx *)data;

    if (det_ctx == NULL) {
        SCLogWarning(SC_ERR_INVALID_ARGUMENTS, "argument \"data\" NULL");
        return TM_ECODE_OK;
    }

    DetectEngineIPOnlyThreadDeinit(&det_ctx->io_ctx);

    /** \todo get rid of this static */
    PatternMatchThreadDestroy(&det_ctx->mtc, det_ctx->de_ctx->mpm_matcher);
    PatternMatchThreadDestroy(&det_ctx->mtcu, det_ctx->de_ctx->mpm_matcher);

    PmqFree(&det_ctx->pmq);
    int i;
    for (i = 0; i < 256; i++) {
        PmqFree(&det_ctx->smsg_pmq[i]);
    }

    if (det_ctx->de_state_sig_array != NULL)
        SCFree(det_ctx->de_state_sig_array);

    if (det_ctx->bj_values != NULL)
        SCFree(det_ctx->bj_values);

    SCFree(det_ctx);

    return TM_ECODE_OK;
}

void DetectEngineThreadCtxInfo(ThreadVars *t, DetectEngineThreadCtx *det_ctx) {
    /* XXX */
    PatternMatchThreadPrint(&det_ctx->mtc, det_ctx->de_ctx->mpm_matcher);
    PatternMatchThreadPrint(&det_ctx->mtcu, det_ctx->de_ctx->mpm_matcher);
}

/*************************************Unittest*********************************/

#ifdef UNITTESTS

static int DetectEngineInitYamlConf(char *conf)
{
    ConfCreateContextBackup();
    ConfInit();
    return ConfYamlLoadString(conf, strlen(conf));
}

static void DetectEngineDeInitYamlConf(void)
{
    ConfDeInit();
    ConfRestoreContextBackup();

    return;
}

static int DetectEngineTest01(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: medium\n"
        "  - custom-values:\n"
        "      toclient_src_groups: 2\n"
        "      toclient_dst_groups: 2\n"
        "      toclient_sp_groups: 2\n"
        "      toclient_dp_groups: 3\n"
        "      toserver_src_groups: 2\n"
        "      toserver_dst_groups: 4\n"
        "      toserver_sp_groups: 2\n"
        "      toserver_dp_groups: 25\n"
        "  - inspection-recursion-limit: 0\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (DetectEngineInitYamlConf(conf) == -1)
        return 0;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    result = (de_ctx->inspection_recursion_limit == -1);

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    return result;
}

static int DetectEngineTest02(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: medium\n"
        "  - custom-values:\n"
        "      toclient_src_groups: 2\n"
        "      toclient_dst_groups: 2\n"
        "      toclient_sp_groups: 2\n"
        "      toclient_dp_groups: 3\n"
        "      toserver_src_groups: 2\n"
        "      toserver_dst_groups: 4\n"
        "      toserver_sp_groups: 2\n"
        "      toserver_dp_groups: 25\n"
        "  - inspection-recursion-limit:\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (DetectEngineInitYamlConf(conf) == -1)
        return 0;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    result = (de_ctx->inspection_recursion_limit == -1);

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    return result;
}

static int DetectEngineTest03(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: medium\n"
        "  - custom-values:\n"
        "      toclient_src_groups: 2\n"
        "      toclient_dst_groups: 2\n"
        "      toclient_sp_groups: 2\n"
        "      toclient_dp_groups: 3\n"
        "      toserver_src_groups: 2\n"
        "      toserver_dst_groups: 4\n"
        "      toserver_sp_groups: 2\n"
        "      toserver_dp_groups: 25\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (DetectEngineInitYamlConf(conf) == -1)
        return 0;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    result = (de_ctx->inspection_recursion_limit ==
              DETECT_ENGINE_DEFAULT_INSPECTION_RECURSION_LIMIT);

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    return result;
}

static int DetectEngineTest04(void)
{
    char *conf =
        "%YAML 1.1\n"
        "---\n"
        "detect-engine:\n"
        "  - profile: medium\n"
        "  - custom-values:\n"
        "      toclient_src_groups: 2\n"
        "      toclient_dst_groups: 2\n"
        "      toclient_sp_groups: 2\n"
        "      toclient_dp_groups: 3\n"
        "      toserver_src_groups: 2\n"
        "      toserver_dst_groups: 4\n"
        "      toserver_sp_groups: 2\n"
        "      toserver_dp_groups: 25\n"
        "  - inspection-recursion-limit: 10\n";

    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    if (DetectEngineInitYamlConf(conf) == -1)
        return 0;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    result = (de_ctx->inspection_recursion_limit == 10);

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    DetectEngineDeInitYamlConf();

    return result;
}

#endif

void DetectEngineRegisterTests()
{

#ifdef UNITTESTS
    UtRegisterTest("DetectEngineTest01", DetectEngineTest01, 1);
    UtRegisterTest("DetectEngineTest02", DetectEngineTest02, 1);
    UtRegisterTest("DetectEngineTest03", DetectEngineTest03, 1);
    UtRegisterTest("DetectEngineTest04", DetectEngineTest04, 1);
#endif

    return;
}
