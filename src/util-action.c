/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 */

#include "suricata-common.h"

#include "action-globals.h"
#include "conf.h"
#include "conf-yaml-loader.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-sigorder.h"

#include "util-unittest.h"
#include "util-action.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

/* Default order: */
uint8_t action_order_sigs[4] = {ACTION_PASS, ACTION_DROP, ACTION_REJECT, ACTION_ALERT};
/* This order can be changed from config */

/**
 * \brief Return the priority associated to an action (to order sigs
 *        as specified at config)
 *        action_order_sigs has this priority by index val
 *        so action_order_sigs[0] has to be inspected first.
 *        This function is called from detect-engine-sigorder
 * \param action can be one of ACTION_PASS, ACTION_DROP,
 *        ACTION_REJECT or ACTION_ALERT
 * \retval uint8_t the priority (order of this actions)
 */
uint8_t ActionOrderVal(uint8_t action)
{
    /* reject_both and reject_dst have the same prio as reject */
    if( (action & ACTION_REJECT) ||
        (action & ACTION_REJECT_BOTH) ||
        (action & ACTION_REJECT_DST)) {
        action = ACTION_REJECT;
    }
    uint8_t i = 0;
    for (; i < 4; i++) {
        if (action_order_sigs[i] == action)
            return i;
    }
    /* Unknown action, set just a low prio (high val) */
    return 10;
}

/**
 * \brief Return the ACTION_* bit from their ascii value
 * \param action can be one of "pass", "drop",
 *        "reject" or "alert"
 * \retval uint8_t can be one of ACTION_PASS, ACTION_DROP,
 *        ACTION_REJECT or ACTION_ALERT
 */
static uint8_t ActionAsciiToFlag(const char *action)
{
    if (strcmp(action,"pass") == 0)
        return ACTION_PASS;
    if (strcmp(action,"drop") == 0)
        return ACTION_DROP;
    if (strcmp(action,"reject") == 0)
        return ACTION_REJECT;
    if (strcmp(action,"alert") == 0)
        return ACTION_ALERT;

    return 0;
}

/**
 * \brief Load the action order from config. If none is provided,
 *        it will be default to ACTION_PASS, ACTION_DROP,
 *        ACTION_REJECT, ACTION_ALERT (pass has the highest prio)
 *
 * \retval 0 on success; -1 on fatal error;
 */
int ActionInitConfig()
{
    uint8_t actions_used = 0;
    uint8_t action_flag = 0;
    uint8_t actions_config[4] = {0, 0, 0, 0};
    int order = 0;

    ConfNode *action_order;
    ConfNode *action = NULL;

    /* Let's load the order of actions from the general config */
    action_order = ConfGetNode("action-order");
    if (action_order == NULL) {
        /* No configuration, use defaults. */
        return 0;
    }
    else {
        TAILQ_FOREACH(action, &action_order->head, next) {
            SCLogDebug("Loading action order : %s", action->val);
            action_flag = ActionAsciiToFlag(action->val);
            if (action_flag == 0) {
                SCLogError(SC_ERR_ACTION_ORDER, "action-order, invalid action: \"%s\". Please, use"
                       " \"pass\",\"drop\",\"alert\",\"reject\". You have"
                       " to specify all of them, without quotes and without"
                       " capital letters", action->val);
                goto error;
            }

            if (actions_used & action_flag) {
                SCLogError(SC_ERR_ACTION_ORDER, "action-order, action already set: \"%s\". Please,"
                       " use \"pass\",\"drop\",\"alert\",\"reject\". You"
                       " have to specify all of them, without quotes and"
                       " without capital letters", action->val);
                goto error;
            }

            if (order >= 4) {
                SCLogError(SC_ERR_ACTION_ORDER, "action-order, you have already specified all the "
                       "possible actions plus \"%s\". Please, use \"pass\","
                       "\"drop\",\"alert\",\"reject\". You have to specify"
                       " all of them, without quotes and without capital"
                       " letters", action->val);
                goto error;
            }
            actions_used |= action_flag;
            actions_config[order++] = action_flag;
        }
    }
    if (order < 4) {
        SCLogError(SC_ERR_ACTION_ORDER, "action-order, the config didn't specify all of the "
               "actions. Please, use \"pass\",\"drop\",\"alert\","
               "\"reject\". You have to specify all of them, without"
               " quotes and without capital letters");
        goto error;
    }

    /* Now, it's a valid config. Override the default preset */
    for (order = 0; order < 4; order++) {
        action_order_sigs[order] = actions_config[order];
    }

    return 0;

 error:
    return -1;
}

#ifdef UNITTESTS

/**
 * \test Check that we invalidate duplicated actions
 *       (It should default to pass, drop, reject, alert)
 */
static int UtilActionTest01(void)
{
    int res = 1;
    char config[] = "\
%YAML 1.1\n\
---\n\
action-order:\n\
  - alert\n\
  - drop\n\
  - reject\n\
  - alert\n";

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(config, strlen(config));

    ActionInitConfig();
    if (action_order_sigs[0] != ACTION_PASS ||
        action_order_sigs[1] != ACTION_DROP ||
        action_order_sigs[2] != ACTION_REJECT ||
        action_order_sigs[3] != ACTION_ALERT)
    {
        res = 0;
    }
    ConfRestoreContextBackup();

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    return res;
}

/**
 * \test Check that we invalidate with unknown keywords
 *       (It should default to pass, drop, reject, alert)
 */
static int UtilActionTest02(void)
{
    int res = 1;
    char config[] = "\
%YAML 1.1\n\
---\n\
action-order:\n\
  - alert\n\
  - drop\n\
  - reject\n\
  - ftw\n";

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(config, strlen(config));

    ActionInitConfig();
    if (action_order_sigs[0] != ACTION_PASS ||
        action_order_sigs[1] != ACTION_DROP ||
        action_order_sigs[2] != ACTION_REJECT ||
        action_order_sigs[3] != ACTION_ALERT)
    {
        res = 0;
    }
    ConfRestoreContextBackup();

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    return res;
}

/**
 * \test Check that we invalidate if any action is missing
 *       (It should default to pass, drop, reject, alert)
 */
static int UtilActionTest03(void)
{
    int res = 1;
    char config[] = "\
%YAML 1.1\n\
---\n\
action-order:\n\
  - alert\n\
  - drop\n\
  - reject\n";

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(config, strlen(config));

    ActionInitConfig();
    if (action_order_sigs[0] != ACTION_PASS ||
        action_order_sigs[1] != ACTION_DROP ||
        action_order_sigs[2] != ACTION_REJECT ||
        action_order_sigs[3] != ACTION_ALERT)
    {
        res = 0;
    }
    ConfRestoreContextBackup();

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    return res;
}

/**
 * \test Check that we invalidate if any action is missing
 *       (It should default to pass, drop, reject, alert)
 */
static int UtilActionTest04(void)
{
    int res = 1;
    char config[] = "\
%YAML 1.1\n\
---\n\
action-order:\n";

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(config, strlen(config));

    ActionInitConfig();
    if (action_order_sigs[0] != ACTION_PASS ||
        action_order_sigs[1] != ACTION_DROP ||
        action_order_sigs[2] != ACTION_REJECT ||
        action_order_sigs[3] != ACTION_ALERT)
    {
        res = 0;
    }
    ConfRestoreContextBackup();

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    return res;
}

/**
 * \test Check that we invalidate with unknown keywords
 *       and/or more than the expected
 *       (It should default to pass, drop, reject, alert)
 */
static int UtilActionTest05(void)
{
    int res = 1;
    char config[] = "\
%YAML 1.1\n\
---\n\
action-order:\n\
  - alert\n\
  - drop\n\
  - reject\n\
  - pass\n\
  - whatever\n";

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(config, strlen(config));

    ActionInitConfig();
    if (action_order_sigs[0] != ACTION_PASS ||
        action_order_sigs[1] != ACTION_DROP ||
        action_order_sigs[2] != ACTION_REJECT ||
        action_order_sigs[3] != ACTION_ALERT)
    {
        res = 0;
    }
    ConfRestoreContextBackup();

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    return res;
}

/**
 * \test Check that we load a valid config
 */
static int UtilActionTest06(void)
{
    int res = 1;
    char config[] = "\
%YAML 1.1\n\
---\n\
action-order:\n\
  - alert\n\
  - drop\n\
  - reject\n\
  - pass\n";

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(config, strlen(config));

    ActionInitConfig();
    if (action_order_sigs[0] != ACTION_ALERT ||
        action_order_sigs[1] != ACTION_DROP ||
        action_order_sigs[2] != ACTION_REJECT ||
        action_order_sigs[3] != ACTION_PASS)
    {
        res = 0;
    }
    ConfRestoreContextBackup();

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    return res;
}

/**
 * \test Check that we load a valid config
 */
static int UtilActionTest07(void)
{
    int res = 1;
    char config[] = "\
%YAML 1.1\n\
---\n\
action-order:\n\
  - pass\n\
  - alert\n\
  - drop\n\
  - reject\n";

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(config, strlen(config));

    ActionInitConfig();
    if (action_order_sigs[0] != ACTION_PASS ||
        action_order_sigs[1] != ACTION_ALERT ||
        action_order_sigs[2] != ACTION_DROP ||
        action_order_sigs[3] != ACTION_REJECT)
    {
        res = 0;
    }
    ConfRestoreContextBackup();

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    return res;
}

/**
 * \test Check that we handle the "pass" action
 *       correctly at the IP Only engine in the default case
 */
static int UtilActionTest08(void)
{
    int res = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];
    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "alert ip any any -> any any (msg:\"sig 1\"; sid:1;)";
    sigs[1]= "pass ip 192.168.1.1 80 -> any any (msg:\"sig 2\"; sid:2;)";
    sigs[2]= "alert ip any any -> any any (msg:\"sig 3\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {1, 0, 1},
                              {0, 0, 0},
                              {1, 0, 1} };
    /* This means that with the second packet, the results will be
     * all ({0,0,0}) since, we should match the "pass" rule first
     */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    return res;
}

/**
 * \test Check that we handle the "pass" action
 *       correctly at the IP Only engine with more
 *       prio to drop
 */
static int UtilActionTest09(void)
{
    int res = 1;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];

    action_order_sigs[0] = ACTION_DROP;
    action_order_sigs[1] = ACTION_PASS;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;

    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "alert ip any any -> any any (msg:\"sig 1\"; sid:1;)";
    sigs[1]= "pass ip 192.168.1.1 80 -> any any (msg:\"sig 2\"; sid:2;)";
    sigs[2]= "drop ip any any -> any any (msg:\"sig 3\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {1, 0, 1},
                              {0, 0, 1},
                              {1, 0, 1} };
    /* This means that with the second packet, the results will be
     * all ({0,0,1}) since, we should match the "drop" rule first.
     * Later the "pass" rule will avoid the "alert" rule match
     */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    return res;
}

/**
 * \test Check that we handle the "pass" action
 *       correctly at the detection engine in the default case
 */
static int UtilActionTest10(void)
{
    int res = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    uint8_t *buf2 = (uint8_t *)"wo!";
    uint16_t buflen2 = strlen((char *)buf2);
    Packet *p[3];
    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf2, buflen2, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "alert ip any any -> any any (msg:\"sig 1\"; content:\"Hi all\"; sid:1;)";
    sigs[1]= "pass ip any any -> any any (msg:\"sig 2\"; content:\"wo\"; sid:2;)";
    sigs[2]= "alert ip any any -> any any (msg:\"sig 3\"; content:\"Hi all\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {1, 0, 1},
                              {0, 0, 0},
                              {1, 0, 1} };
    /* This means that with the second packet, the results will be
     * all ({0,0,0}) since, we should match the "pass" rule first
     */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    return res;
}

/**
 * \test Check that we handle the "pass" action
 *       correctly at the detection engine with more
 *       prio to drop
 */
static int UtilActionTest11(void)
{
    int res = 1;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    uint8_t *buf2 = (uint8_t *)"Hi all wo!";
    uint16_t buflen2 = strlen((char *)buf2);
    Packet *p[3];

    action_order_sigs[0] = ACTION_DROP;
    action_order_sigs[1] = ACTION_PASS;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;

    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf2, buflen2, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "alert tcp any any -> any any (msg:\"sig 1\"; content:\"Hi all\"; sid:1;)";
    sigs[1]= "pass tcp any any -> any any (msg:\"sig 2\"; content:\"wo\"; sid:2;)";
    sigs[2]= "drop tcp any any -> any any (msg:\"sig 3\"; content:\"Hi all\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {1, 0, 1},
                              {0, 0, 1},
                              {1, 0, 1} };
    /* This means that with the second packet, the results will be
     * all ({0,0,1}) since, we should match the "drop" rule first.
     * Later the "pass" rule will avoid the "alert" rule match
     */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    return res;
}

/**
 * \test Check that we handle the "pass" action
 *       correctly at the detection engine in the default case
 */
static int UtilActionTest12(void)
{
    int res = 0;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];
    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "alert ip any any -> any any (msg:\"sig 1\"; sid:1;)";
    sigs[1]= "pass ip any any -> any any (msg:\"Testing normal 2\"; sid:2;)";
    sigs[2]= "alert ip any any -> any any (msg:\"sig 3\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {0, 0, 0},
                              {0, 0, 0},
                              {0, 0, 0} };
    /* All should match the 3 sigs, but the action pass has prio */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    return res;
}

/**
 * \test Check that we handle the "pass" action
 *       correctly at the detection engine with more
 *       prio to drop
 */
static int UtilActionTest13(void)
{
    int res = 1;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];

    action_order_sigs[0] = ACTION_DROP;
    action_order_sigs[1] = ACTION_PASS;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;

    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "alert tcp any any -> any any (msg:\"sig 1\"; content:\"Hi all\"; sid:1;)";
    sigs[1]= "pass tcp any any -> any any (msg:\"sig 2\"; content:\"Hi all\"; sid:2;)";
    sigs[2]= "drop tcp any any -> any any (msg:\"sig 3\"; content:\"Hi all\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {0, 0, 1},
                              {0, 0, 1},
                              {0, 0, 1} };
     /* All the patckets should match the 3 sigs. As drop has more
      * priority than pass, it should alert on each packet */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    return res;
}

/**
 * \test Check that we handle the "pass" action
 *       correctly at the detection engine with more
 *       prio to drop and alert
 */
static int UtilActionTest14(void)
{
    int res = 1;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];

    action_order_sigs[0] = ACTION_DROP;
    action_order_sigs[1] = ACTION_ALERT;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_PASS;

    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "alert tcp any any -> any any (msg:\"sig 1\"; content:\"Hi all\"; sid:1;)";
    sigs[1]= "pass tcp any any -> any any (msg:\"sig 2\"; content:\"Hi all\"; sid:2;)";
    sigs[2]= "drop tcp any any -> any any (msg:\"sig 3\"; content:\"Hi all\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {1, 0, 1},
                              {1, 0, 1},
                              {1, 0, 1} };
     /* All the patckets should match the 3 sigs. As drop
      * and alert have more priority than pass, both should
      * alert on each packet */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    return res;
}

/**
 * \test Check mixed sigs (iponly and normal)
 */
static int UtilActionTest15(void)
{
    int res = 1;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];

    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "alert tcp any any -> any any (msg:\"sig 1\"; sid:1;)";
    sigs[1]= "pass tcp any any -> any any (msg:\"sig 2\"; content:\"Hi all\"; sid:2;)";
    sigs[2]= "drop tcp any any -> any any (msg:\"sig 3\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {0, 0, 0},
                              {0, 0, 0},
                              {0, 0, 0} };
     /* All the patckets should match the 3 sigs. As drop
      * and alert have more priority than pass, both should
      * alert on each packet */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    return res;
}

/**
 * \test Check mixed sigs (iponly and normal)
 */
static int UtilActionTest16(void)
{
    int res = 1;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];

    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "drop tcp any any -> any any (msg:\"sig 1\"; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"sig 2\"; content:\"Hi all\"; sid:2;)";
    sigs[2]= "pass tcp any any -> any any (msg:\"sig 3\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {0, 0, 0},
                              {0, 0, 0},
                              {0, 0, 0} };
     /* All the patckets should match the 3 sigs. As drop
      * and alert have more priority than pass, both should
      * alert on each packet */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    return res;
}

/**
 * \test Check mixed sigs (iponly and normal)
 */
static int UtilActionTest17(void)
{
    int res = 1;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];

    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "pass tcp any any -> any any (msg:\"sig 1\"; sid:1;)";
    sigs[1]= "drop tcp any any -> any any (msg:\"sig 2\"; content:\"Hi all\"; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"sig 3\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {0, 0, 0},
                              {0, 0, 0},
                              {0, 0, 0} };
     /* All the patckets should match the 3 sigs. As drop
      * and alert have more priority than pass, both should
      * alert on each packet */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    return res;
}

/**
 * \test Check mixed sigs (iponly and normal) with more prio for drop
 */
static int UtilActionTest18(void)
{
    int res = 1;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];

    action_order_sigs[0] = ACTION_DROP;
    action_order_sigs[1] = ACTION_PASS;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;

    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "alert tcp any any -> any any (msg:\"sig 1\"; sid:1;)";
    sigs[1]= "pass tcp any any -> any any (msg:\"sig 2\"; content:\"Hi all\"; sid:2;)";
    sigs[2]= "drop tcp any any -> any any (msg:\"sig 3\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {0, 0, 1},
                              {0, 0, 1},
                              {0, 0, 1} };
     /* All the patckets should match the 3 sigs. As drop
      * and alert have more priority than pass, both should
      * alert on each packet */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;

    return res;
}

/**
 * \test Check mixed sigs (iponly and normal) with more prio for drop
 */
static int UtilActionTest19(void)
{
    int res = 1;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];

    action_order_sigs[0] = ACTION_DROP;
    action_order_sigs[1] = ACTION_PASS;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;

    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "drop tcp any any -> any any (msg:\"sig 1\"; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"sig 2\"; content:\"Hi all\"; sid:2;)";
    sigs[2]= "pass tcp any any -> any any (msg:\"sig 3\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {1, 0, 0},
                              {1, 0, 0},
                              {1, 0, 0} };
     /* All the patckets should match the 3 sigs. As drop
      * and alert have more priority than pass, both should
      * alert on each packet */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;

    return res;
}

/**
 * \test Check mixed sigs (iponly and normal) with more prio for drop
 */
static int UtilActionTest20(void)
{
    int res = 1;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];

    action_order_sigs[0] = ACTION_DROP;
    action_order_sigs[1] = ACTION_PASS;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;

    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "pass tcp any any -> any any (msg:\"sig 1\"; sid:1;)";
    sigs[1]= "drop tcp any any -> any any (msg:\"sig 2\"; content:\"Hi all\"; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"sig 3\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {0, 1, 0},
                              {0, 1, 0},
                              {0, 1, 0} };
     /* All the patckets should match the 3 sigs. As drop
      * and alert have more priority than pass, both should
      * alert on each packet */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    return res;
}

/**
 * \test Check mixed sigs (iponly and normal) with more prio for alert and drop
 */
static int UtilActionTest21(void)
{
    int res = 1;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];

    action_order_sigs[0] = ACTION_DROP;
    action_order_sigs[1] = ACTION_ALERT;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_PASS;

    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "alert tcp any any -> any any (msg:\"sig 1\"; sid:1;)";
    sigs[1]= "pass tcp any any -> any any (msg:\"sig 2\"; content:\"Hi all\"; sid:2;)";
    sigs[2]= "drop tcp any any -> any any (msg:\"sig 3\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {1, 0, 1},
                              {1, 0, 1},
                              {1, 0, 1} };
     /* All the patckets should match the 3 sigs. As drop
      * and alert have more priority than pass, both should
      * alert on each packet */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;

    return res;
}

/**
 * \test Check mixed sigs (iponly and normal) with more prio for alert and drop
 */
static int UtilActionTest22(void)
{
    int res = 1;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];

    action_order_sigs[0] = ACTION_DROP;
    action_order_sigs[1] = ACTION_ALERT;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_PASS;

    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "drop tcp any any -> any any (msg:\"sig 1\"; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"sig 2\"; content:\"Hi all\"; sid:2;)";
    sigs[2]= "pass tcp any any -> any any (msg:\"sig 3\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {1, 1, 0},
                              {1, 1, 0},
                              {1, 1, 0} };
     /* All the patckets should match the 3 sigs. As drop
      * and alert have more priority than pass, both should
      * alert on each packet */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

end:
    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;

    return res;
}

/**
 * \test Check mixed sigs (iponly and normal) with more prio for alert and drop
 */
static int UtilActionTest23(void)
{
    int res = 1;
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buflen = strlen((char *)buf);
    Packet *p[3];

    action_order_sigs[0] = ACTION_DROP;
    action_order_sigs[1] = ACTION_ALERT;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_PASS;

    p[0] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);
    p[1] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.1", "192.168.1.5",
                   80, 41424);
    p[2] = UTHBuildPacketReal((uint8_t *)buf, buflen, IPPROTO_TCP,
                   "192.168.1.5", "192.168.1.1",
                   41424, 80);

    if (p[0] == NULL || p[1] == NULL ||p[2] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "pass tcp any any -> any any (msg:\"sig 1\"; sid:1;)";
    sigs[1]= "drop tcp any any -> any any (msg:\"sig 2\"; content:\"Hi all\"; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"sig 3\"; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[3][3] = {
                              {0, 1, 1},
                              {0, 1, 1},
                              {0, 1, 1} };
     /* All the patckets should match the 3 sigs. As drop
      * and alert have more priority than pass, both should
      * alert on each packet */

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto cleanup;
    de_ctx->flags |= DE_QUIET;

    if (UTHAppendSigs(de_ctx, sigs, 3) == 0)
        goto cleanup;

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);

    res = UTHMatchPacketsWithResults(de_ctx, p, 3, sid, (uint32_t *) results, 3);

cleanup:
    UTHFreePackets(p, 3);

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;

end:
    return res;
}

/**
 * \test Check that the expected defaults are loaded if the
 *     action-order configuration is not present.
 */
static int UtilActionTest24(void)
{
    int res = 1;
    char config[] = "%YAML 1.1\n"
        "---\n";

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(config, strlen(config));

    if (ActionInitConfig() != 0) {
        res = 0;
        goto done;
    }
    if (action_order_sigs[0] != ACTION_PASS ||
        action_order_sigs[1] != ACTION_DROP ||
        action_order_sigs[2] != ACTION_REJECT ||
        action_order_sigs[3] != ACTION_ALERT) {
        res = 0;
    }

done:
    ConfRestoreContextBackup();
    return res;
}

#endif

/* Register unittests */
void UtilActionRegisterTests(void)
{
#ifdef UNITTESTS
    /* Generic tests */
    UtRegisterTest("UtilActionTest01", UtilActionTest01);
    UtRegisterTest("UtilActionTest02", UtilActionTest02);
    UtRegisterTest("UtilActionTest02", UtilActionTest02);
    UtRegisterTest("UtilActionTest03", UtilActionTest03);
    UtRegisterTest("UtilActionTest04", UtilActionTest04);
    UtRegisterTest("UtilActionTest05", UtilActionTest05);
    UtRegisterTest("UtilActionTest06", UtilActionTest06);
    UtRegisterTest("UtilActionTest07", UtilActionTest07);
    UtRegisterTest("UtilActionTest08", UtilActionTest08);
    UtRegisterTest("UtilActionTest09", UtilActionTest09);
    UtRegisterTest("UtilActionTest10", UtilActionTest10);
    UtRegisterTest("UtilActionTest11", UtilActionTest11);
    UtRegisterTest("UtilActionTest12", UtilActionTest12);
    UtRegisterTest("UtilActionTest13", UtilActionTest13);
    UtRegisterTest("UtilActionTest14", UtilActionTest14);
    UtRegisterTest("UtilActionTest15", UtilActionTest15);
    UtRegisterTest("UtilActionTest16", UtilActionTest16);
    UtRegisterTest("UtilActionTest17", UtilActionTest17);
    UtRegisterTest("UtilActionTest18", UtilActionTest18);
    UtRegisterTest("UtilActionTest19", UtilActionTest19);
    UtRegisterTest("UtilActionTest20", UtilActionTest20);
    UtRegisterTest("UtilActionTest21", UtilActionTest21);
    UtRegisterTest("UtilActionTest22", UtilActionTest22);
    UtRegisterTest("UtilActionTest23", UtilActionTest23);
    UtRegisterTest("UtilActionTest24", UtilActionTest24);
#endif
}
