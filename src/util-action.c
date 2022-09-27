/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#include "util-action.h"

#ifdef UNITTESTS
#include "util-unittest.h"
#include "conf-yaml-loader.h"
#endif
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
    FAIL_IF_NOT(action_order_sigs[0] == ACTION_PASS);
    FAIL_IF_NOT(action_order_sigs[1] == ACTION_DROP);
    FAIL_IF_NOT(action_order_sigs[2] == ACTION_REJECT);
    FAIL_IF_NOT(action_order_sigs[3] == ACTION_ALERT);
    ConfRestoreContextBackup();

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    PASS;
}

/**
 * \test Check that we invalidate with unknown keywords
 *       (It should default to pass, drop, reject, alert)
 */
static int UtilActionTest02(void)
{
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
    FAIL_IF_NOT(action_order_sigs[0] == ACTION_PASS);
    FAIL_IF_NOT(action_order_sigs[1] == ACTION_DROP);
    FAIL_IF_NOT(action_order_sigs[2] == ACTION_REJECT);
    FAIL_IF_NOT(action_order_sigs[3] == ACTION_ALERT);
    ConfRestoreContextBackup();

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    PASS;
}

/**
 * \test Check that we invalidate if any action is missing
 *       (It should default to pass, drop, reject, alert)
 */
static int UtilActionTest03(void)
{
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
    FAIL_IF_NOT(action_order_sigs[0] == ACTION_PASS);
    FAIL_IF_NOT(action_order_sigs[1] == ACTION_DROP);
    FAIL_IF_NOT(action_order_sigs[2] == ACTION_REJECT);
    FAIL_IF_NOT(action_order_sigs[3] == ACTION_ALERT);
    ConfRestoreContextBackup();

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    PASS;
}

/**
 * \test Check that we invalidate if any action is missing
 *       (It should default to pass, drop, reject, alert)
 */
static int UtilActionTest04(void)
{
    char config[] = "\
%YAML 1.1\n\
---\n\
action-order:\n";

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(config, strlen(config));

    ActionInitConfig();
    FAIL_IF_NOT(action_order_sigs[0] == ACTION_PASS);
    FAIL_IF_NOT(action_order_sigs[1] == ACTION_DROP);
    FAIL_IF_NOT(action_order_sigs[2] == ACTION_REJECT);
    FAIL_IF_NOT(action_order_sigs[3] == ACTION_ALERT);
    ConfRestoreContextBackup();

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    PASS;
}

/**
 * \test Check that we invalidate with unknown keywords
 *       and/or more than the expected
 *       (It should default to pass, drop, reject, alert)
 */
static int UtilActionTest05(void)
{
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
    FAIL_IF_NOT(action_order_sigs[0] == ACTION_PASS);
    FAIL_IF_NOT(action_order_sigs[1] == ACTION_DROP);
    FAIL_IF_NOT(action_order_sigs[2] == ACTION_REJECT);
    FAIL_IF_NOT(action_order_sigs[3] == ACTION_ALERT);
    ConfRestoreContextBackup();

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    PASS;
}

/**
 * \test Check that we load a valid config
 */
static int UtilActionTest06(void)
{
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
    FAIL_IF_NOT(action_order_sigs[0] == ACTION_ALERT);
    FAIL_IF_NOT(action_order_sigs[1] == ACTION_DROP);
    FAIL_IF_NOT(action_order_sigs[2] == ACTION_REJECT);
    FAIL_IF_NOT(action_order_sigs[3] == ACTION_PASS);
    ConfRestoreContextBackup();

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    PASS;
}

/**
 * \test Check that we load a valid config
 */
static int UtilActionTest07(void)
{
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
    FAIL_IF_NOT(action_order_sigs[0] == ACTION_PASS);
    FAIL_IF_NOT(action_order_sigs[1] == ACTION_ALERT);
    FAIL_IF_NOT(action_order_sigs[2] == ACTION_DROP);
    FAIL_IF_NOT(action_order_sigs[3] == ACTION_REJECT);
    ConfRestoreContextBackup();

    /* Restore default values */
    action_order_sigs[0] = ACTION_PASS;
    action_order_sigs[1] = ACTION_DROP;
    action_order_sigs[2] = ACTION_REJECT;
    action_order_sigs[3] = ACTION_ALERT;
    PASS;
}

/**
 * \test Check that the expected defaults are loaded if the
 *     action-order configuration is not present.
 */
static int UtilActionTest08(void)
{
    char config[] = "%YAML 1.1\n"
        "---\n";

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(config, strlen(config));

    FAIL_IF_NOT(ActionInitConfig() == 0);
    FAIL_IF_NOT(action_order_sigs[0] == ACTION_PASS);
    FAIL_IF_NOT(action_order_sigs[1] == ACTION_DROP);
    FAIL_IF_NOT(action_order_sigs[2] == ACTION_REJECT);
    FAIL_IF_NOT(action_order_sigs[3] == ACTION_ALERT);

    ConfRestoreContextBackup();
    PASS;
}

/* Register unittests */
void UtilActionRegisterTests(void)
{
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
}
#endif
