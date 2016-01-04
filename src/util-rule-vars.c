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
 *  \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 *  Rule variable utility functions
 */

#include "suricata-common.h"
#include "conf.h"
#include "conf-yaml-loader.h"

#include "detect.h"
#include "detect-content.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "util-rule-vars.h"
#include "util-enum.h"
#include "util-debug.h"
#include "util-unittest.h"

/** An enum-string map, that maps the different vars type in the yaml conf
 *  type with the mapping path in the yaml conf file */
SCEnumCharMap sc_rule_vars_type_map[ ] = {
    { "vars.address-groups", SC_RULE_VARS_ADDRESS_GROUPS },
    { "vars.port-groups",    SC_RULE_VARS_PORT_GROUPS }
};

/**
 * \internal
 * \brief Retrieves a value for a yaml mapping.  The sequence from the yaml
 *        conf file, from which the conf value has to be retrieved can be
 *        specified by supplying a SCRuleVarsType enum.  The string mapping
 *        for each of the SCRuleVarsType is present in sc_rule_vars_type_map.
 *
 * \param conf_var_name  Pointer to a character string containing the conf var
 *                       name, whose value has to be retrieved from the yaml
 *                       conf file.
 * \param conf_vars_type Holds an enum value that indicates the kind of yaml
 *                       mapping that has to be retrieved.  Can be one of the
 *                       values in SCRuleVarsType.
 *
 * \retval conf_var_name_value Pointer to the string containing the conf value
 *                             on success; NULL on failure.
 */
char *SCRuleVarsGetConfVar(const DetectEngineCtx *de_ctx,
                           const char *conf_var_name,
                           SCRuleVarsType conf_vars_type)
{
    SCEnter();

    const char *conf_var_type_name = NULL;
    char conf_var_full_name[2048] = "";
    char *conf_var_full_name_value = NULL;

    if (conf_var_name == NULL)
        goto end;

    while (conf_var_name[0] != '\0' && isspace((unsigned char)conf_var_name[0])) {
        conf_var_name++;
    }

    (conf_var_name[0] == '$') ? conf_var_name++ : conf_var_name;
    conf_var_type_name = SCMapEnumValueToName(conf_vars_type,
                                              sc_rule_vars_type_map);
    if (conf_var_type_name == NULL)
        goto end;

    if (de_ctx != NULL && strlen(de_ctx->config_prefix) > 0) {
        if (snprintf(conf_var_full_name, sizeof(conf_var_full_name), "%s.%s.%s",
                    de_ctx->config_prefix, conf_var_type_name, conf_var_name) < 0) {
            goto end;
        }
    } else {
        if (snprintf(conf_var_full_name, sizeof(conf_var_full_name), "%s.%s",
                    conf_var_type_name, conf_var_name) < 0) {
            goto end;
        }
    }

    if (ConfGet(conf_var_full_name, &conf_var_full_name_value) != 1) {
        SCLogError(SC_ERR_UNDEFINED_VAR, "Variable \"%s\" is not defined in "
                                         "configuration file", conf_var_name);
        goto end;
    }

    SCLogDebug("Value obtained from the yaml conf file, for the var "
               "\"%s\" is \"%s\"", conf_var_name, conf_var_full_name_value);

 end:
    SCReturnCharPtr(conf_var_full_name_value);
}


/**********************************Unittests***********************************/
#ifdef UNITTESTS

static const char *dummy_conf_string =
    "%YAML 1.1\n"
    "---\n"
    "\n"
    "default-log-dir: /var/log/suricata\n"
    "\n"
    "logging:\n"
    "\n"
    "  default-log-level: debug\n"
    "\n"
    "  default-format: \"<%t> - <%l>\"\n"
    "\n"
    "  default-startup-message: Your IDS has started.\n"
    "\n"
    "  default-output-filter:\n"
    "\n"
    "  output:\n"
    "\n"
    "  - interface: console\n"
    "    log-level: info\n"
    "\n"
    "  - interface: file\n"
    "    filename: /var/log/suricata.log\n"
    "\n"
    "  - interface: syslog\n"
    "    facility: local5\n"
    "    format: \"%l\"\n"
    "\n"
    "pfring:\n"
    "\n"
    "  interface: eth0\n"
    "\n"
    "  clusterid: 99\n"
    "\n"
    "vars:\n"
    "\n"
    "  address-groups:\n"
    "\n"
    "    HOME_NET: \"[192.168.0.0/16,10.8.0.0/16,127.0.0.1,2001:888:"
    "13c5:5AFE::/64,2001:888:13c5:CAFE::/64]\"\n"
    "\n"
    "    EXTERNAL_NET: \"[!192.168.0.0/16,2000::/3]\"\n"
    "\n"
    "    HTTP_SERVERS: \"!192.168.0.0/16\"\n"
    "\n"
    "    SMTP_SERVERS: \"!192.168.0.0/16\"\n"
    "\n"
    "    SQL_SERVERS: \"!192.168.0.0/16\"\n"
    "\n"
    "    DNS_SERVERS: any\n"
    "\n"
    "    TELNET_SERVERS: any\n"
    "\n"
    "    AIM_SERVERS: any\n"
    "\n"
    "  port-groups:\n"
    "\n"
    "    HTTP_PORTS: \"80:81,88\"\n"
    "\n"
    "    SHELLCODE_PORTS: 80\n"
    "\n"
    "    ORACLE_PORTS: 1521\n"
    "\n"
    "    SSH_PORTS: 22\n"
    "\n";

/**
 * \test Check that valid address and port group vars are correctly retrieved
 *       from the configuration.
 */
int SCRuleVarsPositiveTest01(void)
{
    int result = 1;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    /* check for address-groups */
    result &= (SCRuleVarsGetConfVar(NULL,"$HOME_NET", SC_RULE_VARS_ADDRESS_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL,"$HOME_NET", SC_RULE_VARS_ADDRESS_GROUPS),
                      "[192.168.0.0/16,10.8.0.0/16,127.0.0.1,2001:888:13c5:"
                      "5AFE::/64,2001:888:13c5:CAFE::/64]") == 0);
    result &= (SCRuleVarsGetConfVar(NULL,"$EXTERNAL_NET", SC_RULE_VARS_ADDRESS_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL,"$EXTERNAL_NET", SC_RULE_VARS_ADDRESS_GROUPS),
                      "[!192.168.0.0/16,2000::/3]") == 0);
    result &= (SCRuleVarsGetConfVar(NULL,"$HTTP_SERVERS", SC_RULE_VARS_ADDRESS_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL,"$HTTP_SERVERS", SC_RULE_VARS_ADDRESS_GROUPS),
                      "!192.168.0.0/16") == 0);
    result &= (SCRuleVarsGetConfVar(NULL,"$SMTP_SERVERS", SC_RULE_VARS_ADDRESS_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL,"$SMTP_SERVERS", SC_RULE_VARS_ADDRESS_GROUPS),
                      "!192.168.0.0/16") == 0);
    result &= (SCRuleVarsGetConfVar(NULL,"$SQL_SERVERS", SC_RULE_VARS_ADDRESS_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL,"$SQL_SERVERS", SC_RULE_VARS_ADDRESS_GROUPS),
                      "!192.168.0.0/16") == 0);
    result &= (SCRuleVarsGetConfVar(NULL,"$DNS_SERVERS", SC_RULE_VARS_ADDRESS_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL,"$DNS_SERVERS", SC_RULE_VARS_ADDRESS_GROUPS),
                      "any") == 0);
    result &= (SCRuleVarsGetConfVar(NULL,"$TELNET_SERVERS", SC_RULE_VARS_ADDRESS_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL,"$TELNET_SERVERS", SC_RULE_VARS_ADDRESS_GROUPS),
                      "any") == 0);
    result &= (SCRuleVarsGetConfVar(NULL,"$AIM_SERVERS", SC_RULE_VARS_ADDRESS_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL,"$AIM_SERVERS", SC_RULE_VARS_ADDRESS_GROUPS),
                      "any") == 0);

    /* Test that a leading space is stripped. */
    result &= (SCRuleVarsGetConfVar(NULL," $AIM_SERVERS", SC_RULE_VARS_ADDRESS_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL," $AIM_SERVERS", SC_RULE_VARS_ADDRESS_GROUPS),
                      "any") == 0);

    /* check for port-groups */
    result &= (SCRuleVarsGetConfVar(NULL,"$HTTP_PORTS", SC_RULE_VARS_PORT_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL,"$HTTP_PORTS", SC_RULE_VARS_PORT_GROUPS),
                      "80:81,88") == 0);
    result &= (SCRuleVarsGetConfVar(NULL,"$SHELLCODE_PORTS", SC_RULE_VARS_PORT_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL,"$SHELLCODE_PORTS", SC_RULE_VARS_PORT_GROUPS),
                      "80") == 0);
    result &= (SCRuleVarsGetConfVar(NULL,"$ORACLE_PORTS", SC_RULE_VARS_PORT_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL,"$ORACLE_PORTS", SC_RULE_VARS_PORT_GROUPS),
                      "1521") == 0);
    result &= (SCRuleVarsGetConfVar(NULL,"$SSH_PORTS", SC_RULE_VARS_PORT_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL,"$SSH_PORTS", SC_RULE_VARS_PORT_GROUPS),
                      "22") == 0);

    ConfDeInit();
    ConfRestoreContextBackup();

    return result;
}

/**
 * \test Check that invalid address and port groups are properly handled by the
 *       API.
 */
int SCRuleVarsNegativeTest02(void)
{
    int result = 1;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    result &= (SCRuleVarsGetConfVar(NULL,"$HOME_NETW", SC_RULE_VARS_ADDRESS_GROUPS) == NULL);
    result &= (SCRuleVarsGetConfVar(NULL,"$home_net", SC_RULE_VARS_ADDRESS_GROUPS) == NULL);

    result &= (SCRuleVarsGetConfVar(NULL,"$TOMCAT_PORTSW", SC_RULE_VARS_PORT_GROUPS) == NULL);
    result &= (SCRuleVarsGetConfVar(NULL,"$tomcat_ports", SC_RULE_VARS_PORT_GROUPS) == NULL);

    ConfDeInit();
    ConfRestoreContextBackup();

    return result;
}

/**
 * \test Check that Signatures with valid address and port groups are parsed
 *       without any errors by the Signature parsing API.
 */
int SCRuleVarsPositiveTest03(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;
/*
    s = SigInit(de_ctx, "alert tcp $HTTP_SERVERS any -> any any (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp $SMTP_SERVERS any -> $HTTP_SERVERS any (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp $AIM_SERVERS any -> $AIM_SERVERS any (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp $TELNET_SERVERS any -> any $SSH_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp $TELNET_SERVERS any -> any !$SSH_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp $TELNET_SERVERS 80 -> any !$SSH_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp $TELNET_SERVERS !80 -> any !$SSH_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp !$HTTP_SERVERS !80 -> any !$SSH_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp 192.168.1.2 any -> any $HTTP_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp !192.168.1.2 any -> any $HTTP_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp !192.168.1.2 any -> any !$HTTP_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp !192.168.1.2 any -> !$HTTP_SERVERS !$HTTP_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp !192.168.1.2 $HTTP_PORTS -> !$HTTP_SERVERS !$HTTP_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp [!192.168.24.0/23,!167.12.0.0/24] any -> any $HTTP_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp ![192.168.24.0/23,!167.12.0.0/24] any -> any $HTTP_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp [$HOME_NET,!192.168.1.2] $HTTP_PORTS -> !$HTTP_SERVERS !$HTTP_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp [[192.168.1.3,$EXTERNAL_NET],192.168.2.5] $HTTP_PORTS -> !$HTTP_SERVERS !$HTTP_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp [[192.168.1.3,$EXTERNAL_NET],192.168.2.5] $HTTP_PORTS -> !$HTTP_SERVERS [80,[!$HTTP_PORTS,$ORACLE_PORTS]] (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);
*/
    s = SigInit(de_ctx, "alert tcp [$HTTP_SERVERS,$HOME_NET,192.168.2.5] $HTTP_PORTS -> $EXTERNAL_NET [80,[!$HTTP_PORTS,$ORACLE_PORTS]] (msg:\"Rule Vars Test\"; sid:1;)");
    if (s == NULL)
        goto end;
    SigFree(s);

    result = 1;

end:
    ConfDeInit();
    ConfRestoreContextBackup();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check that Signatures with invalid address and port groups, are
 *       are invalidated by the Singature parsing API.
 */
int SCRuleVarsNegativeTest04(void)
{
    int result = 0;
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = NULL;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx, "alert tcp $HTTP_SERVER any -> any any (msg:\"Rule Vars Test\"; sid:1;)");
    if (s != NULL)
        goto end;

    s = SigInit(de_ctx, "alert tcp $http_servers any -> any any (msg:\"Rule Vars Test\"; sid:1;)");
    if (s != NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp $http_servers any -> any $HTTP_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s != NULL)
        goto end;
    SigFree(s);

    s = SigInit(de_ctx, "alert tcp !$TELNET_SERVERS !80 -> any !$SSH_PORTS (msg:\"Rule Vars Test\"; sid:1;)");
    if (s != NULL)
        goto end;
    SigFree(s);

    result = 1;

end:
    ConfDeInit();
    ConfRestoreContextBackup();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static const char *dummy_mt_conf_string =
    "%YAML 1.1\n"
    "---\n"
    "vars:\n"
    "\n"
    "  address-groups:\n"
    "\n"
    "    HOME_NET: \"[1.2.3.4]\"\n"
    "  port-groups:\n"
    "    HTTP_PORTS: \"12345\"\n"
    "multi-detect:\n"
    "  0:\n"
    "    vars:\n"
    "\n"
    "      address-groups:\n"
    "\n"
    "        HOME_NET: \"[8.8.8.8]\"\n"
    "      port-groups:\n"
    "        HTTP_PORTS: \"54321\"\n"
    "\n";

/**
 * \test Check that valid address and port group vars are correctly retrieved
 *       from the configuration.
 */
int SCRuleVarsMTest01(void)
{
    int result = 0;
    DetectEngineCtx *de_ctx = NULL;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_mt_conf_string, strlen(dummy_mt_conf_string));

    if ( (de_ctx = DetectEngineCtxInit()) == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;
    snprintf(de_ctx->config_prefix, sizeof(de_ctx->config_prefix),
                "multi-detect.0");

    /* check for address-groups */
    result = (SCRuleVarsGetConfVar(de_ctx,"$HOME_NET", SC_RULE_VARS_ADDRESS_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(de_ctx,"$HOME_NET", SC_RULE_VARS_ADDRESS_GROUPS),
                      "[8.8.8.8]") == 0);
    if (result == 0)
        goto end;

    result = (SCRuleVarsGetConfVar(NULL,"$HOME_NET", SC_RULE_VARS_ADDRESS_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL,"$HOME_NET", SC_RULE_VARS_ADDRESS_GROUPS),
                      "[1.2.3.4]") == 0);
    if (result == 0)
        goto end;

    /* check for port-groups */
    result = (SCRuleVarsGetConfVar(de_ctx,"$HTTP_PORTS", SC_RULE_VARS_PORT_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(de_ctx,"$HTTP_PORTS", SC_RULE_VARS_PORT_GROUPS),
                      "54321") == 0);
    if (result == 0)
        goto end;

    result = (SCRuleVarsGetConfVar(NULL,"$HTTP_PORTS", SC_RULE_VARS_PORT_GROUPS) != NULL &&
               strcmp(SCRuleVarsGetConfVar(NULL,"$HTTP_PORTS", SC_RULE_VARS_PORT_GROUPS),
                      "12345") == 0);
    if (result == 0)
        goto end;

end:
    ConfDeInit();
    ConfRestoreContextBackup();

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

#endif /* UNITTESTS */

void SCRuleVarsRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SCRuleVarsPositiveTest01", SCRuleVarsPositiveTest01, 1);
    UtRegisterTest("SCRuleVarsNegativeTest02", SCRuleVarsNegativeTest02, 1);
    UtRegisterTest("SCRuleVarsPositiveTest03", SCRuleVarsPositiveTest03, 1);
    UtRegisterTest("SCRuleVarsNegativeTest04", SCRuleVarsNegativeTest04, 1);

    UtRegisterTest("SCRuleVarsMTest01", SCRuleVarsMTest01, 1);
#endif

    return;
}
