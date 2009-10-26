/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __UTIL_RULE_VARS_H__
#define __UTIL_RULE_VARS_H__

/** Enum indicating the various vars type in the yaml conf file */
typedef enum {
    SC_RULE_VARS_ADDRESS_GROUPS,
    SC_RULE_VARS_PORT_GROUPS,
} SCRuleVarsType;

char *SCRuleVarsGetConfVar(const char *, SCRuleVarsType);
void SCRuleVarsRegisterTests(void);

#endif /* __UTIL_RULE_VARS_H__ */
