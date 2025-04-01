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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Host info utility functions
 */

#include "suricata-common.h"
#include "util-host-os-info.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-ip.h"
#include "util-radix4-tree.h"
#include "util-radix6-tree.h"
#include "util-byte.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "util-enum.h"
#include "util-unittest.h"

/** Enum map for the various OS flavours */
SCEnumCharMap sc_hinfo_os_policy_map[ ] = {
    { "none",        OS_POLICY_NONE },
    { "bsd",         OS_POLICY_BSD },
    { "bsd-right",   OS_POLICY_BSD_RIGHT },
    { "old-linux",   OS_POLICY_OLD_LINUX },
    { "linux",       OS_POLICY_LINUX },
    { "old-solaris", OS_POLICY_OLD_SOLARIS },
    { "solaris",     OS_POLICY_SOLARIS },
    { "hpux10",      OS_POLICY_HPUX10 },
    { "hpux11",      OS_POLICY_HPUX11 },
    { "irix",        OS_POLICY_IRIX },
    { "macos",       OS_POLICY_MACOS },
    { "windows",     OS_POLICY_WINDOWS },
    { "vista",       OS_POLICY_VISTA },
    { "windows2k3",  OS_POLICY_WINDOWS2K3 },
    { NULL,          -1 },
};

/** Radix trees that hold the host OS information */
static SCRadix4Tree sc_hinfo_tree4 = SC_RADIX4_TREE_INITIALIZER;
static SCRadix6Tree sc_hinfo_tree6 = SC_RADIX6_TREE_INITIALIZER;

/**
 * \brief Allocates the host_os flavour wrapped in user_data variable to be sent
 *        along with the key to the radix tree
 *
 * \param host_os Pointer to a character string containing the host_os flavour
 *
 * \retval user_data On success, pointer to the user_data that has to be sent
 *                   along with the key, to be added to the Radix tree; NULL on
 *                   failure
 * \initonly
 */
static void *SCHInfoAllocUserDataOSPolicy(const char *host_os)
{
    /* the host os flavour that has to be sent as user data */
    int v = SCMapEnumNameToValue(host_os, sc_hinfo_os_policy_map);
    if (v == -1) {
        SCLogError("Invalid enum map inside SCHInfoAddHostOSInfo()");
        return NULL;
    }

    int *user_data = SCMalloc(sizeof(int));
    if (user_data == NULL) {
        FatalError("Error allocating memory. Exiting");
    }
    *user_data = v;
    return (void *)user_data;
}

/**
 * \brief Used to free the user data that is allocated by host_os_info API
 *
 * \param Pointer to the data that has to be freed
 */
static void SCHInfoFreeUserDataOSPolicy(void *data)
{
    if (data != NULL)
        SCFree(data);
}

static const SCRadix4Config ospolicy_radix4_config = { SCHInfoFreeUserDataOSPolicy, NULL };
static const SCRadix6Config ospolicy_radix6_config = { SCHInfoFreeUserDataOSPolicy, NULL };

/**
 * \brief Used to add the host-os-info data obtained from the conf
 *
 * \param host_os          The host_os name/flavour from the conf file
 * \param host_os_ip_range Pointer to a char string holding the ip/ip_netblock
 *                         for the host_os specified in the first argument
 * \param is_ipv4          Indicates if the ip address to be considered for the
 *                         default configuration is IPV4; if not it is IPV6.
 *                         Specified using SC_HINFO_IS_IPV6 or SC_HINFO_IS_IPV4
 *
 * \retval  0 On successfully adding the host os info to the Radix tree
 * \retval -1 On failure
 * \initonly (only specified from config, at the startup)
 */
int SCHInfoAddHostOSInfo(const char *host_os, const char *host_os_ip_range, int is_ipv4)
{
    char *ip_str = NULL;
    char *ip_str_rem = NULL;
    int *user_data = NULL;
    bool recursive = false;

    if (host_os == NULL || host_os_ip_range == NULL ||
            strlen(host_os_ip_range) == 0) {
        SCLogError("Invalid arguments");
        return -1;
    }

    /* the host os flavour that has to be sent as user data */
    if ( (user_data = SCHInfoAllocUserDataOSPolicy(host_os)) == NULL) {
        SCLogError("Invalid enum map inside");
        return -1;
    }

    /* if we have a default configuration set the appropriate values for the
     * netblocks */
    if ( (strcasecmp(host_os_ip_range, "default")) == 0) {
        if (is_ipv4)
            host_os_ip_range = "0.0.0.0/0";
        else
            host_os_ip_range = "::/0";
    }

    if ( (ip_str = SCStrdup(host_os_ip_range)) == NULL) {
        FatalError("Error allocating memory");
    }

    /* check if we have more addresses in the host_os_ip_range */
    if ((ip_str_rem = strchr(ip_str, ',')) != NULL) {
        ip_str_rem[0] = '\0';
        ip_str_rem++;
        recursive = true;
    }

    if (strchr(ip_str, ':') == NULL) {
        if (!SCRadix4AddKeyIPV4String(
                    &sc_hinfo_tree4, &ospolicy_radix4_config, ip_str, user_data)) {
            if (sc_errno == SC_EEXIST) {
                SCLogError("duplicate ipv4 address '%s'", ip_str);
            } else {
                SCLogError("invalid ipv4 address '%s'", ip_str);
            }
            SCHInfoFreeUserDataOSPolicy(user_data);
            SCFree(ip_str);
            return -1;
        }
    } else {
        if (!SCRadix6AddKeyIPV6String(
                    &sc_hinfo_tree6, &ospolicy_radix6_config, ip_str, user_data)) {
            if (sc_errno == SC_EEXIST) {
                SCLogError("duplicate ipv6 address '%s'", ip_str);
            } else {
                SCLogError("invalid ipv6 address '%s'", ip_str);
            }
            SCHInfoFreeUserDataOSPolicy(user_data);
            SCFree(ip_str);
            return -1;
        }
    }

    if (recursive) {
        SCHInfoAddHostOSInfo(host_os, ip_str_rem, is_ipv4);
    }

    SCFree(ip_str);
    return *user_data;
}

#ifdef UNITTESTS
/**
 * \brief Retrieves the host os flavour, given an ipv4/ipv6 address as a string.
 *
 * \param Pointer to a string containing an IP address
 *
 * \retval The OS flavour on success; -1 on failure, or on not finding the key
 */
static int SCHInfoGetHostOSFlavour(const char *str)
{
    void *user_data = NULL;

    if (str == NULL || strchr(str, '/') != NULL)
        return -1;

    if (strchr(str, ':') != NULL) {
        struct in6_addr addr;
        if (inet_pton(AF_INET6, str, &addr) <= 0) {
            SCLogError("Invalid IPV6 address");
            return -1;
        }
        (void)SCRadix6TreeFindBestMatch(&sc_hinfo_tree6, (uint8_t *)&addr.s6_addr, &user_data);
        if (user_data == NULL)
            return -1;
        else
            return *((int *)user_data);
    } else {
        struct in_addr addr;
        if (inet_pton(AF_INET, str, &addr) <= 0) {
            SCLogError("Invalid IPV4 address");
            return -1;
        }
        (void)SCRadix4TreeFindBestMatch(&sc_hinfo_tree4, (uint8_t *)&addr.s_addr, &user_data);
        if (user_data == NULL)
            return -1;
        else
            return *((int *)user_data);
    }
}
#endif

/**
 * \brief Retrieves the host os flavour, given an ipv4 address in the raw
 *        address format.
 *
 * \param Pointer to a raw ipv4 address.
 *
 * \retval The OS flavour on success; -1 on failure, or on not finding the key
 */
int SCHInfoGetIPv4HostOSFlavour(uint8_t *addr)
{
    void *user_data = NULL;
    (void)SCRadix4TreeFindBestMatch(&sc_hinfo_tree4, addr, &user_data);
    if (user_data == NULL)
        return -1;
    return *((int *)user_data);
}

/**
 * \brief Retrieves the host os flavour, given an ipv6 address in the raw
 *        address format.
 *
 * \param Pointer to a raw ipv6 address.
 *
 * \retval The OS flavour on success; -1 on failure, or on not finding the key
 */
int SCHInfoGetIPv6HostOSFlavour(uint8_t *addr)
{
    void *user_data = NULL;
    (void)SCRadix6TreeFindBestMatch(&sc_hinfo_tree6, addr, &user_data);
    if (user_data == NULL)
        return -1;
    return *((int *)user_data);
}

void SCHInfoCleanResources(void)
{
    SCRadix4TreeRelease(&sc_hinfo_tree4, &ospolicy_radix4_config);
    SCRadix6TreeRelease(&sc_hinfo_tree6, &ospolicy_radix6_config);
}

/**
 * \brief Load the host os policy information from the configuration.
 *
 * \initonly (A mem alloc error should cause an exit failure)
 */
void SCHInfoLoadFromConfig(void)
{
    SCConfNode *root = SCConfGetNode("host-os-policy");
    if (root == NULL)
        return;

    SCConfNode *policy;
    TAILQ_FOREACH(policy, &root->head, next) {
        SCConfNode *host;
        TAILQ_FOREACH(host, &policy->head, next) {
            int is_ipv4 = 1;
            if (host->val != NULL && strchr(host->val, ':') != NULL)
                is_ipv4 = 0;
            if (SCHInfoAddHostOSInfo(policy->name, host->val, is_ipv4) == -1) {
                FatalError("Failed to add host \"%s\" with policy \"%s\" to host "
                           "info database",
                        host->val, policy->name);
            }
        }
    }
}

/*------------------------------------Unit_Tests------------------------------*/

#ifdef UNITTESTS
static SCRadix4Tree sc_hinfo_tree_backup4 = SC_RADIX4_TREE_INITIALIZER;
static SCRadix6Tree sc_hinfo_tree_backup6 = SC_RADIX6_TREE_INITIALIZER;

static void SCHInfoCreateContextBackup(void)
{
    sc_hinfo_tree_backup4 = sc_hinfo_tree4;
    sc_hinfo_tree4 = SCRadix4TreeInitialize();
    sc_hinfo_tree_backup6 = sc_hinfo_tree6;
    sc_hinfo_tree6 = SCRadix6TreeInitialize();
}

static void SCHInfoRestoreContextBackup(void)
{
    sc_hinfo_tree4 = sc_hinfo_tree_backup4;
    sc_hinfo_tree_backup4 = SCRadix4TreeInitialize();
    sc_hinfo_tree6 = sc_hinfo_tree_backup6;
    sc_hinfo_tree_backup6 = SCRadix6TreeInitialize();
}

/**
 * \test Check if we the IPs with the right OS flavours are added to the host OS
 *       radix tree, and the IPS with invalid flavours returns an error(-1)
 */
static int SCHInfoTestInvalidOSFlavour01(void)
{
    SCHInfoCreateContextBackup();

    FAIL_IF(SCHInfoAddHostOSInfo("bamboo", "192.168.1.1", SC_HINFO_IS_IPV4) != -1);
    FAIL_IF(SCHInfoAddHostOSInfo("linux", "192.168.1.2", SC_HINFO_IS_IPV4) !=
            SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map));
    FAIL_IF(SCHInfoAddHostOSInfo("windows", "192.168.1.3", SC_HINFO_IS_IPV4) !=
            SCMapEnumNameToValue("windows", sc_hinfo_os_policy_map));
    FAIL_IF(SCHInfoAddHostOSInfo("solaris", "192.168.1.4", SC_HINFO_IS_IPV4) !=
            SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map));
    FAIL_IF(SCHInfoAddHostOSInfo("hpux10", "192.168.1.5", SC_HINFO_IS_IPV4) !=
            SCMapEnumNameToValue("hpux10", sc_hinfo_os_policy_map));
    FAIL_IF(SCHInfoAddHostOSInfo("hpux11", "192.168.1.6", SC_HINFO_IS_IPV4) !=
            SCMapEnumNameToValue("hpux11", sc_hinfo_os_policy_map));
    FAIL_IF(SCHInfoAddHostOSInfo("irix", "192.168.1.7", SC_HINFO_IS_IPV4) !=
            SCMapEnumNameToValue("irix", sc_hinfo_os_policy_map));
    FAIL_IF(SCHInfoAddHostOSInfo("bsd", "192.168.1.8", SC_HINFO_IS_IPV4) !=
            SCMapEnumNameToValue("bsd", sc_hinfo_os_policy_map));
    FAIL_IF(SCHInfoAddHostOSInfo("old_linux", "192.168.1.9", SC_HINFO_IS_IPV4) !=
            SCMapEnumNameToValue("old_linux", sc_hinfo_os_policy_map));
    FAIL_IF(SCHInfoAddHostOSInfo("macos", "192.168.1.10", SC_HINFO_IS_IPV4) !=
            SCMapEnumNameToValue("macos", sc_hinfo_os_policy_map));
    FAIL_IF(SCHInfoAddHostOSInfo("vista", "192.168.1.11", SC_HINFO_IS_IPV4) !=
            SCMapEnumNameToValue("vista", sc_hinfo_os_policy_map));
    FAIL_IF(SCHInfoAddHostOSInfo("windows2k3", "192.168.1.12", SC_HINFO_IS_IPV4) !=
            SCMapEnumNameToValue("windows2k3", sc_hinfo_os_policy_map));

    SCHInfoCleanResources();
    SCHInfoRestoreContextBackup();

    PASS;
}

/**
 * \test Check that invalid ipv4 addresses and ipv4 netblocks are rejected by
 *       the host os info API
 */
static int SCHInfoTestInvalidIPV4Address02(void)
{
    SCHInfoCreateContextBackup();

    int result = 0;

    if (SCHInfoAddHostOSInfo("linux", "192.168.1.566", SC_HINFO_IS_IPV4) != -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux", "192.168.1", SC_HINFO_IS_IPV4) != -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux", "192.", SC_HINFO_IS_IPV4) != -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux", "192.168", SC_HINFO_IS_IPV4) != -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux", "", SC_HINFO_IS_IPV4) != -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux", "192.168.1.1/33", SC_HINFO_IS_IPV4) != -1) {
        goto end;
    }

    result = 1;

 end:
    SCHInfoCleanResources();
    SCHInfoRestoreContextBackup();

    return result;
}

/**
 * \test Check that invalid ipv4 addresses and ipv4 netblocks are rejected by
 *       the host os info API
 */
static int SCHInfoTestInvalidIPV6Address03(void)
{
    SCHInfoCreateContextBackup();

    int result = 0;

    if (SCHInfoAddHostOSInfo("linux", "2362:7322", SC_HINFO_IS_IPV6) != -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux", "19YW:", SC_HINFO_IS_IPV6) != -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux", "1235", SC_HINFO_IS_IPV6) != -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux", "1922:236115:", SC_HINFO_IS_IPV6) != -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux", "", SC_HINFO_IS_IPV6) != -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux",
                             "1921.6311:6241:6422:7352:ABBB:DDDD:EEEE/129",
                             SC_HINFO_IS_IPV6) != -1) {
        goto end;
    }

    result = 1;

 end:
    SCHInfoCleanResources();
    SCHInfoRestoreContextBackup();

    return result;
}

/**
 * \test Check that valid ipv4 addresses are inserted into the host os radix
 *       tree, and the host os api retrieves the right value for the host os
 *       flavour, on supplying as arg an ipv4 addresses that has been added to
 *       the host os radix tree.
 */
static int SCHInfoTestValidIPV4Address04(void)
{
    SCHInfoCreateContextBackup();

    int result = 0;

    if (SCHInfoAddHostOSInfo("linux", "192.168.1.1", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("windows", "192.192.1.2", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris", "192.168.1.100", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("hpux10", "192.168.2.4", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux", "192.192.1.5", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("vista", "192.168.10.20", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris", "111.163.151.62", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris", "11.1.120.210", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux", "19.18.110.210", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("windows", "19.18.120.110", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("hpux11", "191.168.11.128", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("vista", "191.168.11.192", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }

    if (SCHInfoGetHostOSFlavour("192.168.1.1") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("192.168.1.2") != -1) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("192.168.1.100") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("192.192.2.4") != -1) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("192.168.2.4") !=
        SCMapEnumNameToValue("hpux10", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("192.192.1.5") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("192.168.10.20") !=
        SCMapEnumNameToValue("vista", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("111.163.151.62") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("11.1.120.210") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("19.18.110.210") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("19.18.120.110") !=
        SCMapEnumNameToValue("windows", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("191.168.11.128") !=
        SCMapEnumNameToValue("hpux11", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("191.168.11.192") !=
        SCMapEnumNameToValue("vista", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("191.168.11.224") != -1) {
        goto end;
    }

    result = 1;

 end:
    SCHInfoCleanResources();
    SCHInfoRestoreContextBackup();

    return result;
}

/**
 * \test Check that valid ipv4 addresses/netblocks are inserted into the host os
 *       radix tree, and the host os api retrieves the right value for the host
 *       os flavour, on supplying as arg an ipv4 addresses that has been added
 *       to the host os radix tree.
 */
static int SCHInfoTestValidIPV4Address05(void)
{
    SCHInfoCreateContextBackup();

    struct in_addr in;
    int result = 0;

    if (SCHInfoAddHostOSInfo("linux", "192.168.1.1", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("windows", "192.192.1.2", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris", "192.168.1.100", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("hpux10", "192.168.2.4", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux", "192.192.1.5", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("vista", "192.168.10.20", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris", "111.163.151.62", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("hpux11", "111.162.208.124/20", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("windows", "111.162.240.1", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris", "111.162.214.100", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("vista", "111.162.208.100", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux", "111.162.194.112", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }

    if (SCHInfoGetHostOSFlavour("192.168.1.1") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("192.168.1.2") != -1) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("192.168.1.100") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("192.192.2.4") != -1) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("192.168.2.4") !=
        SCMapEnumNameToValue("hpux10", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("192.192.1.5") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("192.168.10.20") !=
        SCMapEnumNameToValue("vista", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("111.163.151.62") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("111.162.208.0") !=
        SCMapEnumNameToValue("hpux11", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("111.162.210.1") !=
        SCMapEnumNameToValue("hpux11", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("111.162.214.1") !=
        SCMapEnumNameToValue("hpux11", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("111.162.0.0") != -1) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("111.162.240.112") != -1) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("111.162.240.1") !=
        SCMapEnumNameToValue("windows", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("111.162.214.100") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (inet_pton(AF_INET, "111.162.208.100", &in) < 0) {
        goto end;
    }
    if (SCHInfoGetIPv4HostOSFlavour((uint8_t *)&in) !=
        SCMapEnumNameToValue("vista", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("111.162.194.112") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("111.162.208.200") !=
        SCMapEnumNameToValue("hpux11", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (inet_pton(AF_INET, "111.162.208.200", &in) < 0) {
        goto end;
    }
    if (SCHInfoGetIPv4HostOSFlavour((uint8_t *)&in) !=
        SCMapEnumNameToValue("hpux11", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("111.162.200.201") != -1) {
        goto end;
    }

    result = 1;

 end:
    SCHInfoCleanResources();
    SCHInfoRestoreContextBackup();

    return result;
}

/**
 * \test Check that valid ipv6 addresses are inserted into the host os radix
 *       tree, and the host os api retrieves the right value for the host os
 *       flavour, on supplying as arg an ipv6 address that has been added to
 *       the host os radix tree.
 */
static int SCHInfoTestValidIPV6Address06(void)
{
    SCHInfoCreateContextBackup();

    int result = 0;

    if (SCHInfoAddHostOSInfo("linux",
                             "2351:2512:6211:6246:235A:6242:2352:62AD",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("windows",
                             "6961:6121:2132:6241:423A:2135:2461:621D",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris",
                             "DD13:613D:F312:62DD:6213:421A:6212:2652",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("hpux10",
                             "9891:2131:2151:6426:1342:674D:622F:2342",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux",
                             "3525:2351:4223:6211:2311:2667:6242:2154",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("vista",
                             "1511:6211:6726:7777:1212:2333:6222:7722",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris",
                             "2666:6222:7222:2335:6223:7722:3425:2362",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris",
                             "8762:2352:6241:7245:EE23:21AD:2312:622C",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux",
                             "6422:EE1A:2621:34AD:2462:432D:642E:E13A",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("windows",
                             "3521:7622:6241:6242:7277:1234:2352:6234",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("hpux11",
                             "2141:6232:6252:2223:7734:2345:6245:6222",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("vista",
                             "5222:6432:6432:2322:6662:3423:4322:3245",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }

    if (SCHInfoGetHostOSFlavour("2351:2512:6211:6246:235A:6242:2352:62AD") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("2351:2512:6211:6246:235A:6242:2352:6FFFE") != -1) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("DD13:613D:F312:62DD:6213:421A:6212:2652") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("DD13:613D:F312:62DD:6213:421A:6212:2222") != -1) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("9891:2131:2151:6426:1342:674D:622F:2342") !=
        SCMapEnumNameToValue("hpux10", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("3525:2351:4223:6211:2311:2667:6242:2154") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("1511:6211:6726:7777:1212:2333:6222:7722") !=
        SCMapEnumNameToValue("vista", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("2666:6222:7222:2335:6223:7722:3425:2362") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:2312:622C") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("6422:EE1A:2621:34AD:2462:432D:642E:E13A") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("3521:7622:6241:6242:7277:1234:2352:6234") !=
        SCMapEnumNameToValue("windows", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("2141:6232:6252:2223:7734:2345:6245:6222") !=
        SCMapEnumNameToValue("hpux11", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("5222:6432:6432:2322:6662:3423:4322:3245") !=
        SCMapEnumNameToValue("vista", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("5222:6432:6432:2322:6662:3423:4322:DDDD") != -1) {
        goto end;
    }

    result = 1;

 end:
    SCHInfoCleanResources();
    SCHInfoRestoreContextBackup();

    return result;
}

/**
 * \test Check that valid ipv6 addresses/netblocks are inserted into the host os
 *       radix tree, and the host os api retrieves the right value for the host
 *       os flavour, on supplying as arg an ipv6 address that has been added to
 *       the host os radix tree.
 */
static int SCHInfoTestValidIPV6Address07(void)
{
    SCHInfoCreateContextBackup();

    int result = 0;

    if (SCHInfoAddHostOSInfo("linux",
                             "2351:2512:6211:6246:235A:6242:2352:62AD",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("windows",
                             "6961:6121:2132:6241:423A:2135:2461:621D",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris",
                             "DD13:613D:F312:62DD:6213:421A:6212:2652",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("hpux10",
                             "9891:2131:2151:6426:1342:674D:622F:2342",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux",
                             "3525:2351:4223:6211:2311:2667:6242:2154",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("vista",
                             "1511:6211:6726:7777:1212:2333:6222:7722",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris",
                             "2666:6222:7222:2335:6223:7722:3425:2362",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris",
                             "8762:2352:6241:7245:EE23:21AD:2312:622C/68",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux",
                             "8762:2352:6241:7245:EE23:21AD:2412:622C",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("windows",
                             "8762:2352:6241:7245:EE23:21AD:FFFF:622C",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("hpux11",
                             "8762:2352:6241:7245:EE23:21AD:2312:62FF",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("vista",
                             "8762:2352:6241:7245:EE23:21AD:2121:1212",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }

    if (SCHInfoGetHostOSFlavour("2351:2512:6211:6246:235A:6242:2352:62AD") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("2351:2512:6211:6246:235A:6242:2352:6FFFE") != -1) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("DD13:613D:F312:62DD:6213:421A:6212:2652") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("DD13:613D:F312:62DD:6213:421A:6212:2222") != -1) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("9891:2131:2151:6426:1342:674D:622F:2342") !=
        SCMapEnumNameToValue("hpux10", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("3525:2351:4223:6211:2311:2667:6242:2154") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("1511:6211:6726:7777:1212:2333:6222:7722") !=
        SCMapEnumNameToValue("vista", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("2666:6222:7222:2335:6223:7722:3425:2362") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:2312:622C") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:2412:622C") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:FFFF:622C") !=
        SCMapEnumNameToValue("windows", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:2312:62FF") !=
        SCMapEnumNameToValue("hpux11", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:2121:1212") !=
        SCMapEnumNameToValue("vista", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("5222:6432:6432:2322:6662:3423:4322:DDDD") != -1) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:2121:1DDD") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:FFFF:2121:1DDD") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:2312:622C") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE00:0000:0000:0000") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:E000:0000:0000:0000") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }

    result = 1;

 end:
    SCHInfoCleanResources();
    SCHInfoRestoreContextBackup();

    return result;
}

/**
 * \test Check that valid ipv6 addresses/netblocks are inserted into the host os
 *       radix tree, and the host os api retrieves the right value for the host
 *       os flavour, on supplying as arg an ipv6 address that has been added to
 *       the host os radix tree.
 */
static int SCHInfoTestValidIPV6Address08(void)
{
    SCHInfoCreateContextBackup();

    struct in6_addr in6;
    int result = 0;

    if (SCHInfoAddHostOSInfo("linux",
                             "2351:2512:6211:6246:235A:6242:2352:62AD",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("windows",
                             "6961:6121:2132:6241:423A:2135:2461:621D",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris",
                             "DD13:613D:F312:62DD:6213:421A:6212:2652",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("hpux10",
                             "9891:2131:2151:6426:1342:674D:622F:2342",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux",
                             "3525:2351:4223:6211:2311:2667:6242:2154",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("vista",
                             "1511:6211:6726:7777:1212:2333:6222:7722",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris",
                             "2666:6222:7222:2335:6223:7722:3425:2362",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("solaris",
                             "8762:2352:6241:7245:EE23:21AD:2312:622C/68",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("linux",
                             "8762:2352:6241:7245:EE23:21AD:2412:622C",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("windows",
                             "8762:2352:6241:7245:EE23:21AD:FFFF:622C",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("hpux11",
                             "8762:2352:6241:7245:EE23:21AD:2312:62FF",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("vista",
                             "8762:2352:6241:7245:EE23:21AD:2121:1212",
                             SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("vista", "8.8.8.0/24", SC_HINFO_IS_IPV4) == -1) {
        goto end;
    }
    if (SCHInfoAddHostOSInfo("irix", "default", SC_HINFO_IS_IPV6) == -1) {
        goto end;
    }

    if (SCHInfoGetHostOSFlavour("2351:2512:6211:6246:235A:6242:2352:62AD") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("2351:2512:6211:6246:235A:6242:2352:6FFF") !=
        SCMapEnumNameToValue("irix", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("DD13:613D:F312:62DD:6213:421A:6212:2652") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("DD13:613D:F312:62DD:6213:421A:6212:2222") !=
        SCMapEnumNameToValue("irix", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("9891:2131:2151:6426:1342:674D:622F:2342") !=
        SCMapEnumNameToValue("hpux10", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("3525:2351:4223:6211:2311:2667:6242:2154") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("1511:6211:6726:7777:1212:2333:6222:7722") !=
        SCMapEnumNameToValue("vista", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("2666:6222:7222:2335:6223:7722:3425:2362") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:2312:622C") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:2412:622C") !=
        SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:FFFF:622C") !=
        SCMapEnumNameToValue("windows", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:2312:62FF") !=
        SCMapEnumNameToValue("hpux11", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:2121:1212") !=
        SCMapEnumNameToValue("vista", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("5222:6432:6432:2322:6662:3423:4322:DDDD") !=
        SCMapEnumNameToValue("irix", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:2121:1DDD") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:FFFF:2121:1DDD") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE23:21AD:2312:622C") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8762:2352:6241:7245:EE00:0000:0000:0000") !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (inet_pton(AF_INET6, "8762:2352:6241:7245:E000:0000:0000:0000", &in6) < 0) {
        goto end;
    }
    if (SCHInfoGetIPv6HostOSFlavour((uint8_t *)&in6) !=
        SCMapEnumNameToValue("solaris", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (inet_pton(AF_INET6, "AD23:2DDA:6D1D:A223:E235:0232:1241:1666", &in6) < 0) {
        goto end;
    }
    if (SCHInfoGetIPv6HostOSFlavour((uint8_t *)&in6) !=
        SCMapEnumNameToValue("irix", sc_hinfo_os_policy_map)) {
        goto end;
    }
    if (SCHInfoGetHostOSFlavour("8.8.8.8") !=
            SCMapEnumNameToValue("vista", sc_hinfo_os_policy_map)) {
        goto end;
    }
    result = 1;

 end:
    SCHInfoCleanResources();
    SCHInfoRestoreContextBackup();

    return result;
}

/**
 * \test Check that valid ipv4 addresses are inserted into the host os radix
 *       tree, and the host os api retrieves the right value for the host os
 *       flavour, on supplying as arg an ipv4 addresses that has been added to
 *       the host os radix tree.
 */
static int SCHInfoTestValidIPV4Address09(void)
{
    SCHInfoCreateContextBackup();

    FAIL_IF(SCHInfoAddHostOSInfo("linux", "192.168.1.0", SC_HINFO_IS_IPV4) == -1);
    FAIL_IF(SCHInfoAddHostOSInfo("windows", "192.192.1.2", SC_HINFO_IS_IPV4) == -1);
    FAIL_IF(SCHInfoGetHostOSFlavour("192.168.1.0") !=
            SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map));
    FAIL_IF(SCHInfoAddHostOSInfo("solaris", "192.168.1.0/16", SC_HINFO_IS_IPV4) == -1);
    FAIL_IF(SCHInfoAddHostOSInfo("macos", "192.168.1.0/20", SC_HINFO_IS_IPV4) == -1);
    FAIL_IF(SCHInfoGetHostOSFlavour("192.168.1.0") !=
            SCMapEnumNameToValue("linux", sc_hinfo_os_policy_map));
    FAIL_IF(SCHInfoAddHostOSInfo("vista", "192.168.50.128/25", SC_HINFO_IS_IPV4) == -1);
    FAIL_IF(SCHInfoGetHostOSFlavour("192.168.50.128") !=
            SCMapEnumNameToValue("vista", sc_hinfo_os_policy_map));
    FAIL_IF(SCHInfoAddHostOSInfo("irix", "192.168.50.128", SC_HINFO_IS_IPV4) == -1);
    FAIL_IF(SCHInfoGetHostOSFlavour("192.168.50.128") !=
            SCMapEnumNameToValue("irix", sc_hinfo_os_policy_map));
    FAIL_IF(SCHInfoGetHostOSFlavour("192.168.1.100") !=
            SCMapEnumNameToValue("macos", sc_hinfo_os_policy_map));

    SCHInfoCleanResources();
    SCHInfoRestoreContextBackup();
    PASS;
}

/**
 * \test Check the loading of host info from a configuration file.
 */
static int SCHInfoTestLoadFromConfig01(void)
{
    char config[] = "\
%YAML 1.1\n\
---\n\
host-os-policy:\n\
  bsd: [0.0.0.0/0]\n\
  windows: [10.0.0.0/8, 192.168.1.0/24]\n\
  linux: [10.0.0.5/32]\n\
\n";

    int result = 0;

    SCHInfoCreateContextBackup();

    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(config, strlen(config));

    SCHInfoLoadFromConfig();
    if (SCHInfoGetHostOSFlavour("10.0.0.4") != OS_POLICY_WINDOWS)
        goto end;
    if (SCHInfoGetHostOSFlavour("10.0.0.5") != OS_POLICY_LINUX)
        goto end;
    if (SCHInfoGetHostOSFlavour("192.168.1.1") != OS_POLICY_WINDOWS)
        goto end;
    if (SCHInfoGetHostOSFlavour("172.168.1.1") != OS_POLICY_BSD)
        goto end;

    result = 1;

 end:
     SCConfDeInit();
     SCConfRestoreContextBackup();

     SCHInfoRestoreContextBackup();

     return result;
}

/**
 * \test Check the loading of host info from a configuration file.
 */
static int SCHInfoTestLoadFromConfig02(void)
{
    char config[] = "\
%YAML 1.1\n\
---\n\
host-os-policy:\n\
  one-two: [0.0.0.0/0]\n\
  one-two-three:\n\
  four_five:\n\
  six-seven_eight: [10.0.0.0/8, 192.168.1.0/24]\n\
  nine_ten_eleven: [10.0.0.5/32]\n\
\n";

    int result = 0;

    SCHInfoCreateContextBackup();

    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(config, strlen(config));

    SCConfNode *root = SCConfGetNode("host-os-policy");
    if (root == NULL)
        goto end;

    int count = 0;

    SCConfNode *policy;
    TAILQ_FOREACH(policy, &root->head, next) {
        switch (count) {
            case 0:
                if (strcmp("one-two", policy->name) != 0)
                    goto end;
                break;
            case 1:
                if (strcmp("one-two-three", policy->name) != 0)
                    goto end;
                break;
            case 2:
                if (strcmp("four-five", policy->name) != 0)
                    goto end;
                break;
            case 3:
                if (strcmp("six-seven-eight", policy->name) != 0)
                    goto end;
                break;
            case 4:
                if (strcmp("nine-ten-eleven", policy->name) != 0)
                    goto end;
                break;
        }
        count++;
    }

    result = 1;

 end:
     SCConfDeInit();
     SCConfRestoreContextBackup();

     SCHInfoRestoreContextBackup();

     return result;
}

/**
 * \test Check the loading of host info from a configuration file.
 */
static int SCHInfoTestLoadFromConfig03(void)
{
    char config[] = "\
%YAML 1.1\n\
---\n\
host-os-policy:\n\
  bsd-right: [0.0.0.1]\n\
  old-linux: [0.0.0.2]\n\
  old-solaris: [0.0.0.3]\n\
  windows: [0.0.0.4]\n\
  vista: [0.0.0.5]\n\
\n";

    int result = 0;

    SCHInfoCreateContextBackup();

    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(config, strlen(config));

    SCConfNode *root = SCConfGetNode("host-os-policy");
    if (root == NULL)
        goto end;

    SCConfNode *policy;
    TAILQ_FOREACH(policy, &root->head, next) {
        if (SCMapEnumNameToValue(policy->name, sc_hinfo_os_policy_map) == -1) {
            printf("Invalid enum map inside\n");
            goto end;
        }
    }

    result = 1;

 end:
     SCConfDeInit();
     SCConfRestoreContextBackup();

     SCHInfoRestoreContextBackup();
     return result;
}

/**
 * \test Check the loading of host info from a configuration file.
 */
static int SCHInfoTestLoadFromConfig04(void)
{
    char config[] = "\
%YAML 1.1\n\
---\n\
host-os-policy:\n\
  bsd_right: [0.0.0.1]\n\
  old_linux: [0.0.0.2]\n\
  old_solaris: [0.0.0.3]\n\
  windows: [0.0.0.4]\n\
  vista: [0.0.0.5]\n\
\n";

    int result = 0;

    SCHInfoCreateContextBackup();

    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(config, strlen(config));

    SCConfNode *root = SCConfGetNode("host-os-policy");
    if (root == NULL)
        goto end;

    SCConfNode *policy;
    TAILQ_FOREACH(policy, &root->head, next) {
        if (SCMapEnumNameToValue(policy->name, sc_hinfo_os_policy_map) == -1) {
            printf("Invalid enum map inside\n");
            goto end;
        }
    }

    result = 1;

 end:
     SCConfDeInit();
     SCConfRestoreContextBackup();

     SCHInfoRestoreContextBackup();
     return result;
}

/**
 * \test Check the loading of host info from a configuration file.
 */
static int SCHInfoTestLoadFromConfig05(void)
{
    char config[] = "\
%YAML 1.1\n\
---\n\
host-os-policy:\n\
  bsd_right: [0.0.0.1]\n\
  old_linux: [0.0.0.2]\n\
  old-solaris: [0.0.0.3]\n\
  windows: [0.0.0.4]\n\
  linux: [0.0.0.5]\n\
\n";

    SCHInfoCreateContextBackup();

    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(config, strlen(config));
    SCHInfoLoadFromConfig();

    FAIL_IF (SCHInfoGetHostOSFlavour("0.0.0.1") != OS_POLICY_BSD_RIGHT);
    FAIL_IF (SCHInfoGetHostOSFlavour("0.0.0.2") != OS_POLICY_OLD_LINUX);
    FAIL_IF (SCHInfoGetHostOSFlavour("0.0.0.3") != OS_POLICY_OLD_SOLARIS);
    FAIL_IF (SCHInfoGetHostOSFlavour("0.0.0.4") != OS_POLICY_WINDOWS);
    FAIL_IF (SCHInfoGetHostOSFlavour("0.0.0.5") != OS_POLICY_LINUX);
    FAIL_IF (SCHInfoGetHostOSFlavour("0.0.0.0") != -1);
    FAIL_IF (SCHInfoGetHostOSFlavour("0.0.0.6") != -1);

    SCConfDeInit();
    SCConfRestoreContextBackup();
    SCHInfoRestoreContextBackup();
    PASS;
}

#endif /* UNITTESTS */

void SCHInfoRegisterTests(void)
{

#ifdef UNITTESTS

    UtRegisterTest("SCHInfoTestInvalidOSFlavour01", SCHInfoTestInvalidOSFlavour01);
    UtRegisterTest("SCHInfoTestInvalidIPV4Address02",
                   SCHInfoTestInvalidIPV4Address02);
    UtRegisterTest("SCHInfoTestInvalidIPV6Address03",
                   SCHInfoTestInvalidIPV6Address03);
    UtRegisterTest("SCHInfoTestValidIPV4Address04",
                   SCHInfoTestValidIPV4Address04);
    UtRegisterTest("SCHInfoTestValidIPV4Address05",
                   SCHInfoTestValidIPV4Address05);
    UtRegisterTest("SCHInfoTestValidIPV6Address06",
                   SCHInfoTestValidIPV6Address06);
    UtRegisterTest("SCHInfoTestValidIPV6Address07",
                   SCHInfoTestValidIPV6Address07);
    UtRegisterTest("SCHInfoTestValidIPV6Address08",
                   SCHInfoTestValidIPV6Address08);
    UtRegisterTest("SCHInfoTestValidIPV4Address09",
                   SCHInfoTestValidIPV4Address09);

    UtRegisterTest("SCHInfoTestLoadFromConfig01", SCHInfoTestLoadFromConfig01);
    UtRegisterTest("SCHInfoTestLoadFromConfig02", SCHInfoTestLoadFromConfig02);
    UtRegisterTest("SCHInfoTestLoadFromConfig03", SCHInfoTestLoadFromConfig03);
    UtRegisterTest("SCHInfoTestLoadFromConfig04", SCHInfoTestLoadFromConfig04);
    UtRegisterTest("SCHInfoTestLoadFromConfig05", SCHInfoTestLoadFromConfig05);
#endif /* UNITTESTS */
}
