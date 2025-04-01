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
 * \author Giuseppe Longo <giuseppelng@gmail.com>
 *
 */

#include "suricata-common.h"
#include "defrag-config.h"
#include "util-misc.h"
#include "conf.h"
#include "util-radix4-tree.h"
#include "util-radix6-tree.h"

static void DefragPolicyFreeUserData(void *data)
{
    if (data != NULL)
        SCFree(data);
}

static SCRadix4Tree defrag4_tree = SC_RADIX4_TREE_INITIALIZER;
static SCRadix6Tree defrag6_tree = SC_RADIX6_TREE_INITIALIZER;
static SCRadix4Config defrag4_config = { DefragPolicyFreeUserData, NULL };
static SCRadix6Config defrag6_config = { DefragPolicyFreeUserData, NULL };

static int default_timeout = 0;

static void DefragPolicyAddHostInfo(const char *host_ip_range, uint64_t timeout)
{
    uint64_t *user_data = NULL;

    if ( (user_data = SCMalloc(sizeof(uint64_t))) == NULL) {
        FatalError("Error allocating memory. Exiting");
    }

    *user_data = timeout;

    if (strchr(host_ip_range, ':') != NULL) {
        SCLogDebug("adding ipv6 host %s", host_ip_range);
        if (!SCRadix6AddKeyIPV6String(
                    &defrag6_tree, &defrag6_config, host_ip_range, (void *)user_data)) {
            SCFree(user_data);
            if (sc_errno != SC_EEXIST) {
                SCLogWarning("failed to add ipv6 host %s", host_ip_range);
            }
        }
    } else {
        SCLogDebug("adding ipv4 host %s", host_ip_range);
        if (!SCRadix4AddKeyIPV4String(
                    &defrag4_tree, &defrag4_config, host_ip_range, (void *)user_data)) {
            if (sc_errno != SC_EEXIST) {
                SCLogWarning("failed to add ipv4 host %s", host_ip_range);
            }
        }
    }
}

static int DefragPolicyGetIPv4HostTimeout(const uint8_t *ipv4_addr)
{
    void *user_data = NULL;
    (void)SCRadix4TreeFindBestMatch(&defrag4_tree, ipv4_addr, &user_data);
    if (user_data == NULL)
        return -1;

    return *((int *)user_data);
}

static int DefragPolicyGetIPv6HostTimeout(const uint8_t *ipv6_addr)
{
    void *user_data = NULL;
    (void)SCRadix6TreeFindBestMatch(&defrag6_tree, ipv6_addr, &user_data);
    if (user_data == NULL)
        return -1;

    return *((int *)user_data);
}

int DefragPolicyGetHostTimeout(Packet *p)
{
    int timeout = 0;

    if (PacketIsIPv4(p))
        timeout = DefragPolicyGetIPv4HostTimeout((const uint8_t *)GET_IPV4_DST_ADDR_PTR(p));
    else if (PacketIsIPv6(p))
        timeout = DefragPolicyGetIPv6HostTimeout((const uint8_t *)GET_IPV6_DST_ADDR(p));

    if (timeout <= 0)
        timeout = default_timeout;

    return timeout;
}

static void DefragParseParameters(SCConfNode *n)
{
    SCConfNode *si;
    uint64_t timeout = 0;

    TAILQ_FOREACH(si, &n->head, next) {
        if (strcasecmp("timeout", si->name) == 0) {
            SCLogDebug("timeout value  %s", si->val);
            if (ParseSizeStringU64(si->val, &timeout) < 0) {
                SCLogError("Error parsing timeout "
                           "from conf file");
            }
        }
        if (strcasecmp("address", si->name) == 0) {
            SCConfNode *pval;
            TAILQ_FOREACH(pval, &si->head, next) {
                DefragPolicyAddHostInfo(pval->val, timeout);
            }
        }
    }
}

void DefragSetDefaultTimeout(int timeout)
{
    default_timeout = timeout;
    SCLogDebug("default timeout %d", default_timeout);
}

void DefragPolicyLoadFromConfig(void)
{
    SCEnter();

    SCConfNode *server_config = SCConfGetNode("defrag.host-config");
    if (server_config == NULL) {
        SCLogDebug("failed to read host config");
        SCReturn;
    }

    SCLogDebug("configuring host config %p", server_config);
    SCConfNode *sc;

    TAILQ_FOREACH(sc, &server_config->head, next) {
        SCConfNode *p = NULL;

        TAILQ_FOREACH(p, &sc->head, next) {
            SCLogDebug("parsing configuration for %s", p->name);
            DefragParseParameters(p);
        }
    }
}

void DefragTreeDestroy(void)
{
    SCRadix4TreeRelease(&defrag4_tree, &defrag4_config);
    SCRadix6TreeRelease(&defrag6_tree, &defrag6_config);
}
