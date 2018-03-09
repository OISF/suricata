/* Copyright (C) 2018 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 * \author Giuseppe Longo <glongo@stamus-networks.com>
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "conf.h"
#include "detect-engine.h"
#include "util-network-tree.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

/* workaround for old libjansson on Centos */
#ifndef json_array_foreach
#define json_array_foreach(array, index, value) \
    for(index = 0; \
        index < json_array_size(array) && (value = json_array_get(array, index)); \
        index++)
#endif

typedef struct NetworkTreeElt_ {
    const char *name;
    struct NetworkTreeElt_ *next;
} NetworkTreeElt;

typedef struct NetworkTree_ {
    int tenant_id;
    int ref_cnt;
    SCRadixTree *tree_v4;
    SCRadixTree *tree_v6;
} NetworkTree;

typedef struct NetworkTreeMaster_ {
    SCMutex lock;
    NetworkTree *tree;
    HashTable *mt_trees_hash;
} NetworkTreeMaster;

static NetworkTreeMaster g_master_net_tree = { SCMUTEX_INITIALIZER, NULL, NULL };

static uint32_t NetworkTreeTenantIdHash(HashTable *h, void *data, uint16_t data_len);
static char NetworkTreeTenantIdCompare(void *d1, uint16_t d1_len, void *d2, uint16_t d2_len);
static void NetworkTreeTenantIdFree(void *d);
static void NetworkTreeFreeInstance(NetworkTree *ntree);

static uint32_t NetworkTreeTenantIdHash(HashTable *h, void *data, uint16_t data_len)
{
    NetworkTree *ntree = (NetworkTree *)data;
    return ntree->tenant_id % h->array_size;
}

static char NetworkTreeTenantIdCompare(void *d1, uint16_t d1_len, void *d2, uint16_t d2_len)
{
    NetworkTree *ntree1 = (NetworkTree *)d1;
    NetworkTree *ntree2 = (NetworkTree *)d2;
    return (ntree1->tenant_id == ntree2->tenant_id);
}

static void NetworkTreeTenantIdFree(void *d)
{
    NetworkTreeFreeInstance(d);
}

static void NetworkTreeEltFree(NetworkTreeElt *elt)
{
    NetworkTreeElt *pelt;

    while (elt) {
        if (elt->name)
            SCFree((void *)elt->name);
        pelt = elt;
        elt = elt->next;
        SCFree(pelt);
    }
}
static NetworkTreeElt *NetworkTreeEltCopy(NetworkTreeElt *elt)
{
    NetworkTreeElt *new_elt = NULL;
    NetworkTreeElt *l_elt, *last_elt = NULL;

    while (elt) {
        l_elt = SCCalloc(1, sizeof(*l_elt));
        if (l_elt == NULL)
            goto error;
        if (new_elt == NULL) {
            new_elt = l_elt;
            last_elt = new_elt;
        } else {
            last_elt->next = l_elt;
            last_elt = l_elt;
        }
        l_elt->name = SCStrdup(elt->name);
        if (l_elt->name == NULL)
            goto error;
        l_elt->next = NULL;
        elt = elt->next;
        last_elt = l_elt;
    }
    return new_elt;

error:
    SCLogError(SC_ERR_MEM_ALLOC,
               "Memory allocation failure "
               "when copying network tree element");
    NetworkTreeEltFree(new_elt);
    return NULL;
}

static NetworkTreeElt *NetworkTreeEltAdd(NetworkTreeElt *elt, const char *name)
{
    NetworkTreeElt *new_elt = SCCalloc(1, sizeof(*new_elt));
    if (new_elt == NULL)
        return NULL;
    new_elt->name = SCStrdup(name);
    if (new_elt->name == NULL) {
        SCFree(new_elt);
        return NULL;
    }
    new_elt->next = elt;
    return new_elt;
}

static void NetworkTreeFreeUserData(void *data)
{
    NetworkTreeElt *ldata = (NetworkTreeElt *) data;
    return NetworkTreeEltFree(ldata);
}

static json_t *NetworkTreeEltAsJSON(NetworkTreeElt *elt)
{
    json_t *ejson = NULL;
    if (elt == NULL)
        return NULL;
    ejson = json_array();
    if (ejson == NULL)
        return NULL;
    while (elt) {
        json_array_append_new(ejson, json_string(elt->name));
        elt = elt->next;
    }
    return ejson;
}

static NetworkTree *NetworkTreeCreateInstance(int tenant_id)
{
    NetworkTree *ntree = SCMalloc(sizeof(NetworkTree));
    if (ntree == NULL)
        return NULL;

    ntree->tree_v4 = SCRadixCreateRadixTree(NetworkTreeFreeUserData, NULL);
    if (ntree->tree_v4 == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
                   "Can't alloc memory for the network tree.");
        SCFree(ntree);
        return NULL;
    }

    ntree->tree_v6 = SCRadixCreateRadixTree(NetworkTreeFreeUserData, NULL);
    if (ntree->tree_v6 == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
                   "Can't alloc memory for the network tree.");
        SCFree(ntree->tree_v4);
        SCFree(ntree);
        return NULL;
    }

    ntree->tenant_id = tenant_id;
    ntree->ref_cnt = 0;

    return ntree;
}

static void NetworkTreeFreeInstance(NetworkTree *ntree)
{
    if (ntree->ref_cnt == 0) {
        SCRadixReleaseRadixTree(ntree->tree_v4);
        SCRadixReleaseRadixTree(ntree->tree_v6);
        SCFree(ntree);
        ntree = NULL;
    }
}

static int ParseIPV4String(const char *str, uint32_t *ip, uint8_t *netmask)
{
    char ip_str[32]; /* Max length for full ipv4/mask string with NUL */
    char *mask_str = NULL;
    struct in_addr addr;

    /* Make a copy of the string so it can be modified */
    strlcpy(ip_str, str, sizeof(ip_str) - 2);
    *(ip_str + (sizeof(ip_str) - 1)) = '\0';

    *netmask = 32;

    /* Does it have a mask? */
    if (NULL != (mask_str = strchr(ip_str, '/'))) {
        int cidr;
        *(mask_str++) = '\0';

        /* Dotted type netmask not supported (yet) */
        if (strchr(mask_str, '.') != NULL) {
            return -1;
        }

        /* Get binary values for cidr mask */
        cidr = atoi(mask_str);
        if ((cidr < 0) || (cidr > 32)) {
            return -1;
        }
        *netmask = (uint8_t)cidr;
    }

    /* Validate the IP */
    if (inet_pton(AF_INET, ip_str, &addr) <= 0) {
        return -1;
    }
    *ip = addr.s_addr;
    return 0;
}

static int ParseIPV6String(const char *str, struct in6_addr *addr, uint8_t *netmask)
{
    char ip_str[80]; /* Max length for full ipv6/mask string with NUL */
    char *mask_str = NULL;

    /* Make a copy of the string so it can be modified */
    strlcpy(ip_str, str, sizeof(ip_str) - 2);
    *(ip_str + sizeof(ip_str) - 1) = '\0';

    *netmask = 128;

    /* Does it have a mask? */
    if (NULL != (mask_str = strchr(ip_str, '/'))) {
        int cidr;
        *(mask_str++) = '\0';

        /* Dotted type netmask not supported (yet) */
        if (strchr(mask_str, '.') != NULL) {
            return -1;
        }

        /* Get binary values for cidr mask */
        cidr = atoi(mask_str);
        if ((cidr < 0) || (cidr > 128)) {
            return -1;
        }
        *netmask = (uint8_t)cidr;
    }

    /* Validate the IP */
    if (inet_pton(AF_INET6, ip_str, addr) <= 0) {
        return -1;
    }
    return 0;
}

/**
 * \ brief Function that put all the network information
 *         specified in the configuration file into a tree.
 *         It's called recursively
 *
 * \param js json array with information about networks
 * \param jnames json array of strings which store a network name
 *
 * \retval 0 if success
 * \retval -1 if an error occurred
 */
static int NetworkTreeParseJson(json_t *js, NetworkTreeElt *jnames, NetworkTree *ntree)
{
    size_t size;
    json_t *elem;

    /**
     * For each network, take the name and addresses
     * and add it into the tree, then fetch the children
     * and call the function recursively.
     */
    json_array_foreach(js, size, elem) {
        json_t *jname = json_object_get(elem, "name");
        NetworkTreeElt *local_jnames = NULL;
        if (jname == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "Name not specified, "
                                             "network information not loaded.");
            return -1;
        }

        if (!json_is_string(jname)) {
            SCLogError(SC_ERR_INVALID_VALUE, "An invalid name is specified");
            return -1;
        }
        /* if NULL we are at the top of the tree and we allocate
         * our array in the other case we copy the function param to
         * be able to have a correct and simple freeing code.
         */
        if (jnames != NULL) {
            local_jnames = NetworkTreeEltCopy(jnames);
        }
        local_jnames = NetworkTreeEltAdd(local_jnames, json_string_value(jname));

        json_t *jaddres = json_object_get(elem, "addresses");

        if (jaddres != NULL) {
            size_t addr_size;
            json_t *jaddr;
            json_array_foreach(jaddres, addr_size, jaddr) {
                NetworkTreeElt *jnames_node = NetworkTreeEltCopy(local_jnames);
                /* without a deep copy each node of the tree share the same array
                   reference, so as result you have all the same array for all nodes. */
                if (jnames_node == NULL) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Can't alloc memory");
                    return -1;
                }
                if (!json_is_string(jaddr)) {
                    SCLogError(SC_ERR_INVALID_VALUE, "Expected an IP address as"
                            "string, but it's not.");
                    continue;
                }
                const char *ip_addr = json_string_value(jaddr);

                if (strchr(ip_addr, ':') != NULL) {
                    void *user_data = NULL;
                    struct in6_addr addr;
                    uint8_t netmask;

                    /* if an ip address is duplicated, it's not added */
                    if (ParseIPV6String(ip_addr, &addr, &netmask) != 0) {
                        SCLogError(SC_ERR_INVALID_VALUE, "Invalid IP address: %s", ip_addr);
                        NetworkTreeEltFree(jnames_node);
                        return -1;
                    }

                    if (SCRadixFindKeyIPV6Netblock((uint8_t *)addr.s6_addr, ntree->tree_v6,
                                                   netmask, &user_data) != NULL)
                    {
                        SCLogWarning(SC_ERR_INVALID_VALUE,
                                "ipv6 address %s already added", ip_addr);
                        NetworkTreeEltFree(jnames_node);
                        continue;
                    }
                    if (SCRadixAddKeyIPV6String(ip_addr, ntree->tree_v6,
                                                (void *)jnames_node) == NULL) {
                        SCLogWarning(SC_ERR_INVALID_VALUE,
                                "failed to add ipv6 host %s", ip_addr);
                    }
                } else {
                    void *user_data = NULL;
                    uint32_t ip;
                    uint8_t netmask;

                    /* if an ip address is duplicated, it's not added */
                    if (ParseIPV4String(ip_addr, &ip, &netmask) != 0) {
                        SCLogError(SC_ERR_INVALID_VALUE, "Invalid IP address: %s", ip_addr);
                        NetworkTreeEltFree(jnames_node);
                        break;
                    }
                    if (SCRadixFindKeyIPV4Netblock((uint8_t *)&ip, ntree->tree_v4,
                                                    netmask, &user_data) != NULL) {
                        SCLogWarning(SC_ERR_INVALID_VALUE,
                                "ipv4 address %s already added", ip_addr);
                        NetworkTreeEltFree(jnames_node);
                        continue;
                    }
                    if (SCRadixAddKeyIPV4String(ip_addr, ntree->tree_v4,
                                                (void *)jnames_node) == NULL) {
                        SCLogWarning(SC_ERR_INVALID_VALUE,
                                "failed to add ipv4 host %s", ip_addr);
                    }
                }
            }
        }

        json_t *jchildren = json_object_get(elem, "children");
        if (jchildren == NULL) {
            /* no children to add, so let's continue */
            NetworkTreeEltFree(local_jnames);
            continue;
        } else {
            if (!json_is_array(jchildren)) {
                SCLogError(SC_ERR_INVALID_VALUE, "children format for '%s' is wrong,"
                        "json array is expected",
                        json_string_value(jname));
                NetworkTreeEltFree(jnames);
                NetworkTreeEltFree(local_jnames);
                return -1;
            }

            NetworkTreeElt *recursive_elt = NetworkTreeEltCopy(local_jnames);
            if (recursive_elt) {
                NetworkTreeParseJson(jchildren, recursive_elt, ntree);
            } else {
                SCLogError(SC_ERR_MEM_ALLOC, "Unable to duplicate recursive elt");
                NetworkTreeEltFree(jnames);
                NetworkTreeEltFree(local_jnames);
                return -1;
            }
        }
        NetworkTreeEltFree(local_jnames);
    }
    NetworkTreeEltFree(jnames);
    return 0;
}

static NetworkTreeElt *NetworkTreeGetIPv4Info(uint8_t *ipv4_addr, int tenant_id)
{
    NetworkTreeMaster *master = &g_master_net_tree;
    NetworkTree *ntree = NULL;

    if (DetectEngineMultiTenantEnabled()) {
        SCMutexLock(&master->lock);
        ntree = HashTableLookup(master->mt_trees_hash, &tenant_id, 0);
        if (ntree != NULL) {
            ntree->ref_cnt++;
        }
        SCMutexUnlock(&master->lock);
    } else {
        ntree = master->tree;
    }

    if (ntree == NULL) {
        return NULL;
    }

    void *user_data = NULL;
    (void)SCRadixFindKeyIPV4BestMatch(ipv4_addr, ntree->tree_v4, &user_data);

    if (DetectEngineMultiTenantEnabled()) {
        SCMutexLock(&master->lock);
        ntree->ref_cnt--;
        SCMutexUnlock(&master->lock);
    }

    return ((user_data != NULL) ? (NetworkTreeElt *)user_data : NULL);
}

static NetworkTreeElt *NetworkTreeGetIPv6Info(uint8_t *ipv6_addr, int tenant_id)
{
    NetworkTreeMaster *master = &g_master_net_tree;
    NetworkTree *ntree = NULL;

    if (DetectEngineMultiTenantEnabled()) {
        SCMutexLock(&master->lock);
        ntree = HashTableLookup(master->mt_trees_hash, &tenant_id, 0);
        if (ntree != NULL) {
            ntree->ref_cnt++;
        }
        SCMutexUnlock(&master->lock);
    } else {
        ntree = master->tree;
    }

    if (ntree == NULL) {
        return NULL;
    }

    void *user_data = NULL;
    (void)SCRadixFindKeyIPV6BestMatch(ipv6_addr, ntree->tree_v6, &user_data);

    if (DetectEngineMultiTenantEnabled()) {
        SCMutexLock(&master->lock);
        ntree->ref_cnt--;
        SCMutexUnlock(&master->lock);
    }

    return ((user_data != NULL) ? (NetworkTreeElt *)user_data : NULL);
}

/**
 * \brief Returns an array of labels associated to an ip address
 *
 * \param ipv4_addr IPv4 address to retreive network configuration
 * \param tenant_id Load configuration for this specific id
 *
 * \retval elt A json array containing all the labels associated to the ip address.
 */
json_t *NetworkTreeGetIPv4InfoAsJSON(uint8_t *ipv4_addr, int tenant_id)
{
    NetworkTreeElt *elt = NetworkTreeGetIPv4Info(ipv4_addr, tenant_id);
    if (elt == NULL)
        return NULL;
    return NetworkTreeEltAsJSON(elt);
}

/**
 * \brief Returns an array of labels associated to an ip address
 *
 * \param ipv4_addr IPv6 address to retreive network configuration
 * \param tenant_id Load configuration for this specific id
 *
 * \retval elt A json array containing all the labels associated to the ip address.
 */
json_t *NetworkTreeGetIPv6InfoAsJSON(uint8_t *ipv6_addr, int tenant_id)
{
    NetworkTreeElt *elt = NetworkTreeGetIPv6Info(ipv6_addr, tenant_id);
    if (elt == NULL)
        return NULL;
    return NetworkTreeEltAsJSON(elt);
}

static int NetworkTreeParseConfig(const char *node, NetworkTree *ntree)
{
    const char *filepath = NULL;
    json_t *jfile = NULL;
    int r = 0;

    if (ConfGet(node, &filepath) < 1) {
        return -1;
    }

    jfile = json_load_file(filepath, 0, NULL);
    if (jfile == NULL) {
        SCLogError(SC_ERR_JSON_FILE_NOT_LOADED, "Cannot load the file specified");
        return -1;
    }

    if (!json_is_array(jfile)) {
        SCLogError(SC_ERR_INVALID_VALUE, "Format wrong, json array is expected.");
        json_decref(jfile);
        return -1;
    }

    r = NetworkTreeParseJson(jfile, NULL, ntree);

    json_decref(jfile);

    return r;
}

/**
 * \brief Load network configuration for a tenant
 *
 * \param de_ctx it's used to retrieve the tenant id
 *
 */
void NetworkTreeLoadConfigMultiTenant(DetectEngineCtx *de_ctx)
{
    NetworkTreeMaster *master = &g_master_net_tree;
    char varname[128] = "network-tree-path";

    if (strlen(de_ctx->config_prefix) > 0) {
        snprintf(varname, sizeof(varname), "%s.network-tree-path",
                 de_ctx->config_prefix);
    }
    if (master->mt_trees_hash == NULL) {
        return;
    }
    NetworkTree *ntree = NetworkTreeCreateInstance(de_ctx->tenant_id);
    if (ntree == NULL) {
        return;
    }
    if (NetworkTreeParseConfig(varname, ntree) != 0) {
        NetworkTreeFreeInstance(ntree);
        return;
    }
    if (HashTableAdd(master->mt_trees_hash, ntree, 0) != 0) {
        NetworkTreeFreeInstance(ntree);
        return;
    }
}

/**
 * \brief Initialize the context to store network configuration
 *
 */
void NetworkTreeInit(void)
{
    NetworkTreeMaster *master = &g_master_net_tree;

    if (DetectEngineMultiTenantEnabled()) {
        HashTable *mt_trees_hash = NULL;
        /* number of tenants is needed to allocate hash table */
        ConfNode *tenants_root_node = ConfGetNode("multi-detect.tenants");
        ConfNode *tenant_node = NULL;
        int tenants_cnt = 0;

        if (tenants_root_node != NULL) {
            TAILQ_FOREACH(tenant_node, &tenants_root_node->head, next) {
                tenants_cnt++;
            }
            mt_trees_hash = HashTableInit(tenants_cnt * 2, NetworkTreeTenantIdHash,
                                          NetworkTreeTenantIdCompare, NetworkTreeTenantIdFree);
            if (mt_trees_hash == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Can't alloc memory for hash table.");
                return;
            }
            master->mt_trees_hash = mt_trees_hash;
        }
    } else {
        master->tree = NetworkTreeCreateInstance(0);
        if (master->tree == NULL) {
            return;
        }
        if (NetworkTreeParseConfig("network-tree-path", master->tree) != 0) {
            NetworkTreeFreeInstance(master->tree);
        }
    }
    return;
}

/**
 * \brief Deinitialize the context and frees the resources
 *
 */
void NetworkTreeDeInit(void)
{
    NetworkTreeMaster *master = &g_master_net_tree;

    if (master->tree != NULL) {
        NetworkTreeFreeInstance(master->tree);
    }
    if (master->mt_trees_hash != NULL) {
        HashTableFree(master->mt_trees_hash);
    }
}

#ifdef UNITTESTS
#include "tests/util-network-tree.c"

void NetworkTreeInitForTests(json_t *networkjs)
{
    NetworkTreeMaster *master = &g_master_net_tree;

    master->tree = NetworkTreeCreateInstance(0);
    if (master->tree == NULL) {
        return;
    }

    if (NetworkTreeParseJson(networkjs, NULL, master->tree) != 0) {
        NetworkTreeFreeInstance(master->tree);
    }
}
#endif /* UNITTESTS */

void NetworkTreeRegisterTests(void)
{
#ifdef UNITTESTS
    NetworkTreeDoRegisterTests();
#endif
}
