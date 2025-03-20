/* Copyright (C) 2007-2023 Open Information Security Foundation
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
 * \author Endace Technology Limited - Jason Ish <jason.ish@endace.com>
 *
 * This file provides a basic configuration system for the IDPS
 * engine.
 *
 * NOTE: Setting values should only be done from one thread during
 * engine initialization.  Multiple threads should be able access read
 * configuration data.  Allowing run time changes to the configuration
 * will require some locks.
 *
 * \todo Consider having the in-memory configuration database a direct
 *   reflection of the configuration file and moving command line
 *   parameters to a primary lookup table?
 *
 * \todo Get rid of allow override and go with a simpler first set,
 *   stays approach?
 */

#include "suricata-common.h"
#include "conf.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-path.h"
#include "util-conf.h"

/** Maximum size of a complete domain name. */
#define NODE_NAME_MAX 1024

static SCConfNode *root = NULL;
static SCConfNode *root_backup = NULL;

/**
 * \brief Helper function to get a node, creating it if it does not
 * exist.
 *
 * This function exits on memory failure as creating configuration
 * nodes is usually part of application initialization.
 *
 * \param parent The node to use as the parent
 * \param name The name of the configuration node to get.
 * \param final Flag to set created nodes as final or not.
 *
 * \retval The existing configuration node if it exists, or a newly
 *   created node for the provided name.  On error, NULL will be returned.
 */
SCConfNode *SCConfNodeGetNodeOrCreate(SCConfNode *parent, const char *name, int final)
{
    SCConfNode *node = NULL;
    char node_name[NODE_NAME_MAX];
    char *key;
    char *next;

    if (strlcpy(node_name, name, sizeof(node_name)) >= sizeof(node_name)) {
        SCLogError("Configuration name too long: %s", name);
        return NULL;
    }

    key = node_name;

    do {
        if ((next = strchr(key, '.')) != NULL)
            *next++ = '\0';
        if ((node = SCConfNodeLookupChild(parent, key)) == NULL) {
            node = SCConfNodeNew();
            if (unlikely(node == NULL)) {
                SCLogWarning("Failed to allocate memory for configuration.");
                goto end;
            }
            node->name = SCStrdup(key);
            if (unlikely(node->name == NULL)) {
                SCConfNodeFree(node);
                node = NULL;
                SCLogWarning("Failed to allocate memory for configuration.");
                goto end;
            }
            node->parent = parent;
            node->final = final;
            TAILQ_INSERT_TAIL(&parent->head, node, next);
        }
        key = next;
        parent = node;
    } while (next != NULL);

end:
    return node;
}

/**
 * \brief Wrapper function for SCConfNodeGetNodeOrCreate that operates
 *     on the current root node.
 */
static SCConfNode *SCConfGetNodeOrCreate(const char *name, int final)
{
    return SCConfNodeGetNodeOrCreate(root, name, final);
}

/**
 * \brief Initialize the configuration system.
 */
void SCConfInit(void)
{
    if (root != NULL) {
        SCLogDebug("already initialized");
        return;
    }
    root = SCConfNodeNew();
    if (root == NULL) {
        FatalError("ERROR: Failed to allocate memory for root configuration node, "
                   "aborting.");
    }
    SCLogDebug("configuration module initialized");
}

/**
 * \brief Allocate a new configuration node.
 *
 * \retval An allocated configuration node on success, NULL on failure.
 */
SCConfNode *SCConfNodeNew(void)
{
    SCConfNode *new;

    new = SCCalloc(1, sizeof(*new));
    if (unlikely(new == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&new->head);

    return new;
}

/**
 * \brief Free a SCConfNode and all of its children.
 *
 * \param node The configuration node to SCFree.
 */
void SCConfNodeFree(SCConfNode *node)
{
    SCConfNode *tmp;

    while ((tmp = TAILQ_FIRST(&node->head))) {
        TAILQ_REMOVE(&node->head, tmp, next);
        SCConfNodeFree(tmp);
    }

    if (node->name != NULL)
        SCFree(node->name);
    if (node->val != NULL)
        SCFree(node->val);
    SCFree(node);
}

/**
 * \brief Get a SCConfNode by name.
 *
 * \param name The full name of the configuration node to lookup.
 *
 * \retval A pointer to SCConfNode is found or NULL if the configuration
 *    node does not exist.
 */
SCConfNode *SCConfGetNode(const char *name)
{
    SCConfNode *node = root;
    char node_name[NODE_NAME_MAX];
    char *key;
    char *next;

    if (strlcpy(node_name, name, sizeof(node_name)) >= sizeof(node_name)) {
        SCLogError("Configuration name too long: %s", name);
        return NULL;
    }

    key = node_name;
    do {
        if ((next = strchr(key, '.')) != NULL)
            *next++ = '\0';
        node = SCConfNodeLookupChild(node, key);
        key = next;
    } while (next != NULL && node != NULL);

    return node;
}

SCConfNode *SCConfGetFirstNode(const SCConfNode *parent)
{
    return TAILQ_FIRST(&parent->head);
}

SCConfNode *SCConfGetNextNode(const SCConfNode *node)
{
    return TAILQ_NEXT(node, next);
}

const char *SCConfGetValueNode(const SCConfNode *node)
{
    return node->val;
}

/**
 * \brief Get the root configuration node.
 */
SCConfNode *SCConfGetRootNode(void)
{
    return root;
}

/**
 * \brief Set a configuration value.
 *
 * Configuration values set with this function may be overridden by
 * subsequent calls, or if the value appears multiple times in a
 * configuration file.
 *
 * \param name The name of the configuration parameter to set.
 * \param val The value of the configuration parameter.
 *
 * \retval 1 if the value was set otherwise 0.
 */
int SCConfSet(const char *name, const char *val)
{
    SCConfNode *node = SCConfGetNodeOrCreate(name, 0);
    if (node == NULL || node->final) {
        return 0;
    }
    if (node->val != NULL)
        SCFree(node->val);
    node->val = SCStrdup(val);
    if (unlikely(node->val == NULL)) {
        return 0;
    }
    return 1;
}

/**
 * \brief Set a configuration parameter from a string.
 *
 * Where the input string is something like:
 *    stream.midstream=true
 *
 * \param input the input string to be parsed.
 *
 * \retval 1 if the value of set, otherwise 0.
 */
int SCConfSetFromString(const char *input, int final)
{
    int retval = 0;
    char *name = SCStrdup(input), *val = NULL;
    if (unlikely(name == NULL)) {
        goto done;
    }
    val = strchr(name, '=');
    if (val == NULL) {
        goto done;
    }
    *val++ = '\0';

    while (isspace((int)name[strlen(name) - 1])) {
        name[strlen(name) - 1] = '\0';
    }

    while (isspace((int)*val)) {
        val++;
    }

    if (final) {
        if (!SCConfSetFinal(name, val)) {
            goto done;
        }
    }
    else {
        if (!SCConfSet(name, val)) {
            goto done;
        }
    }

    retval = 1;
done:
    if (name != NULL) {
        SCFree(name);
    }
    return retval;
}

/**
 * \brief Set a final configuration value.
 *
 * A final configuration value is a value that cannot be overridden by
 * the configuration file.  Its mainly useful for setting values that
 * are supplied on the command line prior to the configuration file
 * being loaded.  However, a subsequent call to this function can
 * override a previously set value.
 *
 * \param name The name of the configuration parameter to set.
 * \param val The value of the configuration parameter.
 *
 * \retval 1 if the value was set otherwise 0.
 */
int SCConfSetFinal(const char *name, const char *val)
{
    SCConfNode *node = SCConfGetNodeOrCreate(name, 1);
    if (node == NULL) {
        return 0;
    }
    if (node->val != NULL)
        SCFree(node->val);
    node->val = SCStrdup(val);
    if (unlikely(node->val == NULL)) {
        return 0;
    }
    node->final = 1;
    return 1;
}

/**
 * \brief Retrieve the value of a configuration node.
 *
 * This function will return the value for a configuration node based
 * on the full name of the node.  It is possible that the value
 * returned could be NULL, this could happen if the requested node
 * does exist but is not a node that contains a value, but contains
 * children SCConfNodes instead.
 *
 * \param name Name of configuration parameter to get.
 * \param vptr Pointer that will be set to the configuration value parameter.
 *   Note that this is just a reference to the actual value, not a copy.
 *
 * \retval 1 will be returned if the name is found, otherwise 0 will
 *   be returned.
 */
int SCConfGet(const char *name, const char **vptr)
{
    SCConfNode *node = SCConfGetNode(name);
    if (node == NULL) {
        SCLogDebug("failed to lookup configuration parameter '%s'", name);
        return 0;
    }
    else {
        *vptr = node->val;
        return 1;
    }
}

int SCConfGetChildValue(const SCConfNode *base, const char *name, const char **vptr)
{
    SCConfNode *node = SCConfNodeLookupChild(base, name);

    if (node == NULL) {
        SCLogDebug("failed to lookup configuration parameter '%s'", name);
        return 0;
    }
    else {
        if (node->val == NULL)
            return 0;
        *vptr = node->val;
        return 1;
    }
}

SCConfNode *SCConfGetChildWithDefault(
        const SCConfNode *base, const SCConfNode *dflt, const char *name)
{
    SCConfNode *node = SCConfNodeLookupChild(base, name);
    if (node != NULL)
        return node;

    /* Get 'default' value */
    if (dflt) {
        return SCConfNodeLookupChild(dflt, name);
    }
    return NULL;
}

int SCConfGetChildValueWithDefault(
        const SCConfNode *base, const SCConfNode *dflt, const char *name, const char **vptr)
{
    int ret = SCConfGetChildValue(base, name, vptr);
    /* Get 'default' value */
    if (ret == 0 && dflt) {
        return SCConfGetChildValue(dflt, name, vptr);
    }
    return ret;
}

/**
 * \brief Retrieve a configuration value as an integer.
 *
 * \param name Name of configuration parameter to get.
 * \param val Pointer to an intmax_t that will be set the
 * configuration value.
 *
 * \retval 1 will be returned if the name is found and was properly
 * converted to an integer, otherwise 0 will be returned.
 */
int SCConfGetInt(const char *name, intmax_t *val)
{
    const char *strval = NULL;
    intmax_t tmpint;
    char *endptr;

    if (SCConfGet(name, &strval) == 0)
        return 0;

    if (strval == NULL) {
        SCLogError("malformed integer value "
                   "for %s: NULL",
                name);
        return 0;
    }

    errno = 0;
    tmpint = strtoimax(strval, &endptr, 0);
    if (strval[0] == '\0' || *endptr != '\0') {
        SCLogError("malformed integer value "
                   "for %s: '%s'",
                name, strval);
        return 0;
    }
    if (errno == ERANGE && (tmpint == INTMAX_MAX || tmpint == INTMAX_MIN)) {
        SCLogError("integer value for %s out "
                   "of range: '%s'",
                name, strval);
        return 0;
    }

    *val = tmpint;
    return 1;
}

int SCConfGetChildValueInt(const SCConfNode *base, const char *name, intmax_t *val)
{
    const char *strval = NULL;
    intmax_t tmpint;
    char *endptr;

    if (SCConfGetChildValue(base, name, &strval) == 0)
        return 0;
    errno = 0;
    tmpint = strtoimax(strval, &endptr, 0);
    if (strval[0] == '\0' || *endptr != '\0') {
        SCLogError("malformed integer value "
                   "for %s with base %s: '%s'",
                name, base->name, strval);
        return 0;
    }
    if (errno == ERANGE && (tmpint == INTMAX_MAX || tmpint == INTMAX_MIN)) {
        SCLogError("integer value for %s with "
                   " base %s out of range: '%s'",
                name, base->name, strval);
        return 0;
    }

    *val = tmpint;
    return 1;
}

int SCConfGetChildValueIntWithDefault(
        const SCConfNode *base, const SCConfNode *dflt, const char *name, intmax_t *val)
{
    int ret = SCConfGetChildValueInt(base, name, val);
    /* Get 'default' value */
    if (ret == 0 && dflt) {
        return SCConfGetChildValueInt(dflt, name, val);
    }
    return ret;
}

/**
 * \brief Retrieve a configuration value as a boolean.
 *
 * \param name Name of configuration parameter to get.
 * \param val Pointer to an int that will be set to 1 for true, or 0
 * for false.
 *
 * \retval 1 will be returned if the name is found and was properly
 * converted to a boolean, otherwise 0 will be returned.
 */
int SCConfGetBool(const char *name, int *val)
{
    const char *strval = NULL;

    *val = 0;
    if (SCConfGet(name, &strval) != 1)
        return 0;

    *val = SCConfValIsTrue(strval);

    return 1;
}

/**
 * Get a boolean value from the provided SCConfNode.
 *
 * \retval 1 If the value exists, 0 if not.
 */
int SCConfGetChildValueBool(const SCConfNode *base, const char *name, int *val)
{
    const char *strval = NULL;

    *val = 0;
    if (SCConfGetChildValue(base, name, &strval) == 0)
        return 0;

    *val = SCConfValIsTrue(strval);

    return 1;
}

int SCConfGetChildValueBoolWithDefault(
        const SCConfNode *base, const SCConfNode *dflt, const char *name, int *val)
{
    int ret = SCConfGetChildValueBool(base, name, val);
    /* Get 'default' value */
    if (ret == 0 && dflt) {
        return SCConfGetChildValueBool(dflt, name, val);
    }
    return ret;
}


/**
 * \brief Check if a value is true.
 *
 * The value is considered true if it is a string with the value of 1,
 * yes, true or on.  The test is not case sensitive, any other value
 * is false.
 *
 * \param val The string to test for a true value.
 *
 * \retval 1 If the value is true, 0 if not.
 */
int SCConfValIsTrue(const char *val)
{
    const char *trues[] = {"1", "yes", "true", "on"};
    size_t u;

    for (u = 0; u < sizeof(trues) / sizeof(trues[0]); u++) {
        if (strcasecmp(val, trues[u]) == 0) {
            return 1;
        }
    }

    return 0;
}

/**
 * \brief Check if a value is false.
 *
 * The value is considered false if it is a string with the value of 0,
 * no, false or off.  The test is not case sensitive, any other value
 * is not false.
 *
 * \param val The string to test for a false value.
 *
 * \retval 1 If the value is false, 0 if not.
 */
int SCConfValIsFalse(const char *val)
{
    const char *falses[] = {"0", "no", "false", "off"};
    size_t u;

    for (u = 0; u < sizeof(falses) / sizeof(falses[0]); u++) {
        if (strcasecmp(val, falses[u]) == 0) {
            return 1;
        }
    }

    return 0;
}

/**
 * \brief Retrieve a configuration value as a double
 *
 * \param name Name of configuration parameter to get.
 * \param val Pointer to an double that will be set the
 * configuration value.
 *
 * \retval 1 will be returned if the name is found and was properly
 * converted to a double, otherwise 0 will be returned.
 */
int SCConfGetDouble(const char *name, double *val)
{
    const char *strval = NULL;
    double tmpdo;
    char *endptr;

    if (SCConfGet(name, &strval) == 0)
        return 0;

    errno = 0;
    tmpdo = strtod(strval, &endptr);
    if (strval[0] == '\0' || *endptr != '\0')
        return 0;
    if (errno == ERANGE)
        return 0;

    *val = tmpdo;
    return 1;
}

/**
 * \brief Retrieve a configuration value as a float
 *
 * \param name Name of configuration parameter to get.
 * \param val Pointer to an float that will be set the
 * configuration value.
 *
 * \retval 1 will be returned if the name is found and was properly
 * converted to a double, otherwise 0 will be returned.
 */
int SCConfGetFloat(const char *name, float *val)
{
    const char *strval = NULL;
    double tmpfl;
    char *endptr;

    if (SCConfGet(name, &strval) == 0)
        return 0;

    errno = 0;
    tmpfl = strtof(strval, &endptr);
    if (strval[0] == '\0' || *endptr != '\0')
        return 0;
    if (errno == ERANGE)
        return 0;

    *val = tmpfl;
    return 1;
}

/**
 * \brief Remove (and SCFree) the provided configuration node.
 */
void SCConfNodeRemove(SCConfNode *node)
{
    if (node->parent != NULL)
        TAILQ_REMOVE(&node->parent->head, node, next);
    SCConfNodeFree(node);
}

/**
 * \brief Remove a configuration parameter from the configuration db.
 *
 * \param name The name of the configuration parameter to remove.
 *
 * \retval Returns 1 if the parameter was removed, otherwise 0 is returned
 *   most likely indicating the parameter was not set.
 */
int SCConfRemove(const char *name)
{
    SCConfNode *node;

    node = SCConfGetNode(name);
    if (node == NULL)
        return 0;
    else {
        SCConfNodeRemove(node);
        return 1;
    }
}

/**
 * \brief Creates a backup of the conf_hash hash_table used by the conf API.
 */
void SCConfCreateContextBackup(void)
{
    root_backup = root;
    root = NULL;
}

/**
 * \brief Restores the backup of the hash_table present in backup_conf_hash
 *        back to conf_hash.
 */
void SCConfRestoreContextBackup(void)
{
    root = root_backup;
    root_backup = NULL;
}

/**
 * \brief De-initializes the configuration system.
 */
void SCConfDeInit(void)
{
    if (root != NULL) {
        SCConfNodeFree(root);
        root = NULL;
    }

    SCLogDebug("configuration module de-initialized");
}

static char *ConfPrintNameArray(char **name_arr, int level)
{
    static char name[128*128];
    int i;

    name[0] = '\0';
    for (i = 0; i <= level; i++) {
        strlcat(name, name_arr[i], sizeof(name));
        if (i < level)
            strlcat(name, ".", sizeof(name));
    }

    return name;
}

/**
 * \brief Dump a configuration node and all its children.
 */
void SCConfNodeDump(const SCConfNode *node, const char *prefix)
{
    SCConfNode *child;

    static char *name[128];
    static int level = -1;

    level++;
    TAILQ_FOREACH(child, &node->head, next) {
        name[level] = SCStrdup(child->name);
        if (unlikely(name[level] == NULL)) {
            continue;
        }
        if (prefix == NULL) {
            printf("%s = %s\n", ConfPrintNameArray(name, level),
                child->val);
        }
        else {
            printf("%s.%s = %s\n", prefix,
                ConfPrintNameArray(name, level), child->val);
        }
        SCConfNodeDump(child, prefix);
        SCFree(name[level]);
    }
    level--;
}

/**
 * \brief Dump configuration to stdout.
 */
void SCConfDump(void)
{
    SCConfNodeDump(root, NULL);
}

/**
 * \brief Check if a node has any children.
 *
 * Checks if the provided node has any children. Any node that is a
 * YAML map or array will have children.
 *
 * \param node The node to check.
 *
 * \retval true if node has children
 * \retval false if node does not have children
 */
bool SCConfNodeHasChildren(const SCConfNode *node)
{
    if (TAILQ_EMPTY(&node->head)) {
        return false;
    }
    return true;
}

/**
 * \brief Lookup a child configuration node by name.
 *
 * Given a SCConfNode this function will lookup an immediate child
 * SCConfNode by name and return the child ConfNode.
 *
 * \param node The parent configuration node.
 * \param name The name of the child node to lookup.
 *
 * \retval A pointer the child SCConfNode if found otherwise NULL.
 */
SCConfNode *SCConfNodeLookupChild(const SCConfNode *node, const char *name)
{
    SCConfNode *child;

    if (node == NULL || name == NULL) {
        return NULL;
    }

    TAILQ_FOREACH(child, &node->head, next) {
        if (child->name != NULL && strcmp(child->name, name) == 0)
            return child;
    }

    return NULL;
}

/**
 * \brief Lookup the value of a child configuration node by name.
 *
 * Given a parent SCConfNode this function will return the value of a
 * child configuration node by name returning a reference to that
 * value.
 *
 * \param node The parent configuration node.
 * \param name The name of the child node to lookup.
 *
 * \retval A pointer the child SCConfNodes value if found otherwise NULL.
 */
const char *SCConfNodeLookupChildValue(const SCConfNode *node, const char *name)
{
    SCConfNode *child;

    child = SCConfNodeLookupChild(node, name);
    if (child != NULL)
        return child->val;

    return NULL;
}

/**
 * \brief Lookup for a key value under a specific node
 *
 * \return the SCConfNode matching or NULL
 */

SCConfNode *SCConfNodeLookupKeyValue(const SCConfNode *base, const char *key, const char *value)
{
    SCConfNode *child;

    TAILQ_FOREACH(child, &base->head, next) {
        if (!strncmp(child->val, key, strlen(child->val))) {
            SCConfNode *subchild;
            TAILQ_FOREACH(subchild, &child->head, next) {
                if ((!strcmp(subchild->name, key)) && (!strcmp(subchild->val, value))) {
                    return child;
                }
            }
        }
    }

    return NULL;
}

/**
 * \brief Test if a configuration node has a true value.
 *
 * \param node The parent configuration node.
 * \param name The name of the child node to test.
 *
 * \retval 1 if the child node has a true value, otherwise 0 is
 *     returned, even if the child node does not exist.
 */
int SCConfNodeChildValueIsTrue(const SCConfNode *node, const char *key)
{
    const char *val;

    val = SCConfNodeLookupChildValue(node, key);

    return val != NULL ? SCConfValIsTrue(val) : 0;
}

/**
 *  \brief Create the path for an include entry
 *  \param file The name of the file
 *  \retval str Pointer to the string path + sig_file
 */

/**
 * \brief Prune a configuration node.
 *
 * Pruning a configuration is similar to freeing, but only fields that
 * may be overridden are, leaving final type parameters.  Additional
 * the value of the provided node is also free'd, but the node itself
 * is left.
 *
 * \param node The configuration node to prune.
 */
void SCConfNodePrune(SCConfNode *node)
{
    SCConfNode *item, *it;

    for (item = TAILQ_FIRST(&node->head); item != NULL; item = it) {
        it = TAILQ_NEXT(item, next);
        if (!item->final) {
            SCConfNodePrune(item);
            if (TAILQ_EMPTY(&item->head)) {
                TAILQ_REMOVE(&node->head, item, next);
                if (item->name != NULL)
                    SCFree(item->name);
                if (item->val != NULL)
                    SCFree(item->val);
                SCFree(item);
            }
        }
    }

    if (node->val != NULL) {
        SCFree(node->val);
        node->val = NULL;
    }
}

/**
 * \brief Check if a node is a sequence or node.
 *
 * \param node the node to check.
 *
 * \return 1 if node is a sequence, otherwise 0.
 */
int SCConfNodeIsSequence(const SCConfNode *node)
{
    return node->is_seq == 0 ? 0 : 1;
}

/**
 * @brief Finds an interface from the list of interfaces.
 * @param ifaces_node_name - name of the node which holds a list of interfaces
 * @param iface - interfaces name
 * @return NULL on failure otherwise a valid pointer
 */
SCConfNode *SCConfSetIfaceNode(const char *ifaces_node_name, const char *iface)
{
    SCConfNode *if_node;
    SCConfNode *ifaces_list_node;
    /* Find initial node which holds all interfaces */
    ifaces_list_node = SCConfGetNode(ifaces_node_name);
    if (ifaces_list_node == NULL) {
        SCLogError("unable to find %s config", ifaces_node_name);
        return NULL;
    }

    if_node = ConfFindDeviceConfig(ifaces_list_node, iface);
    if (if_node == NULL)
        SCLogNotice("unable to find interface %s in DPDK config", iface);

    return if_node;
}

/**
 * @brief Finds and sets root and default node of the interface.
 * @param ifaces_node_name Node which holds list of interfaces
 * @param iface Name of the interface e.g. eth3
 * @param if_root Node which will hold the interface configuration
 * @param if_default Node which is the default configuration in the given list of interfaces
 * @return 0 on success, -ENODEV when neither the root interface nor the default interface was found
 */
int SCConfSetRootAndDefaultNodes(const char *ifaces_node_name, const char *iface,
        SCConfNode **if_root, SCConfNode **if_default)
{
    const char *default_iface = "default";
    *if_root = SCConfSetIfaceNode(ifaces_node_name, iface);
    *if_default = SCConfSetIfaceNode(ifaces_node_name, default_iface);

    if (*if_root == NULL && *if_default == NULL) {
        SCLogError("unable to find configuration for the interface \"%s\" or the default "
                   "configuration (\"%s\")",
                iface, default_iface);
        return (-ENODEV);
    }

    /* If there is no setting for current interface use default one as main iface */
    if (*if_root == NULL) {
        *if_root = *if_default;
        *if_default = NULL;
    }
    return 0;
}

#ifdef UNITTESTS

/**
 * Lookup a non-existant value.
 */
static int ConfTestGetNonExistant(void)
{
    char name[] = "non-existant-value";
    const char *value;

    FAIL_IF(SCConfGet(name, &value));
    PASS;
}

/**
 * Set then lookup a value.
 */
static int ConfTestSetAndGet(void)
{
    char name[] = "some-name";
    char value[] = "some-value";
    const char *value0 = NULL;

    FAIL_IF(SCConfSet(name, value) != 1);
    FAIL_IF(SCConfGet(name, &value0) != 1);
    FAIL_IF(value0 == NULL);
    FAIL_IF(strcmp(value, value0) != 0);

    /* Cleanup. */
    SCConfRemove(name);

    PASS;
}

/**
 * Test that overriding a value is allowed provided allow_override is
 * true and that the config parameter gets the new value.
 */
static int ConfTestOverrideValue1(void)
{
    char name[] = "some-name";
    char value0[] = "some-value";
    char value1[] = "new-value";
    const char *val = NULL;

    FAIL_IF(SCConfSet(name, value0) != 1);
    FAIL_IF(SCConfSet(name, value1) != 1);
    FAIL_IF(SCConfGet(name, &val) != 1);
    FAIL_IF(val == NULL);
    FAIL_IF(strcmp(val, value1) != 0);

    /* Cleanup. */
    SCConfRemove(name);

    PASS;
}

/**
 * Test that a final value will not be overridden by a ConfSet.
 */
static int ConfTestOverrideValue2(void)
{
    char name[] = "some-name";
    char value0[] = "some-value";
    char value1[] = "new-value";
    const char *val = NULL;

    FAIL_IF(SCConfSetFinal(name, value0) != 1);
    FAIL_IF(SCConfSet(name, value1) != 0);
    FAIL_IF(SCConfGet(name, &val) != 1);
    FAIL_IF(val == NULL);
    FAIL_IF(strcmp(val, value0) != 0);

    /* Cleanup. */
    SCConfRemove(name);

    PASS;
}

/**
 * Test retrieving an integer value from the configuration db.
 */
static int ConfTestGetInt(void)
{
    char name[] = "some-int.x";
    intmax_t val;

    FAIL_IF(SCConfSet(name, "0") != 1);
    FAIL_IF(SCConfGetInt(name, &val) != 1);
    FAIL_IF(val != 0);

    FAIL_IF(SCConfSet(name, "-1") != 1);
    FAIL_IF(SCConfGetInt(name, &val) != 1);
    FAIL_IF(val != -1);

    FAIL_IF(SCConfSet(name, "0xffff") != 1);
    FAIL_IF(SCConfGetInt(name, &val) != 1);
    FAIL_IF(val != 0xffff);

    FAIL_IF(SCConfSet(name, "not-an-int") != 1);
    FAIL_IF(SCConfGetInt(name, &val) != 0);

    PASS;
}

/**
 * Test retrieving a boolean value from the configuration db.
 */
static int ConfTestGetBool(void)
{
    char name[] = "some-bool";
    const char *trues[] = {
        "1",
        "on", "ON",
        "yes", "YeS",
        "true", "TRUE",
    };
    const char *falses[] = {
        "0",
        "something",
        "off", "OFF",
        "false", "FalSE",
        "no", "NO",
    };
    int val;
    size_t u;

    for (u = 0; u < sizeof(trues) / sizeof(trues[0]); u++) {
        FAIL_IF(SCConfSet(name, trues[u]) != 1);
        FAIL_IF(SCConfGetBool(name, &val) != 1);
        FAIL_IF(val != 1);
    }

    for (u = 0; u < sizeof(falses) / sizeof(falses[0]); u++) {
        FAIL_IF(SCConfSet(name, falses[u]) != 1);
        FAIL_IF(SCConfGetBool(name, &val) != 1);
        FAIL_IF(val != 0);
    }

    PASS;
}

static int ConfNodeLookupChildTest(void)
{
    const char *test_vals[] = { "one", "two", "three" };
    size_t u;

    SCConfNode *parent = SCConfNodeNew();
    SCConfNode *child;

    for (u = 0; u < sizeof(test_vals)/sizeof(test_vals[0]); u++) {
        child = SCConfNodeNew();
        child->name = SCStrdup(test_vals[u]);
        child->val = SCStrdup(test_vals[u]);
        TAILQ_INSERT_TAIL(&parent->head, child, next);
    }

    child = SCConfNodeLookupChild(parent, "one");
    FAIL_IF(child == NULL);
    FAIL_IF(strcmp(child->name, "one") != 0);
    FAIL_IF(strcmp(child->val, "one") != 0);

    child = SCConfNodeLookupChild(parent, "two");
    FAIL_IF(child == NULL);
    FAIL_IF(strcmp(child->name, "two") != 0);
    FAIL_IF(strcmp(child->val, "two") != 0);

    child = SCConfNodeLookupChild(parent, "three");
    FAIL_IF(child == NULL);
    FAIL_IF(strcmp(child->name, "three") != 0);
    FAIL_IF(strcmp(child->val, "three") != 0);

    child = SCConfNodeLookupChild(parent, "four");
    FAIL_IF(child != NULL);

    FAIL_IF(SCConfNodeLookupChild(NULL, NULL) != NULL);

    if (parent != NULL) {
        SCConfNodeFree(parent);
    }

    PASS;
}

static int ConfNodeLookupChildValueTest(void)
{
    const char *test_vals[] = { "one", "two", "three" };
    size_t u;

    SCConfNode *parent = SCConfNodeNew();
    SCConfNode *child;
    const char *value;

    for (u = 0; u < sizeof(test_vals)/sizeof(test_vals[0]); u++) {
        child = SCConfNodeNew();
        child->name = SCStrdup(test_vals[u]);
        child->val = SCStrdup(test_vals[u]);
        TAILQ_INSERT_TAIL(&parent->head, child, next);
    }

    value = (char *)SCConfNodeLookupChildValue(parent, "one");
    FAIL_IF(value == NULL);
    FAIL_IF(strcmp(value, "one") != 0);

    value = (char *)SCConfNodeLookupChildValue(parent, "two");
    FAIL_IF(value == NULL);
    FAIL_IF(strcmp(value, "two") != 0);

    value = (char *)SCConfNodeLookupChildValue(parent, "three");
    FAIL_IF(value == NULL);
    FAIL_IF(strcmp(value, "three") != 0);

    value = (char *)SCConfNodeLookupChildValue(parent, "four");
    FAIL_IF(value != NULL);

    SCConfNodeFree(parent);

    PASS;
}

static int ConfGetChildValueWithDefaultTest(void)
{
    const char  *val = "";
    SCConfCreateContextBackup();
    SCConfInit();
    SCConfSet("af-packet.0.interface", "eth0");
    SCConfSet("af-packet.1.interface", "default");
    SCConfSet("af-packet.1.cluster-type", "cluster_cpu");

    SCConfNode *myroot = SCConfGetNode("af-packet.0");
    SCConfNode *dflt = SCConfGetNode("af-packet.1");
    SCConfGetChildValueWithDefault(myroot, dflt, "cluster-type", &val);
    FAIL_IF(strcmp(val, "cluster_cpu"));

    SCConfSet("af-packet.0.cluster-type", "cluster_flow");
    SCConfGetChildValueWithDefault(myroot, dflt, "cluster-type", &val);

    FAIL_IF(strcmp(val, "cluster_flow"));

    SCConfDeInit();
    SCConfRestoreContextBackup();
    PASS;
}

static int ConfGetChildValueIntWithDefaultTest(void)
{
    intmax_t val = 0;
    SCConfCreateContextBackup();
    SCConfInit();
    SCConfSet("af-packet.0.interface", "eth0");
    SCConfSet("af-packet.1.interface", "default");
    SCConfSet("af-packet.1.threads", "2");

    SCConfNode *myroot = SCConfGetNode("af-packet.0");
    SCConfNode *dflt = SCConfGetNode("af-packet.1");
    SCConfGetChildValueIntWithDefault(myroot, dflt, "threads", &val);
    FAIL_IF(val != 2);

    SCConfSet("af-packet.0.threads", "1");
    SCConfGetChildValueIntWithDefault(myroot, dflt, "threads", &val);
    FAIL_IF(val != 1);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

static int ConfGetChildValueBoolWithDefaultTest(void)
{
    int val;
    SCConfCreateContextBackup();
    SCConfInit();
    SCConfSet("af-packet.0.interface", "eth0");
    SCConfSet("af-packet.1.interface", "default");
    SCConfSet("af-packet.1.use-mmap", "yes");

    SCConfNode *myroot = SCConfGetNode("af-packet.0");
    SCConfNode *dflt = SCConfGetNode("af-packet.1");
    SCConfGetChildValueBoolWithDefault(myroot, dflt, "use-mmap", &val);
    FAIL_IF(val == 0);

    SCConfSet("af-packet.0.use-mmap", "no");
    SCConfGetChildValueBoolWithDefault(myroot, dflt, "use-mmap", &val);
    FAIL_IF(val);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

/**
 * Test the removal of a configuration node.
 */
static int ConfNodeRemoveTest(void)
{
    SCConfCreateContextBackup();
    SCConfInit();

    FAIL_IF(SCConfSet("some.nested.parameter", "blah") != 1);

    SCConfNode *node = SCConfGetNode("some.nested.parameter");
    FAIL_IF(node == NULL);
    SCConfNodeRemove(node);

    node = SCConfGetNode("some.nested.parameter");
    FAIL_IF(node != NULL);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

static int ConfSetTest(void)
{
    SCConfCreateContextBackup();
    SCConfInit();

    /* Set some value with 2 levels. */
    FAIL_IF(SCConfSet("one.two", "three") != 1);
    SCConfNode *n = SCConfGetNode("one.two");
    FAIL_IF(n == NULL);

    /* Set another 2 level parameter with the same first level, this
     * used to trigger a bug that caused the second level of the name
     * to become a first level node. */
    FAIL_IF(SCConfSet("one.three", "four") != 1);

    n = SCConfGetNode("one.three");
    FAIL_IF(n == NULL);

    /* A top level node of "three" should not exist. */
    n = SCConfGetNode("three");
    FAIL_IF(n != NULL);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

static int ConfGetNodeOrCreateTest(void)
{
    SCConfNode *node;

    SCConfCreateContextBackup();
    SCConfInit();

    /* Get a node that should not exist, give it a value, re-get it
     * and make sure the second time it returns the existing node. */
    node = SCConfGetNodeOrCreate("node0", 0);
    FAIL_IF(node == NULL);
    FAIL_IF(node->parent == NULL || node->parent != root);
    FAIL_IF(node->val != NULL);
    node->val = SCStrdup("node0");
    node = SCConfGetNodeOrCreate("node0", 0);
    FAIL_IF(node == NULL);
    FAIL_IF(node->val == NULL);
    FAIL_IF(strcmp(node->val, "node0") != 0);

    /* Do the same, but for something deeply nested. */
    node = SCConfGetNodeOrCreate("parent.child.grandchild", 0);
    FAIL_IF(node == NULL);
    FAIL_IF(node->parent == NULL || node->parent == root);
    FAIL_IF(node->val != NULL);
    node->val = SCStrdup("parent.child.grandchild");
    node = SCConfGetNodeOrCreate("parent.child.grandchild", 0);
    FAIL_IF(node == NULL);
    FAIL_IF(node->val == NULL);
    FAIL_IF(strcmp(node->val, "parent.child.grandchild") != 0);

    /* Test that 2 child nodes have the same root. */
    SCConfNode *child1 = SCConfGetNodeOrCreate("parent.kids.child1", 0);
    SCConfNode *child2 = SCConfGetNodeOrCreate("parent.kids.child2", 0);
    FAIL_IF(child1 == NULL || child2 == NULL);
    FAIL_IF(child1->parent != child2->parent);
    FAIL_IF(strcmp(child1->parent->name, "kids") != 0);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

static int ConfNodePruneTest(void)
{
    SCConfNode *node;

    SCConfCreateContextBackup();
    SCConfInit();

    /* Test that final nodes exist after a prune. */
    FAIL_IF(SCConfSet("node.notfinal", "notfinal") != 1);
    FAIL_IF(SCConfSetFinal("node.final", "final") != 1);
    FAIL_IF(SCConfGetNode("node.notfinal") == NULL);
    FAIL_IF(SCConfGetNode("node.final") == NULL);
    FAIL_IF((node = SCConfGetNode("node")) == NULL);
    SCConfNodePrune(node);
    FAIL_IF(SCConfGetNode("node.notfinal") != NULL);
    FAIL_IF(SCConfGetNode("node.final") == NULL);

    /* Test that everything under a final node exists after a prune. */
    FAIL_IF(SCConfSet("node.final.one", "one") != 1);
    FAIL_IF(SCConfSet("node.final.two", "two") != 1);
    SCConfNodePrune(node);
    FAIL_IF(SCConfNodeLookupChild(node, "final") == NULL);
    FAIL_IF(SCConfGetNode("node.final.one") == NULL);
    FAIL_IF(SCConfGetNode("node.final.two") == NULL);

    SCConfDeInit();
    SCConfRestoreContextBackup();

    PASS;
}

static int ConfNodeIsSequenceTest(void)
{
    SCConfNode *node = SCConfNodeNew();
    FAIL_IF(node == NULL);
    FAIL_IF(SCConfNodeIsSequence(node));
    node->is_seq = 1;
    FAIL_IF(!SCConfNodeIsSequence(node));

    if (node != NULL) {
        SCConfNodeFree(node);
    }
    PASS;
}

static int ConfSetFromStringTest(void)
{
    SCConfNode *n;

    SCConfCreateContextBackup();
    SCConfInit();

    FAIL_IF_NOT(SCConfSetFromString("stream.midstream=true", 0));
    n = SCConfGetNode("stream.midstream");
    FAIL_IF_NULL(n);
    FAIL_IF_NULL(n->val);
    FAIL_IF(strcmp("true", n->val));

    FAIL_IF_NOT(SCConfSetFromString("stream.midstream =false", 0));
    n = SCConfGetNode("stream.midstream");
    FAIL_IF_NULL(n);
    FAIL_IF(n->val == NULL || strcmp("false", n->val));

    FAIL_IF_NOT(SCConfSetFromString("stream.midstream= true", 0));
    n = SCConfGetNode("stream.midstream");
    FAIL_IF_NULL(n);
    FAIL_IF(n->val == NULL || strcmp("true", n->val));

    FAIL_IF_NOT(SCConfSetFromString("stream.midstream = false", 0));
    n = SCConfGetNode("stream.midstream");
    FAIL_IF_NULL(n);
    FAIL_IF(n->val == NULL || strcmp("false", n->val));

    SCConfDeInit();
    SCConfRestoreContextBackup();
    PASS;
}

static int ConfNodeHasChildrenTest(void)
{
    SCConfCreateContextBackup();
    SCConfInit();

    /* Set a plain key with value. */
    SCConfSet("no-children", "value");
    SCConfNode *n = SCConfGetNode("no-children");
    FAIL_IF_NULL(n);
    FAIL_IF(SCConfNodeHasChildren(n));

    /* Set a key with a sub key to a value. This makes the first key a
     * map. */
    SCConfSet("parent.child", "value");
    n = SCConfGetNode("parent");
    FAIL_IF_NULL(n);
    FAIL_IF(!SCConfNodeHasChildren(n));

    SCConfDeInit();
    SCConfRestoreContextBackup();
    PASS;
}

void SCConfRegisterTests(void)
{
    UtRegisterTest("ConfTestGetNonExistant", ConfTestGetNonExistant);
    UtRegisterTest("ConfSetTest", ConfSetTest);
    UtRegisterTest("ConfTestSetAndGet", ConfTestSetAndGet);
    UtRegisterTest("ConfTestOverrideValue1", ConfTestOverrideValue1);
    UtRegisterTest("ConfTestOverrideValue2", ConfTestOverrideValue2);
    UtRegisterTest("ConfTestGetInt", ConfTestGetInt);
    UtRegisterTest("ConfTestGetBool", ConfTestGetBool);
    UtRegisterTest("ConfNodeLookupChildTest", ConfNodeLookupChildTest);
    UtRegisterTest("ConfNodeLookupChildValueTest",
                   ConfNodeLookupChildValueTest);
    UtRegisterTest("ConfNodeRemoveTest", ConfNodeRemoveTest);
    UtRegisterTest("ConfGetChildValueWithDefaultTest",
                   ConfGetChildValueWithDefaultTest);
    UtRegisterTest("ConfGetChildValueIntWithDefaultTest",
                   ConfGetChildValueIntWithDefaultTest);
    UtRegisterTest("ConfGetChildValueBoolWithDefaultTest",
                   ConfGetChildValueBoolWithDefaultTest);
    UtRegisterTest("ConfGetNodeOrCreateTest", ConfGetNodeOrCreateTest);
    UtRegisterTest("ConfNodePruneTest", ConfNodePruneTest);
    UtRegisterTest("ConfNodeIsSequenceTest", ConfNodeIsSequenceTest);
    UtRegisterTest("ConfSetFromStringTest", ConfSetFromStringTest);
    UtRegisterTest("ConfNodeHasChildrenTest", ConfNodeHasChildrenTest);
}

#endif /* UNITTESTS */
