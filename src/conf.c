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

static ConfNode *root = NULL;
static ConfNode *root_backup = NULL;

/**
 * \brief Initialize the configuration system.
 */
void
ConfInit(void)
{
    if (root != NULL) {
        SCLogDebug("already initialized");
        return;
    }
    root = ConfNodeNew();
    if (root == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "ERROR: Failed to allocate memory for root configuration node, "
            "aborting.");
        exit(EXIT_FAILURE);
    }
    SCLogDebug("configuration module initialized");
}

/**
 * \brief Allocate a new configuration node.
 *
 * \retval An allocated configuration node on success, NULL on failure.
 */
ConfNode *
ConfNodeNew(void)
{
    ConfNode *new;

    new = SCCalloc(1, sizeof(*new));
    if (unlikely(new == NULL)) {
        return NULL;
    }
    /* By default we allow an override. */
    new->allow_override = 1;
    TAILQ_INIT(&new->head);

    return new;
}

/**
 * \brief Free a ConfNode and all of its children.
 *
 * \param node The configuration node to SCFree.
 */
void
ConfNodeFree(ConfNode *node)
{
    ConfNode *tmp;

    while ((tmp = TAILQ_FIRST(&node->head))) {
        TAILQ_REMOVE(&node->head, tmp, next);
        ConfNodeFree(tmp);
    }

    if (node->name != NULL)
        SCFree(node->name);
    if (node->val != NULL)
        SCFree(node->val);
    SCFree(node);
}

/**
 * \brief Get a ConfNode by name.
 *
 * \param key The full name of the configuration node to lookup.
 *
 * \retval A pointer to ConfNode is found or NULL if the configuration
 *    node does not exist.
 */
ConfNode *
ConfGetNode(char *key)
{
    ConfNode *node = root;
#if !defined(__WIN32) && !defined(_WIN32)
    char *saveptr = NULL;
#endif /* __WIN32 */
    char *token;

    /* Need to dup the key for tokenization... */
    char *tokstr = SCStrdup(key);
    if (unlikely(tokstr == NULL)) {
        return NULL;
    }

#if defined(__WIN32) || defined(_WIN32)
    token = strtok(tokstr, ".");
#else
    token = strtok_r(tokstr, ".", &saveptr);
#endif /* __WIN32 */
    for (;;) {
        node = ConfNodeLookupChild(node, token);
        if (node == NULL)
            break;

#if defined(__WIN32) || defined(_WIN32)
        token = strtok(NULL, ".");
#else
        token = strtok_r(NULL, ".", &saveptr);
#endif /* __WIN32 */
        if (token == NULL)
            break;
    }
    SCFree(tokstr);
    return node;
}

/**
 * \brief Get the root configuration node.
 */
ConfNode *
ConfGetRootNode(void)
{
    return root;
}

/**
 * \brief Set a configuration value.
 *
 * \param name The name of the configuration parameter to set.
 * \param val The value of the configuration parameter.
 * \param allow_override Can a subsequent set override this value.
 *
 * \retval 1 if the value was set otherwise 0.
 */
int
ConfSet(char *name, char *val, int allow_override)
{
    ConfNode *parent = root;
    ConfNode *node;
    char *token;
#if !defined(__WIN32) && !defined(_WIN32)
    char *saveptr = NULL;
#endif /* __WIN32 */
    /* First check if the node already exists. */
    node = ConfGetNode(name);
    if (node != NULL) {
        if (!node->allow_override) {
            return 0;
        }
        else {
            if (node->val != NULL)
                SCFree(node->val);
            node->val = SCStrdup(val);
            node->allow_override = allow_override;
            return 1;
        }
    }
    else {
        char *tokstr = SCStrdup(name);
        if (unlikely(tokstr == NULL)) {
            return 0;
        }
#if defined(__WIN32) || defined(_WIN32)
        token = strtok(tokstr, ".");
#else
        token = strtok_r(tokstr, ".", &saveptr);
#endif /* __WIN32 */
        node = ConfNodeLookupChild(parent, token);
        for (;;) {
            if (node == NULL) {
                node = ConfNodeNew();
                node->name = SCStrdup(token);
                node->parent = parent;
                TAILQ_INSERT_TAIL(&parent->head, node, next);
                parent = node;
            }
            else {
                parent = node;
            }
#if defined(__WIN32) || defined(_WIN32)
            token = strtok(NULL, ".");
#else
            token = strtok_r(NULL, ".", &saveptr);
#endif /* __WIN32 */
            if (token == NULL) {
                if (!node->allow_override)
                    break;
                if (node->val != NULL)
                    SCFree(node->val);
                node->val = SCStrdup(val);
                node->allow_override = allow_override;
                break;
            }
            else {
                node = ConfNodeLookupChild(parent, token);
            }
        }
        SCFree(tokstr);
    }

    SCLogDebug("configuration parameter '%s' set", name);

    return 1;
}

/**
 * \brief Retrieve the value of a configuration node.
 *
 * This function will return the value for a configuration node based
 * on the full name of the node.  It is possible that the value
 * returned could be NULL, this could happen if the requested node
 * does exist but is not a node that contains a value, but contains
 * children ConfNodes instead.
 *
 * \param name Name of configuration parameter to get.
 * \param vptr Pointer that will be set to the configuration value parameter.
 *   Note that this is just a reference to the actual value, not a copy.
 *
 * \retval 1 will be returned if the name is found, otherwise 0 will
 *   be returned.
 */
int
ConfGet(char *name, char **vptr)
{
    ConfNode *node = ConfGetNode(name);
    if (node == NULL) {
        SCLogDebug("failed to lookup configuration parameter '%s'", name);
        return 0;
    }
    else {
        *vptr = node->val;
        return 1;
    }
}

int ConfGetChildValue(ConfNode *base, char *name, char **vptr)
{
    ConfNode *node = ConfNodeLookupChild(base, name);

    if (node == NULL) {
        SCLogDebug("failed to lookup configuration parameter '%s'", name);
        return 0;
    }
    else {
        *vptr = node->val;
        return 1;
    }
}


int ConfGetChildValueWithDefault(ConfNode *base, ConfNode *dflt, char *name, char **vptr)
{
    int ret = ConfGetChildValue(base, name, vptr);
    /* Get 'default' value */
    if (ret == 0 && dflt) {
        return ConfGetChildValue(dflt, name, vptr);
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
 * converted to an interger, otherwise 0 will be returned.
 */
int
ConfGetInt(char *name, intmax_t *val)
{
    char *strval;
    intmax_t tmpint;
    char *endptr;

    if (ConfGet(name, &strval) == 0)
        return 0;

    errno = 0;
    tmpint = strtoimax(strval, &endptr, 0);
    if (strval[0] == '\0' || *endptr != '\0')
        return 0;
    if (errno == ERANGE && (tmpint == INTMAX_MAX || tmpint == INTMAX_MIN))
        return 0;

    *val = tmpint;
    return 1;
}

int ConfGetChildValueInt(ConfNode *base, char *name, intmax_t *val)
{
    char *strval;
    intmax_t tmpint;
    char *endptr;

    if (ConfGetChildValue(base, name, &strval) == 0)
        return 0;
    errno = 0;
    tmpint = strtoimax(strval, &endptr, 0);
    if (strval[0] == '\0' || *endptr != '\0')
        return 0;
    if (errno == ERANGE && (tmpint == INTMAX_MAX || tmpint == INTMAX_MIN))
        return 0;

    *val = tmpint;
    return 1;

}

int ConfGetChildValueIntWithDefault(ConfNode *base, ConfNode *dflt, char *name, intmax_t *val)
{
    int ret = ConfGetChildValueInt(base, name, val);
    /* Get 'default' value */
    if (ret == 0 && dflt) {
        return ConfGetChildValueInt(dflt, name, val);
    }
    return ret;
}


/**
 * \brief Retrieve a configuration value as an boolen.
 *
 * \param name Name of configuration parameter to get.
 * \param val Pointer to an int that will be set to 1 for true, or 0
 * for false.
 *
 * \retval 1 will be returned if the name is found and was properly
 * converted to a boolean, otherwise 0 will be returned.
 */
int
ConfGetBool(char *name, int *val)
{
    char *strval;

    *val = 0;
    if (ConfGet(name, &strval) != 1)
        return 0;

    *val = ConfValIsTrue(strval);

    return 1;
}

int ConfGetChildValueBool(ConfNode *base, char *name, int *val)
{
    char *strval;

    *val = 0;
    if (ConfGetChildValue(base, name, &strval) == 0)
        return 0;

    *val = ConfValIsTrue(strval);

    return 1;
}

int ConfGetChildValueBoolWithDefault(ConfNode *base, ConfNode *dflt, char *name, int *val)
{
    int ret = ConfGetChildValueBool(base, name, val);
    /* Get 'default' value */
    if (ret == 0 && dflt) {
        return ConfGetChildValueBool(dflt, name, val);
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
int
ConfValIsTrue(const char *val)
{
    char *trues[] = {"1", "yes", "true", "on"};
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
int
ConfValIsFalse(const char *val)
{
    char *falses[] = {"0", "no", "false", "off"};
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
int
ConfGetDouble(char *name, double *val)
{
    char *strval;
    double tmpdo;
    char *endptr;

    if (ConfGet(name, &strval) == 0)
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
int
ConfGetFloat(char *name, float *val)
{
    char *strval;
    double tmpfl;
    char *endptr;

    if (ConfGet(name, &strval) == 0)
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
void
ConfNodeRemove(ConfNode *node)
{
    if (node->parent != NULL)
        TAILQ_REMOVE(&node->parent->head, node, next);
    ConfNodeFree(node);
}

/**
 * \brief Remove a configuration parameter from the configuration db.
 *
 * \param name The name of the configuration parameter to remove.
 *
 * \retval Returns 1 if the parameter was removed, otherwise 0 is returned
 *   most likely indicating the parameter was not set.
 */
int
ConfRemove(char *name)
{
    ConfNode *node;

    node = ConfGetNode(name);
    if (node == NULL)
        return 0;
    else {
        ConfNodeRemove(node);
        return 1;
    }
}

/**
 * \brief Creates a backup of the conf_hash hash_table used by the conf API.
 */
void
ConfCreateContextBackup(void)
{
    root_backup = root;
    root = NULL;

    return;
}

/**
 * \brief Restores the backup of the hash_table present in backup_conf_hash
 *        back to conf_hash.
 */
void
ConfRestoreContextBackup(void)
{
    root = root_backup;
    root_backup = NULL;

    return;
}

/**
 * \brief De-initializes the configuration system.
 */
void
ConfDeInit(void)
{
    if (root != NULL) {
        ConfNodeFree(root);
        root = NULL;
    }

    SCLogDebug("configuration module de-initialized");
}

static char *
ConfPrintNameArray(char **name_arr, int level)
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
void
ConfNodeDump(ConfNode *node, const char *prefix)
{
    ConfNode *child;

    static char *name[128];
    static int level = -1;

    level++;
    TAILQ_FOREACH(child, &node->head, next) {
        name[level] = SCStrdup(child->name);
        if (prefix == NULL) {
            printf("%s = %s\n", ConfPrintNameArray(name, level),
                child->val);
        }
        else {
            printf("%s.%s = %s\n", prefix,
                ConfPrintNameArray(name, level), child->val);
        }
        ConfNodeDump(child, prefix);
        SCFree(name[level]);
    }
    level--;
}

/**
 * \brief Dump configuration to stdout.
 */
void
ConfDump(void)
{
    ConfNodeDump(root, NULL);
}

/**
 * \brief Lookup a child configuration node by name.
 *
 * Given a ConfNode this function will lookup an immediate child
 * ConfNode by name and return the child ConfNode.
 *
 * \param node The parent configuration node.
 * \param name The name of the child node to lookup.
 *
 * \retval A pointer the child ConfNode if found otherwise NULL.
 */
ConfNode *
ConfNodeLookupChild(ConfNode *node, const char *name)
{
    ConfNode *child;

    TAILQ_FOREACH(child, &node->head, next) {
        if (strcmp(child->name, name) == 0)
            return child;
    }

    return NULL;
}

/**
 * \brief Lookup the value of a child configuration node by name.
 *
 * Given a parent ConfNode this function will return the value of a
 * child configuration node by name returning a reference to that
 * value.
 *
 * \param node The parent configuration node.
 * \param name The name of the child node to lookup.
 *
 * \retval A pointer the child ConfNodes value if found otherwise NULL.
 */
const char *
ConfNodeLookupChildValue(ConfNode *node, const char *name)
{
    ConfNode *child;

    child = ConfNodeLookupChild(node, name);
    if (child != NULL)
        return child->val;

    return NULL;
}

/**
 * \brief Lookup for a key value under a specific node
 *
 * \return the ConfNode matching or NULL
 */

ConfNode *ConfNodeLookupKeyValue(ConfNode *base, const char *key, const char *value)
{
    ConfNode *child;

    TAILQ_FOREACH(child, &base->head, next) {
        if (!strncmp(child->val, key, strlen(child->val))) {
            ConfNode *subchild;
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
int
ConfNodeChildValueIsTrue(ConfNode *node, const char *key)
{
    const char *val;

    val = ConfNodeLookupChildValue(node, key);

    return val != NULL ? ConfValIsTrue(val) : 0;
}

/**
 *  \brief Create the path for an include entry
 *  \param file The name of the file
 *  \retval str Pointer to the string path + sig_file
 */
char *ConfLoadCompleteIncludePath(char *file)
{
    char *defaultpath = NULL;
    char *path = NULL;

    /* Path not specified */
    if (PathIsRelative(file)) {
        if (ConfGet("include-path", &defaultpath) == 1) {
            SCLogDebug("Default path: %s", defaultpath);
            size_t path_len = sizeof(char) * (strlen(defaultpath) +
                          strlen(file) + 2);
            path = SCMalloc(path_len);
            if (unlikely(path == NULL))
                return NULL;
            strlcpy(path, defaultpath, path_len);
            if (path[strlen(path) - 1] != '/')
                strlcat(path, "/", path_len);
            strlcat(path, file, path_len);
       } else {
            path = SCStrdup(file);
            if (unlikely(path == NULL))
                return NULL;
        }
    } else {
        path = SCStrdup(file);
        if (unlikely(path == NULL))
            return NULL;
    }
    return path;
}




#ifdef UNITTESTS

/**
 * Lookup a non-existant value.
 */
static int
ConfTestGetNonExistant(void)
{
    char name[] = "non-existant-value";
    char *value;

    return !ConfGet(name, &value);
}

/**
 * Set then lookup a value.
 */
static int
ConfTestSetAndGet(void)
{
    char name[] = "some-name";
    char value[] = "some-value";
    char *value0;

    if (ConfSet(name, value, 1) != 1)
        return 0;
    if (ConfGet(name, &value0) != 1)
        return 0;
    if (strcmp(value, value0) != 0)
        return 0;

    /* Cleanup. */
    ConfRemove(name);

    return 1;
}

/**
 * Test that overriding a value is allowed provided allow_override is
 * true and that the config parameter gets the new value.
 */
static int
ConfTestOverrideValue1(void)
{
    char name[] = "some-name";
    char value0[] = "some-value";
    char value1[] = "new-value";
    char *val;
    int rc;

    if (ConfSet(name, value0, 1) != 1)
        return 0;
    if (ConfSet(name, value1, 1) != 1)
        return 0;
    if (ConfGet(name, &val) != 1)
        return 0;

    rc = !strcmp(val, value1);

    /* Cleanup. */
    ConfRemove(name);

    return rc;
}

/**
 * Test that overriding a value is not allowed provided that
 * allow_override is false and make sure the value was not overrided.
 */
static int
ConfTestOverrideValue2(void)
{
    char name[] = "some-name";
    char value0[] = "some-value";
    char value1[] = "new-value";
    char *val;
    int rc;

    if (ConfSet(name, value0, 0) != 1)
        return 0;
    if (ConfSet(name, value1, 1) != 0)
        return 0;
    if (ConfGet(name, &val) != 1)
        return 0;

    rc = !strcmp(val, value0);

    /* Cleanup. */
    ConfRemove(name);

    return rc;
}

/**
 * Test retrieving an integer value from the configuration db.
 */
static int
ConfTestGetInt(void)
{
    char name[] = "some-int.x";
    intmax_t val;

    if (ConfSet(name, "0", 1) != 1)
        return 0;
    if (ConfGetInt(name, &val) != 1)
        return 0;

    if (val != 0)
        return 0;

    if (ConfSet(name, "-1", 1) != 1)
        return 0;
    if (ConfGetInt(name, &val) != 1)
        return 0;
    if (val != -1)
        return 0;

    if (ConfSet(name, "0xffff", 1) != 1)
        return 0;
    if (ConfGetInt(name, &val) != 1)
        return 0;
    if (val != 0xffff)
        return 0;

    if (ConfSet(name, "not-an-int", 1) != 1)
        return 0;
    if (ConfGetInt(name, &val) != 0)
        return 0;

    return 1;
}

/**
 * Test retrieving a boolean value from the configuration db.
 */
static int
ConfTestGetBool(void)
{
    char name[] = "some-bool";
    char *trues[] = {
        "1",
        "on", "ON",
        "yes", "YeS",
        "true", "TRUE",
    };
    char *falses[] = {
        "0",
        "something",
        "off", "OFF",
        "false", "FalSE",
        "no", "NO",
    };
    int val;
    size_t u;

    for (u = 0; u < sizeof(trues) / sizeof(trues[0]); u++) {
        if (ConfSet(name, trues[u], 1) != 1)
            return 0;
        if (ConfGetBool(name, &val) != 1)
            return 0;
        if (val != 1)
            return 0;
    }

    for (u = 0; u < sizeof(falses) / sizeof(falses[0]); u++) {
        if (ConfSet(name, falses[u], 1) != 1)
            return 0;
        if (ConfGetBool(name, &val) != 1)
            return 0;
        if (val != 0)
            return 0;
    }

    return 1;
}

static int
ConfNodeLookupChildTest(void)
{
    char *test_vals[] = { "one", "two", "three" };
    size_t u;

    ConfNode *parent = ConfNodeNew();
    ConfNode *child;

    for (u = 0; u < sizeof(test_vals)/sizeof(test_vals[0]); u++) {
        child = ConfNodeNew();
        child->name = SCStrdup(test_vals[u]);
        child->val = SCStrdup(test_vals[u]);
        TAILQ_INSERT_TAIL(&parent->head, child, next);
    }

    child = ConfNodeLookupChild(parent, "one");
    if (child == NULL)
        return 0;
    if (strcmp(child->name, "one") != 0)
        return 0;
    if (strcmp(child->val, "one") != 0)
        return 0;

    child = ConfNodeLookupChild(parent, "two");
    if (child == NULL)
        return 0;
    if (strcmp(child->name, "two") != 0)
        return 0;
    if (strcmp(child->val, "two") != 0)
        return 0;

    child = ConfNodeLookupChild(parent, "three");
    if (child == NULL)
        return 0;
    if (strcmp(child->name, "three") != 0)
        return 0;
    if (strcmp(child->val, "three") != 0)
        return 0;

    child = ConfNodeLookupChild(parent, "four");
    if (child != NULL)
        return 0;

    ConfNodeFree(parent);

    return 1;
}

static int
ConfNodeLookupChildValueTest(void)
{
    char *test_vals[] = { "one", "two", "three" };
    size_t u;

    ConfNode *parent = ConfNodeNew();
    ConfNode *child;
    const char *value;

    for (u = 0; u < sizeof(test_vals)/sizeof(test_vals[0]); u++) {
        child = ConfNodeNew();
        child->name = SCStrdup(test_vals[u]);
        child->val = SCStrdup(test_vals[u]);
        TAILQ_INSERT_TAIL(&parent->head, child, next);
    }

    value = (char *)ConfNodeLookupChildValue(parent, "one");
    if (value == NULL)
        return 0;
    if (strcmp(value, "one") != 0)
        return 0;

    value = (char *)ConfNodeLookupChildValue(parent, "two");
    if (value == NULL)
        return 0;
    if (strcmp(value, "two") != 0)
        return 0;

    value = (char *)ConfNodeLookupChildValue(parent, "three");
    if (value == NULL)
        return 0;
    if (strcmp(value, "three") != 0)
        return 0;

    value = (char *)ConfNodeLookupChildValue(parent, "four");
    if (value != NULL)
        return 0;

    ConfNodeFree(parent);

    return 1;
}

static int ConfGetChildValueWithDefaultTest(void)
{
    char  *val;
    int ret = 1;
    ConfCreateContextBackup();
    ConfInit();
    ConfSet("af-packet.0.interface", "eth0", 1);
    ConfSet("af-packet.1.interface", "default", 1);
    ConfSet("af-packet.1.cluster-type", "cluster_cpu", 1);

    ConfNode *root = ConfGetNode("af-packet.0");
    ConfNode *dflt = ConfGetNode("af-packet.1");
    ConfGetChildValueWithDefault(root, dflt, "cluster-type", &val);
    if (strcmp(val, "cluster_cpu")) {
        ConfDeInit();
        ConfRestoreContextBackup();
        return 0;
    }

    ConfSet("af-packet.0.cluster-type", "cluster_flow", 1);
    ConfGetChildValueWithDefault(root, dflt, "cluster-type", &val);

    if (strcmp(val, "cluster_flow")) {
        ret = 0;
    }
    ConfDeInit();
    ConfRestoreContextBackup();
    return ret;
}

static int ConfGetChildValueIntWithDefaultTest(void)
{
    intmax_t val;
    ConfCreateContextBackup();
    ConfInit();
    ConfSet("af-packet.0.interface", "eth0", 1);
    ConfSet("af-packet.1.interface", "default", 1);
    ConfSet("af-packet.1.threads", "2", 1);

    ConfNode *root = ConfGetNode("af-packet.0");
    ConfNode *dflt = ConfGetNode("af-packet.1");
    ConfGetChildValueIntWithDefault(root, dflt, "threads", &val);
    if (val != 2) {
        ConfDeInit();
        ConfRestoreContextBackup();
        return 0;
    }

    ConfSet("af-packet.0.threads", "1", 1);
    ConfGetChildValueIntWithDefault(root, dflt, "threads", &val);

    ConfDeInit();
    ConfRestoreContextBackup();
    if (val != 1) {
        return 0;
    }
    return 1;
}

static int ConfGetChildValueBoolWithDefaultTest(void)
{
    int val;
    ConfCreateContextBackup();
    ConfInit();
    ConfSet("af-packet.0.interface", "eth0", 1);
    ConfSet("af-packet.1.interface", "default", 1);
    ConfSet("af-packet.1.use-mmap", "yes", 1);

    ConfNode *root = ConfGetNode("af-packet.0");
    ConfNode *dflt = ConfGetNode("af-packet.1");
    ConfGetChildValueBoolWithDefault(root, dflt, "use-mmap", &val);
    if (val == 0) {
        ConfDeInit();
        ConfRestoreContextBackup();
        return 0;
    }

    ConfSet("af-packet.0.use-mmap", "no", 1);
    ConfGetChildValueBoolWithDefault(root, dflt, "use-mmap", &val);

    ConfDeInit();
    ConfRestoreContextBackup();
    if (val) {
        return 0;
    }
    return 1;
}

/**
 * Test the removal of a configuration node.
 */
static int
ConfNodeRemoveTest(void)
{
    ConfCreateContextBackup();
    ConfInit();

    if (ConfSet("some.nested.parameter", "blah", 1) != 1)
        return 0;

    ConfNode *node = ConfGetNode("some.nested.parameter");
    if (node == NULL)
        return 0;
    ConfNodeRemove(node);

    node = ConfGetNode("some.nested.parameter");
    if (node != NULL)
        return 0;

    ConfDeInit();
    ConfRestoreContextBackup();

    return 1;
}

static int
ConfSetTest(void)
{
    ConfCreateContextBackup();
    ConfInit();

    /* Set some value with 2 levels. */
    if (ConfSet("one.two", "three", 1) != 1)
        return 0;
    ConfNode *n = ConfGetNode("one.two");
    if (n == NULL)
        return 0;

    /* Set another 2 level parameter with the same first level, this
     * used to trigger a bug that caused the second level of the name
     * to become a first level node. */
    if (ConfSet("one.three", "four", 1) != 1)
        return 0;

    n = ConfGetNode("one.three");
    if (n == NULL)
        return 0;

    /* A top level node of "three" should not exist. */
    n = ConfGetNode("three");
    if (n != NULL)
        return 0;

    ConfDeInit();
    ConfRestoreContextBackup();

    return 1;
}


void
ConfRegisterTests(void)
{
    UtRegisterTest("ConfTestGetNonExistant", ConfTestGetNonExistant, 1);
    UtRegisterTest("ConfSetTest", ConfSetTest, 1);
    UtRegisterTest("ConfTestSetAndGet", ConfTestSetAndGet, 1);
    UtRegisterTest("ConfTestOverrideValue1", ConfTestOverrideValue1, 1);
    UtRegisterTest("ConfTestOverrideValue2", ConfTestOverrideValue2, 1);
    UtRegisterTest("ConfTestGetInt", ConfTestGetInt, 1);
    UtRegisterTest("ConfTestGetBool", ConfTestGetBool, 1);
    UtRegisterTest("ConfNodeLookupChildTest", ConfNodeLookupChildTest, 1);
    UtRegisterTest("ConfNodeLookupChildValueTest", ConfNodeLookupChildValueTest, 1);
    UtRegisterTest("ConfNodeRemoveTest", ConfNodeRemoveTest, 1);
    UtRegisterTest("ConfGetChildValueWithDefaultTest", ConfGetChildValueWithDefaultTest, 1);
    UtRegisterTest("ConfGetChildValueIntWithDefaultTest", ConfGetChildValueIntWithDefaultTest, 1);
    UtRegisterTest("ConfGetChildValueBoolWithDefaultTest", ConfGetChildValueBoolWithDefaultTest, 1);
}

#endif /* UNITTESTS */
