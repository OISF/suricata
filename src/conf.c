/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * This file provides a basic configuration system for the IDPS
 * engine.
 *
 * NOTE: Setting values should only be done from one thread during
 * engine initialization.  Multiple threads should be able access read
 * configuration data.  Allowing run time changes to the configuration
 * will require some locks.
 *
 * \author Endace Technology Limited - Jason Ish <jason.ish@endace.com>
 *
 * \todo Consider using HashListTable to allow easy dumping of all data.
 */

#include "suricata-common.h"
#include "conf.h"
#include "util-hash.h"
#include "util-unittest.h"
#include "util-debug.h"

#define CONF_HASH_TBL_SIZE 1024

static HashTable *conf_hash = NULL;

/* temporary variable that would be used to hold the hash_table instance
 * present in conf_hash.  Used while running tests that require their
 * own yaml conf file.  The backup can be set and then be reused by using
 * the function ConfCreateContextBackup() and ConfRestoreContextBackup() */
static HashTable *backup_conf_hash = NULL;

/**
 * \brief Function to generate the hash of a configuration value.
 *
 * This is a callback function provided to HashTable for creating the
 * hash key.  Its a simple wrapper around the generic hash function
 * the passes on the configuration parameter name.
 *
 * \retval The hash ID of the configuration parameters name.
 */
static uint32_t
ConfHashFunc(HashTable *ht, void *data, uint16_t len)
{
    ConfNode *cn = (ConfNode *)data;
    uint32_t hash;

    hash = HashTableGenericHash(ht, cn->name, strlen(cn->name));
    SCLogDebug("%s -> %" PRIu32 "", cn->name, hash);
    return hash;
}

/**
 * \brief Function to compare 2 hash nodes.
 *
 * This is a callback function provided to the HashTable for comparing
 * 2 nodes.
 *
 * \retval 1 if equivalant otherwise 0.
 */
static char
ConfHashComp(void *a, uint16_t a_len, void *b, uint16_t b_len)
{
    ConfNode *ca = (ConfNode *)a;
    ConfNode *cb = (ConfNode *)b;

    if (strcmp(ca->name, cb->name) == 0)
        return 1;
    else
        return 0;
}

/**
 * \brief Callback function to free a hash node.
 */
static void ConfHashFree(void *data)
{
    ConfNode *cn = (ConfNode *)data;
    if (cn == NULL)
        return;

    /** \todo VJ apparently the list that is free is also in the hash
     *           individually resulting in double free errors if we
     *           call ConfNodeFree (that clears the list) from this
     *           hash free function */

    if (cn->name != NULL)
        free(cn->name);
    if (cn->val != NULL)
        free(cn->val);
    free(cn);
    //ConfNodeFree(cn);
}

/**
 * \brief Initialize the configuration system.
 */
void
ConfInit(void)
{
    /* Prevent double initialization. */
    if (conf_hash != NULL) {
        SCLogDebug("already initialized");
        return;
    }

    conf_hash = HashTableInit(CONF_HASH_TBL_SIZE, ConfHashFunc, ConfHashComp,
        ConfHashFree);
    if (conf_hash == NULL) {
        fprintf(stderr,
            "ERROR: Failed to allocate memory for configuration, aborting.\n");
        exit(1);
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

    new = calloc(1, sizeof(*new));
    if (new == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC,
            "Error allocating memory for new configuration node");
        exit(EXIT_FAILURE);
    }
    TAILQ_INIT(&new->head);

    return new;
}

/**
 * \brief Free a ConfNode and all of its children.
 *
 * \param node The configuration node to free.
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
        free(node->name);
    if (node->val != NULL)
        free(node->val);
    free(node);
}

/**
 * \brief Set a configuration node.
 *
 * \retval 1 on success, 0 on failure.
 */
int
ConfSetNode(ConfNode *node)
{
    ConfNode lookup;
    ConfNode *pnode;

    lookup.name = node->name;
    pnode = HashTableLookup(conf_hash, &lookup, sizeof(lookup));
    if (pnode != NULL) {
        if (!pnode->allow_override) {
            return 0;
        }
        HashTableRemove(conf_hash, pnode, sizeof(*pnode));
    }

    if (HashTableAdd(conf_hash, node, sizeof(*node)) != 0) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to add new configuration node.");
        exit(EXIT_FAILURE);
    }

    return 1;
}

/**
 * \brief Get a ConfNode by key.
 *
 * \param key The lookup key of the node to find.
 *
 * \retval The node matching the key or NULL if not found.
 */
ConfNode *
ConfGetNode(char *key)
{
    ConfNode lookup;
    ConfNode *node;

    lookup.name = key;

    node = HashTableLookup(conf_hash, &lookup, sizeof(lookup));
    return node;
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
    ConfNode lookup_key, *conf_node;

    lookup_key.name = name;
    conf_node = HashTableLookup(conf_hash, &lookup_key, sizeof(lookup_key));
    if (conf_node != NULL) {
        if (!conf_node->allow_override) {
            return 0;
        }
        HashTableRemove(conf_hash, conf_node, sizeof(*conf_node));
    }

    conf_node = ConfNodeNew();
    if (conf_node == NULL) {
        return 0;
    }
    conf_node->name = strdup(name);
    conf_node->val = strdup(val);
    conf_node->allow_override = allow_override;

    if (HashTableAdd(conf_hash, conf_node, sizeof(*conf_node)) != 0) {
        fprintf(stderr, "ERROR: Failed to set configuration parameter %s\n",
            name);
        exit(1);
    }
    SCLogDebug("configuration parameter '%s' set", name);

    return 1;
}

/**
 * \brief Retrieve a configuration value.
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
    ConfNode lookup_key;
    ConfNode *conf_node;

    if (conf_hash == NULL)
        return 0;

    lookup_key.name = name;

    conf_node = HashTableLookup(conf_hash, &lookup_key, sizeof(lookup_key));
    if (conf_node == NULL) {
        SCLogDebug("failed to lookup configuration parameter '%s'", name);
        return 0;
    }
    else {
        *vptr = conf_node->val;
        return 1;
    }
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
    char *trues[] = {"1", "yes", "true", "on"};
    int i;

    *val = 0;
    if (ConfGet(name, &strval) != 1)
        return 0;

    for (i = 0; i < sizeof(trues) / sizeof(trues[0]); i++) {
        if (strcasecmp(strval, trues[i]) == 0) {
            *val = 1;
            break;
        }
    }

    return 1;
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
    ConfNode cn;

    cn.name = name;
    if (HashTableRemove(conf_hash, &cn, sizeof(cn)) == 0)
        return 1;
    else
        return 0;
}

/**
 * \brief Creates a backup of the conf_hash hash_table used by the conf API.
 */
void
ConfCreateContextBackup(void)
{
    backup_conf_hash = conf_hash;
    conf_hash = NULL;

    return;
}

/**
 * \brief Restores the backup of the hash_table present in backup_conf_hash
 *        back to conf_hash.
 */
void
ConfRestoreContextBackup(void)
{
    conf_hash = backup_conf_hash;

    return;
}

/**
 * \brief De-initializes the configuration system.
 */
void
ConfDeInit(void)
{
    if (conf_hash == NULL)
        return;

    HashTableFree(conf_hash);
    conf_hash = NULL;

    SCLogDebug("configuration module de-initialized");
}

static char *
ConfPrintNameArray(char **name_arr, int level)
{
    static char name[128*128];
    int i;

    name[0] = '\0';
    for (i = 0; i <= level; i++) {
        strcat(name, name_arr[i]);
        if (i < level)
            strcat(name, ".");
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
        name[level] = strdup(child->name);
        if (child->val != NULL)
            printf("%s.%s = %s\n", prefix,
                ConfPrintNameArray(name, level), child->val);
        ConfNodeDump(child, prefix);
        free(name[level]);
    }
    level--;
}

/**
 * \brief Dump configuration to stdout.
 */
void
ConfDump(void)
{
    HashTableBucket *b;
    ConfNode *cn;
    int i;

    for (i = 0; i < conf_hash->array_size; i++) {
        if (conf_hash->array[i] != NULL) {
            b = (HashTableBucket *)conf_hash->array[i];
            while (b != NULL) {
                cn = (ConfNode *)b->data;
                if (cn->val != NULL)
                    printf("%s = %s\n", cn->name, cn->val);
                ConfNodeDump(cn, cn->name);
                b = b->next;
            }
        }
    }
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

static int
ConfTestSetGetNode(void)
{
    ConfNode *set;
    ConfNode *get;
    char key[] = "some-key";
    char val[] = "some-val";

    set = ConfNodeNew();
    if (set == NULL)
        return 0;
    set->name = strdup(key);
    set->val = strdup(val);
    if (ConfSetNode(set) != 1)
        return 0;

    get = ConfGetNode(key);
    if (get == NULL)
        return 0;
    if (strcmp(get->name, key) != 0)
        return 0;
    if (strcmp(get->val, val) != 0)
        return 0;

    ConfRemove(key);
    get = ConfGetNode(key);
    if (get != NULL)
        return 0;

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
    char name[] = "some-int";
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
    int i;

    for (i = 0; i < sizeof(trues) / sizeof(trues[0]); i++) {
        if (ConfSet(name, trues[i], 1) != 1)
            return 0;
        if (ConfGetBool(name, &val) != 1)
            return 0;
        if (val != 1)
            return 0;
    }

    for (i = 0; i < sizeof(falses) / sizeof(falses[0]); i++) {
        if (ConfSet(name, falses[i], 1) != 1)
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
    int i;

    ConfNode *parent = ConfNodeNew();
    ConfNode *child;

    for (i = 0; i < sizeof(test_vals)/sizeof(test_vals[0]); i++) {
        child = ConfNodeNew();
        child->name = strdup(test_vals[i]);
        child->val = strdup(test_vals[i]);
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
    int i;

    ConfNode *parent = ConfNodeNew();
    ConfNode *child;
    const char *value;

    for (i = 0; i < sizeof(test_vals)/sizeof(test_vals[0]); i++) {
        child = ConfNodeNew();
        child->name = strdup(test_vals[i]);
        child->val = strdup(test_vals[i]);
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

void
ConfRegisterTests(void)
{
    UtRegisterTest("ConfTestGetNonExistant", ConfTestGetNonExistant, 1);
    UtRegisterTest("ConfTestSetGetNode", ConfTestSetGetNode, 1);
    UtRegisterTest("ConfTestSetAndGet", ConfTestSetAndGet, 1);
    UtRegisterTest("ConfTestOverrideValue1", ConfTestOverrideValue1, 1);
    UtRegisterTest("ConfTestOverrideValue2", ConfTestOverrideValue2, 1);
    UtRegisterTest("ConfTestGetInt", ConfTestGetInt, 1);
    UtRegisterTest("ConfTestGetBool", ConfTestGetBool, 1);
    UtRegisterTest("ConfNodeLookupChildTest", ConfNodeLookupChildTest, 1);
    UtRegisterTest("ConfNodeLookupChildValueTest", ConfNodeLookupChildValueTest, 1);
}

#endif /* UNITTESTS */
