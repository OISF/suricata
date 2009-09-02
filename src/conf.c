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
 * \author Endace Technology Limited
 *
 * \todo Consider using HashListTable to allow easy dumping of all data.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "eidps-common.h"
#include "conf.h"
#include "util-hash.h"
#include "util-unittest.h"

#undef CONF_DEBUG
#ifdef CONF_DEBUG
#define DPRINTF(x)    do { printf x ; } while (0)
#else
#define DPRINTF(x)
#endif /* CONF_DEBUG */

#define CONF_HASH_TBL_SIZE 1024

static HashTable *conf_hash = NULL;

/**
 * Structure of a configuration parameter.
 */
typedef struct ConfNode_ {
    char *name;
    char *val;

    int allow_override;
} ConfNode;

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
    DPRINTF(("%s: %s -> %" PRIu32 "\n", __func__, cn->name, hash));
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

    DPRINTF(("%s: Freeing configuration parameter '%s'\n", __func__, cn->name));
    free(cn->name);
    free(cn->val);
    free(cn);
}

/**
 * \brief Initialize the configuration system.
 */
void
ConfInit(void)
{
    /* Prevent double initialization. */
    if (conf_hash != NULL) {
        DPRINTF(("%s: Already initialized.\n", __func__));
        return;
    }

    conf_hash = HashTableInit(CONF_HASH_TBL_SIZE, ConfHashFunc, ConfHashComp,
        ConfHashFree);
    if (conf_hash == NULL) {
        fprintf(stderr,
            "ERROR: Failed to allocate memory for configuration, aborting.\n");
        exit(1);
    }
    DPRINTF(("%s: Configuration module initialized.\n", __func__));
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

    conf_node = calloc(1, sizeof(*conf_node));
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
    DPRINTF(("%s: Configuration parameter '%s' set.\n", __func__, name));

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

    lookup_key.name = name;

    conf_node = HashTableLookup(conf_hash, &lookup_key, sizeof(lookup_key));
    if (conf_node == NULL) {
        DPRINTF(("%s: Failed to lookup configuration parameter '%s'\n",
                 __func__, name));
        return 0;
    }
    else {
        *vptr = conf_node->val;
        return 1;
    }
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
                printf("%s=%s\n", cn->name, cn->val);
                b = b->next;
            }
        }
    }
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

void
ConfRegisterTests(void)
{
    UtRegisterTest("ConfTestGetNonExistant", ConfTestGetNonExistant, 1);
    UtRegisterTest("ConfTestSetAndGet", ConfTestSetAndGet, 1);
    UtRegisterTest("ConfTestOverrideValue1", ConfTestOverrideValue1, 1);
    UtRegisterTest("ConfTestOverrideValue2", ConfTestOverrideValue2, 1);
}

#endif /* UNITTESTS */
