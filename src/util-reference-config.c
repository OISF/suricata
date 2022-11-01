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
 */

#include "suricata-common.h"
#include "detect-engine.h"

#include "util-reference-config.h"
#include "util-fmemopen.h"

/* Regex to parse each line from reference.config file.  The first substring
 * is for the system name and the second for the url */
/*-----------------------------------------------------------system-------------------url----*/
#define SC_RCONF_REGEX "^\\s*config\\s+reference\\s*:\\s*([a-zA-Z][a-zA-Z0-9-_]*)\\s+(.+)\\s*$"

/* Default path for the reference.conf file */
#define SC_RCONF_DEFAULT_FILE_PATH CONFIG_DIR "/reference.config"

static pcre2_code *regex = NULL;
static pcre2_match_data *regex_match = NULL;

/* the hash functions */
uint32_t SCRConfReferenceHashFunc(HashTable *ht, void *data, uint16_t datalen);
char SCRConfReferenceHashCompareFunc(void *data1, uint16_t datalen1,
                                     void *data2, uint16_t datalen2);
void SCRConfReferenceHashFree(void *ch);

/* used to get the reference.config file path */
static const char *SCRConfGetConfFilename(const DetectEngineCtx *de_ctx);

void SCReferenceConfInit(void)
{
    int en;
    PCRE2_SIZE eo;
    int opts = 0;

    regex = pcre2_compile((PCRE2_SPTR8)SC_RCONF_REGEX, PCRE2_ZERO_TERMINATED, opts, &en, &eo, NULL);
    if (regex == NULL) {
        PCRE2_UCHAR errbuffer[256];
        pcre2_get_error_message(en, errbuffer, sizeof(errbuffer));
        SCLogWarning(SC_ERR_PCRE_COMPILE,
                "pcre2 compile of \"%s\" failed at "
                "offset %d: %s",
                SC_RCONF_REGEX, (int)eo, errbuffer);
        return;
    }
    regex_match = pcre2_match_data_create_from_pattern(regex, NULL);

    return;
}

void SCReferenceConfDeinit(void)
{
    if (regex != NULL) {
        pcre2_code_free(regex);
        regex = NULL;
    }
    if (regex_match != NULL) {
        pcre2_match_data_free(regex_match);
        regex_match = NULL;
    }
}


/**
 * \brief Inits the context to be used by the Reference Config parsing API.
 *
 *        This function initializes the hash table to be used by the Detection
 *        Engine Context to hold the data from reference.config file,
 *        obtains the file descriptor to parse the reference.config file, and
 *        inits the regex used to parse the lines from reference.config file.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 *
 * \note if file open fails, we leave de_ctx->reference_conf_ht initialized
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static FILE *SCRConfInitContextAndLocalResources(DetectEngineCtx *de_ctx, FILE *fd)
{
    /* init the hash table to be used by the reference config references */
    de_ctx->reference_conf_ht = HashTableInit(128, SCRConfReferenceHashFunc,
                                              SCRConfReferenceHashCompareFunc,
                                              SCRConfReferenceHashFree);
    if (de_ctx->reference_conf_ht == NULL) {
        SCLogError(SC_ERR_HASH_TABLE_INIT, "Error initializing the hash "
                   "table");
        return NULL;
    }

    /* if it is not NULL, use the file descriptor.  The hack so that we can
     * avoid using a dummy reference file for testing purposes and
     * instead use an input stream against a buffer containing the
     * reference strings */
    if (fd == NULL) {
        const char *filename = SCRConfGetConfFilename(de_ctx);
        if ((fd = fopen(filename, "r")) == NULL) {
#ifdef UNITTESTS
            if (RunmodeIsUnittests()) {
                return NULL; // silently fail
            }
#endif
            SCLogError(SC_ERR_FOPEN, "Error opening file: \"%s\": %s", filename,
                       strerror(errno));
            return NULL;
        }
    }

    return fd;
}


/**
 * \brief Returns the path for the Reference Config file.  We check if we
 *        can retrieve the path from the yaml conf file.  If it is not present,
 *        return the default path for the reference.config file which is
 *        "./reference.config".
 *
 * \retval log_filename Pointer to a string containing the path for the
 *                      reference.config file.
 */
static const char *SCRConfGetConfFilename(const DetectEngineCtx *de_ctx)
{
    const char *path = NULL;

    if (de_ctx != NULL && strlen(de_ctx->config_prefix) > 0) {
        char config_value[256];
        snprintf(config_value, sizeof(config_value),
                 "%s.reference-config-file", de_ctx->config_prefix);

        /* try loading prefix setting, fall back to global if that
         * fails. */
        if (ConfGet(config_value, &path) != 1) {
            if (ConfGet("reference-config-file", &path) != 1) {
                return (char *)SC_RCONF_DEFAULT_FILE_PATH;
            }
        }
    } else {
        if (ConfGet("reference-config-file", &path) != 1) {
            return (char *)SC_RCONF_DEFAULT_FILE_PATH;
        }
    }
    return path;
}

/**
 * \brief Releases local resources used by the Reference Config API.
 */
static void SCRConfDeInitLocalResources(DetectEngineCtx *de_ctx, FILE *fd)
{
    if (fd != NULL) {
        fclose(fd);
    }

    return;
}

/**
 * \brief Releases de_ctx resources related to Reference Config API.
 */
void SCRConfDeInitContext(DetectEngineCtx *de_ctx)
{
    if (de_ctx->reference_conf_ht != NULL)
        HashTableFree(de_ctx->reference_conf_ht);

    de_ctx->reference_conf_ht = NULL;

    return;
}

/**
 * \brief Converts a string to lowercase.
 *
 * \param str Pointer to the string to be converted.
 */
static char *SCRConfStringToLowercase(const char *str)
{
    char *new_str = NULL;
    char *temp_str = NULL;

    if ((new_str = SCStrdup(str)) == NULL) {
        return NULL;
    }

    temp_str = new_str;
    while (*temp_str != '\0') {
        *temp_str = u8_tolower((unsigned char)*temp_str);
        temp_str++;
    }

    return new_str;
}

/**
 * \brief Parses a line from the reference config file and adds it to Reference
 *        Config hash table DetectEngineCtx->reference_conf_ht.
 *
 * \param rawstr Pointer to the string to be parsed.
 * \param de_ctx Pointer to the Detection Engine Context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCRConfAddReference(DetectEngineCtx *de_ctx, const char *line)
{
    char system[REFERENCE_SYSTEM_NAME_MAX];
    char url[REFERENCE_CONTENT_NAME_MAX];

    SCRConfReference *ref_new = NULL;
    SCRConfReference *ref_lookup = NULL;

    int ret = 0;

    ret = pcre2_match(regex, (PCRE2_SPTR8)line, strlen(line), 0, 0, regex_match, NULL);
    if (ret < 0) {
        SCLogError(SC_ERR_REFERENCE_CONFIG, "Invalid Reference Config in "
                   "reference.config file");
        goto error;
    }

    /* retrieve the reference system */
    size_t copylen = sizeof(system);
    ret = pcre2_substring_copy_bynumber(regex_match, 1, (PCRE2_UCHAR8 *)system, &copylen);
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber() failed");
        goto error;
    }

    /* retrieve the reference url */
    copylen = sizeof(url);
    ret = pcre2_substring_copy_bynumber(regex_match, 2, (PCRE2_UCHAR8 *)url, &copylen);
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber() failed");
        goto error;
    }

    /* Create a new instance of the parsed Reference string */
    ref_new = SCRConfAllocSCRConfReference(system, url);
    if (ref_new == NULL)
        goto error;

    /* Check if the Reference is present in the HashTable.  In case it's present
     * ignore it, as it's a duplicate.  If not present, add it to the table */
    ref_lookup = HashTableLookup(de_ctx->reference_conf_ht, ref_new, 0);
    if (ref_lookup == NULL) {
        if (HashTableAdd(de_ctx->reference_conf_ht, ref_new, 0) < 0) {
            SCLogDebug("HashTable Add failed");
        }
    } else {
        SCLogDebug("Duplicate reference found inside reference.config");
        SCRConfDeAllocSCRConfReference(ref_new);
    }

    return 0;

 error:
    return -1;
}

/**
 * \brief Checks if a string is a comment or a blank line.
 *
 *        Comments lines are lines of the following format -
 *        "# This is a comment string" or
 *        "   # This is a comment string".
 *
 * \param line String that has to be checked.
 *
 * \retval 1 On the argument string being a comment or blank line.
 * \retval 0 Otherwise.
 */
static int SCRConfIsLineBlankOrComment(char *line)
{
    while (*line != '\0') {
        /* we have a comment */
        if (*line == '#')
            return 1;

        /* this line is neither a comment line, nor a blank line */
        if (!isspace((unsigned char)*line))
            return 0;

        line++;
    }

    /* we have a blank line */
    return 1;
}

/**
 * \brief Parses the Reference Config file and updates the
 *        DetectionEngineCtx->reference_conf_ht with the Reference information.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 */
static bool SCRConfParseFile(DetectEngineCtx *de_ctx, FILE *fd)
{
    char line[1024];
    uint8_t i = 1;

    int runmode = RunmodeGetCurrent();
    bool is_conf_test_mode = runmode == RUNMODE_CONF_TEST;
    while (fgets(line, sizeof(line), fd) != NULL) {
        if (SCRConfIsLineBlankOrComment(line))
            continue;

        if (SCRConfAddReference(de_ctx, line) != 0) {
            if (is_conf_test_mode) {
                return false;
            }
        }
        i++;
    }

#ifdef UNITTESTS
    SCLogInfo("Added \"%d\" reference types from the reference.config file",
              de_ctx->reference_conf_ht->count);
#endif /* UNITTESTS */
    return true;
}

/**
 * \brief Returns a new SCRConfReference instance.  The reference string
 *        is converted into lowercase, before being assigned to the instance.
 *
 * \param system  Pointer to the system.
 * \param url     Pointer to the reference url.
 *
 * \retval ref Pointer to the new instance of SCRConfReference.
 */
SCRConfReference *SCRConfAllocSCRConfReference(const char *system,
                                               const char *url)
{
    SCRConfReference *ref = NULL;

    if (system == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid arguments.  system NULL");
        return NULL;
    }

    if ((ref = SCMalloc(sizeof(SCRConfReference))) == NULL) {
        return NULL;
    }
    memset(ref, 0, sizeof(SCRConfReference));

    if ((ref->system = SCRConfStringToLowercase(system)) == NULL) {
        SCFree(ref);
        return NULL;
    }

    if (url != NULL && (ref->url = SCStrdup(url)) == NULL) {
        SCFree(ref->system);
        SCFree(ref);
        return NULL;
    }

    return ref;
}

/**
 * \brief Frees a SCRConfReference instance.
 *
 * \param Pointer to the SCRConfReference instance that has to be freed.
 */
void SCRConfDeAllocSCRConfReference(SCRConfReference *ref)
{
    if (ref != NULL) {
        if (ref->system != NULL)
            SCFree(ref->system);

        if (ref->url != NULL)
            SCFree(ref->url);

        SCFree(ref);
    }

    return;
}

/**
 * \brief Hashing function to be used to hash the Reference name.  Would be
 *        supplied as an argument to the HashTableInit function for
 *        DetectEngineCtx->reference_conf_ht.
 *
 * \param ht      Pointer to the HashTable.
 * \param data    Pointer to the data to be hashed.  In this case, the data
 *                would be a pointer to a SCRConfReference instance.
 * \param datalen Not used by this function.
 */
uint32_t SCRConfReferenceHashFunc(HashTable *ht, void *data, uint16_t datalen)
{
    SCRConfReference *ref = (SCRConfReference *)data;
    uint32_t hash = 0;
    int i = 0;

    int len = strlen(ref->system);

    for (i = 0; i < len; i++)
        hash += u8_tolower((unsigned char)ref->system[i]);

    hash = hash % ht->array_size;

    return hash;
}

/**
 * \brief Used to compare two References that have been stored in the HashTable.
 *        This function is supplied as an argument to the HashTableInit function
 *        for DetectionEngineCtx->reference_conf_ct.
 *
 * \param data1 Pointer to the first SCRConfReference to be compared.
 * \param len1  Not used by this function.
 * \param data2 Pointer to the second SCRConfReference to be compared.
 * \param len2  Not used by this function.
 *
 * \retval 1 On data1 and data2 being equal.
 * \retval 0 On data1 and data2 not being equal.
 */
char SCRConfReferenceHashCompareFunc(void *data1, uint16_t datalen1,
                                     void *data2, uint16_t datalen2)
{
    SCRConfReference *ref1 = (SCRConfReference *)data1;
    SCRConfReference *ref2 = (SCRConfReference *)data2;
    int len1 = 0;
    int len2 = 0;

    if (ref1 == NULL || ref2 == NULL)
        return 0;

    if (ref1->system == NULL || ref2->system == NULL)
        return 0;

    len1 = strlen(ref1->system);
    len2 = strlen(ref2->system);

    if (len1 == len2 && memcmp(ref1->system, ref2->system, len1) == 0) {
        SCLogDebug("Match found inside Reference-Config hash function");
        return 1;
    }

    return 0;
}

/**
 * \brief Used to free the Reference Config Hash Data that was stored in
 *        DetectEngineCtx->reference_conf_ht Hashtable.
 *
 * \param data Pointer to the data that has to be freed.
 */
void SCRConfReferenceHashFree(void *data)
{
    SCRConfDeAllocSCRConfReference(data);

    return;
}

/**
 * \brief Loads the Reference info from the reference.config file.
 *
 *        The reference.config file contains references that can be used in
 *        Signatures.  Each line of the file should  have the following format -
 *        config reference: system_name, reference_url.
 *
 * \param de_ctx Pointer to the Detection Engine Context that should be updated
 *               with reference information.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCRConfLoadReferenceConfigFile(DetectEngineCtx *de_ctx, FILE *fd)
{
    fd = SCRConfInitContextAndLocalResources(de_ctx, fd);
    if (fd == NULL) {
#ifdef UNITTESTS
        if (RunmodeIsUnittests()) {
            return -1;
        }
#endif
        SCLogError(SC_ERR_OPENING_FILE, "please check the \"reference-config-file\" "
                "option in your suricata.yaml file");
        return -1;
    }

    bool rc = SCRConfParseFile(de_ctx, fd);
    SCRConfDeInitLocalResources(de_ctx, fd);

    return rc ? 0 : -1;
}

/**
 * \brief Gets the reference config from the corresponding hash table stored
 *        in the Detection Engine Context's reference conf ht, given the
 *        reference name.
 *
 * \param ct_name Pointer to the reference name that has to be looked up.
 * \param de_ctx  Pointer to the Detection Engine Context.
 *
 * \retval lookup_rconf_info Pointer to the SCRConfReference instance from
 *                           the hash table on success; NULL on failure.
 */
SCRConfReference *SCRConfGetReference(const char *rconf_name,
                                      DetectEngineCtx *de_ctx)
{
    SCRConfReference *ref_conf = SCRConfAllocSCRConfReference(rconf_name, NULL);
    if (ref_conf == NULL)
        return NULL;
    SCRConfReference *lookup_ref_conf = HashTableLookup(de_ctx->reference_conf_ht,
                                                        ref_conf, 0);

    SCRConfDeAllocSCRConfReference(ref_conf);
    return lookup_ref_conf;
}

/*----------------------------------Unittests---------------------------------*/


#ifdef UNITTESTS

/**
 * \brief Creates a dummy reference config, with all valid references, for
 *        testing purposes.
 */
FILE *SCRConfGenerateValidDummyReferenceConfigFD01(void)
{
    const char *buffer =
        "config reference: one http://www.one.com\n"
        "config reference: two http://www.two.com\n"
        "config reference: three http://www.three.com\n"
        "config reference: one http://www.one.com\n"
        "config reference: three http://www.three.com\n";

    FILE *fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Reference Config test code");

    return fd;
}

/**
 * \brief Creates a dummy reference config, with some valid references and a
 *        couple of invalid references, for testing purposes.
 */
FILE *SCRConfGenerateInValidDummyReferenceConfigFD02(void)
{
    const char *buffer =
        "config reference: one http://www.one.com\n"
        "config_ reference: two http://www.two.com\n"
        "config reference_: three http://www.three.com\n"
        "config reference: four\n"
        "config reference five http://www.five.com\n";

    FILE *fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Reference Config test code");

    return fd;
}

/**
 * \brief Creates a dummy reference config, with all invalid references, for
 *        testing purposes.
 */
FILE *SCRConfGenerateInValidDummyReferenceConfigFD03(void)
{
    const char *buffer =
        "config reference one http://www.one.com\n"
        "config_ reference: two http://www.two.com\n"
        "config reference_: three http://www.three.com\n"
        "config reference: four\n";

    FILE *fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Reference Config test code");

    return fd;
}

/**
 * \test Check that the reference file is loaded and the detection engine
 *       content reference_conf_ht loaded with the reference data.
 */
static int SCRConfTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    int result = 0;

    if (de_ctx == NULL)
        return result;

    FILE *fd = SCRConfGenerateValidDummyReferenceConfigFD01();
    SCRConfLoadReferenceConfigFile(de_ctx, fd);

    if (de_ctx->reference_conf_ht == NULL)
        goto end;

    result = (de_ctx->reference_conf_ht->count == 3);
    if (result == 0)
        printf("FAILED: de_ctx->reference_conf_ht->count %u: ", de_ctx->reference_conf_ht->count);

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check that invalid references present in the reference.config file
 *       aren't loaded.
 */
static int SCRConfTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    int result = 0;

    if (de_ctx == NULL)
        return result;

    FILE *fd = SCRConfGenerateInValidDummyReferenceConfigFD03();
    SCRConfLoadReferenceConfigFile(de_ctx, fd);

    if (de_ctx->reference_conf_ht == NULL)
        goto end;

    result = (de_ctx->reference_conf_ht->count == 0);


 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check that only valid references are loaded into the hash table from
 *       the reference.config file.
 */
static int SCRConfTest03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    int result = 0;

    if (de_ctx == NULL)
        return result;

    FILE *fd = SCRConfGenerateInValidDummyReferenceConfigFD02();
    SCRConfLoadReferenceConfigFile(de_ctx, fd);

    if (de_ctx->reference_conf_ht == NULL)
        goto end;

    result = (de_ctx->reference_conf_ht->count == 1);

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check if the reference info from the reference.config file have
 *       been loaded into the hash table.
 */
static int SCRConfTest04(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    int result = 1;

    if (de_ctx == NULL)
        return 0;

    FILE *fd = SCRConfGenerateValidDummyReferenceConfigFD01();
    SCRConfLoadReferenceConfigFile(de_ctx, fd);

    if (de_ctx->reference_conf_ht == NULL)
        goto end;

    result = (de_ctx->reference_conf_ht->count == 3);

    result &= (SCRConfGetReference("one", de_ctx) != NULL);
    result &= (SCRConfGetReference("two", de_ctx) != NULL);
    result &= (SCRConfGetReference("three", de_ctx) != NULL);
    result &= (SCRConfGetReference("four", de_ctx) == NULL);

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check if the reference info from the invalid reference.config file
 *       have not been loaded into the hash table, and cross verify to check
 *       that the hash table contains no reference data.
 */
static int SCRConfTest05(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    int result = 1;

    if (de_ctx == NULL)
        return 0;

    FILE *fd = SCRConfGenerateInValidDummyReferenceConfigFD03();
    SCRConfLoadReferenceConfigFile(de_ctx, fd);

    if (de_ctx->reference_conf_ht == NULL)
        goto end;

    result = (de_ctx->reference_conf_ht->count == 0);

    result &= (SCRConfGetReference("one", de_ctx) == NULL);
    result &= (SCRConfGetReference("two", de_ctx) == NULL);
    result &= (SCRConfGetReference("three", de_ctx) == NULL);
    result &= (SCRConfGetReference("four", de_ctx) == NULL);
    result &= (SCRConfGetReference("five", de_ctx) == NULL);

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check if the reference info from the reference.config file have
 *       been loaded into the hash table.
 */
static int SCRConfTest06(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    int result = 1;

    if (de_ctx == NULL)
        return 0;

    FILE *fd = SCRConfGenerateInValidDummyReferenceConfigFD02();
    SCRConfLoadReferenceConfigFile(de_ctx, fd);

    if (de_ctx->reference_conf_ht == NULL)
        goto end;

    result = (de_ctx->reference_conf_ht->count == 1);

    result &= (SCRConfGetReference("one", de_ctx) != NULL);
    result &= (SCRConfGetReference("two", de_ctx) == NULL);
    result &= (SCRConfGetReference("three", de_ctx) == NULL);
    result &= (SCRConfGetReference("four", de_ctx) == NULL);
    result &= (SCRConfGetReference("five", de_ctx) == NULL);

 end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for Reference Config API.
 */
void SCRConfRegisterTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("SCRConfTest01", SCRConfTest01);
    UtRegisterTest("SCRConfTest02", SCRConfTest02);
    UtRegisterTest("SCRConfTest03", SCRConfTest03);
    UtRegisterTest("SCRConfTest04", SCRConfTest04);
    UtRegisterTest("SCRConfTest05", SCRConfTest05);
    UtRegisterTest("SCRConfTest06", SCRConfTest06);
#endif /* UNITTESTS */

    return;
}
