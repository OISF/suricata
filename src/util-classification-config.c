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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Used for parsing a classification.config file
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
#include "util-hash.h"

#include "conf.h"
#include "util-classification-config.h"
#include "util-unittest.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-fmemopen.h"
#include "util-byte.h"

/* Regex to parse the classtype argument from a Signature.  The first substring
 * holds the classtype name, the second substring holds the classtype the
 * classtype description, and the third argument holds the priority */
#define DETECT_CLASSCONFIG_REGEX "^\\s*config\\s*classification\\s*:\\s*([a-zA-Z][a-zA-Z0-9-_]*)\\s*,\\s*(.+)\\s*,\\s*(\\d+)\\s*$"

/* Default path for the classification.config file */
#if defined OS_WIN32 || defined __CYGWIN__
#define SC_CLASS_CONF_DEF_CONF_FILEPATH CONFIG_DIR "\\\\classification.config"
#else
#define SC_CLASS_CONF_DEF_CONF_FILEPATH CONFIG_DIR "/classification.config"
#endif

static pcre2_code *regex = NULL;
static pcre2_match_data *regex_match = NULL;

uint32_t SCClassConfClasstypeHashFunc(HashTable *ht, void *data, uint16_t datalen);
char SCClassConfClasstypeHashCompareFunc(void *data1, uint16_t datalen1,
                                         void *data2, uint16_t datalen2);
void SCClassConfClasstypeHashFree(void *ch);
static const char *SCClassConfGetConfFilename(const DetectEngineCtx *de_ctx);

static SCClassConfClasstype *SCClassConfAllocClasstype(uint16_t classtype_id,
        const char *classtype, const char *classtype_desc, int priority);
static void SCClassConfDeAllocClasstype(SCClassConfClasstype *ct);

void SCClassConfInit(void)
{
    int en;
    PCRE2_SIZE eo;
    int opts = 0;

    regex = pcre2_compile(
            (PCRE2_SPTR8)DETECT_CLASSCONFIG_REGEX, PCRE2_ZERO_TERMINATED, opts, &en, &eo, NULL);
    if (regex == NULL) {
        PCRE2_UCHAR errbuffer[256];
        pcre2_get_error_message(en, errbuffer, sizeof(errbuffer));
        SCLogWarning(SC_ERR_PCRE_COMPILE,
                "pcre2 compile of \"%s\" failed at "
                "offset %d: %s",
                DETECT_CLASSCONFIG_REGEX, (int)eo, errbuffer);
        return;
    }
    regex_match = pcre2_match_data_create_from_pattern(regex, NULL);
    return;
}

void SCClassConfDeinit(void)
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
 * \brief Inits the context to be used by the Classification Config parsing API.
 *
 *        This function initializes the hash table to be used by the Detection
 *        Engine Context to hold the data from the classification.config file,
 *        obtains the file desc to parse the classification.config file, and
 *        inits the regex used to parse the lines from classification.config
 *        file.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param fd Pointer to already opened file
 *
 * \note even if the file open fails we will keep the de_ctx->class_conf_ht
 *       initialized.
 *
 * \retval fp NULL on error
 */
static FILE *SCClassConfInitContextAndLocalResources(DetectEngineCtx *de_ctx, FILE *fd)
{
    /* init the hash table to be used by the classification config Classtypes */
    de_ctx->class_conf_ht = HashTableInit(128, SCClassConfClasstypeHashFunc,
                                          SCClassConfClasstypeHashCompareFunc,
                                          SCClassConfClasstypeHashFree);
    if (de_ctx->class_conf_ht == NULL) {
        SCLogError(SC_ERR_HASH_TABLE_INIT, "Error initializing the hash "
                   "table");
        return NULL;
    }

    /* if it is not NULL, use the file descriptor.  The hack so that we can
     * avoid using a dummy classification file for testing purposes and
     * instead use an input stream against a buffer containing the
     * classification strings */
    if (fd == NULL) {
        const char *filename = SCClassConfGetConfFilename(de_ctx);
        if ( (fd = fopen(filename, "r")) == NULL) {
#ifdef UNITTESTS
            if (RunmodeIsUnittests())
                return NULL; // silently fail
#endif
            SCLogWarning(SC_ERR_FOPEN, "could not open: \"%s\": %s",
                    filename, strerror(errno));
            return NULL;
        }
    }

    return fd;
}


/**
 * \brief Returns the path for the Classification Config file.  We check if we
 *        can retrieve the path from the yaml conf file.  If it is not present,
 *        return the default path for the classification file which is
 *        "./classification.config".
 *
 * \retval log_filename Pointer to a string containing the path for the
 *                      Classification Config file.
 */
static const char *SCClassConfGetConfFilename(const DetectEngineCtx *de_ctx)
{
    const char *log_filename = NULL;

    if (de_ctx != NULL && strlen(de_ctx->config_prefix) > 0) {
        char config_value[256];
        snprintf(config_value, sizeof(config_value),
                 "%s.classification-file", de_ctx->config_prefix);

        /* try loading prefix setting, fall back to global if that
         * fails. */
        if (ConfGet(config_value, &log_filename) != 1) {
            if (ConfGet("classification-file", &log_filename) != 1) {
                log_filename = (char *)SC_CLASS_CONF_DEF_CONF_FILEPATH;
            }
        }
    } else {
        if (ConfGet("classification-file", &log_filename) != 1) {
            log_filename = (char *)SC_CLASS_CONF_DEF_CONF_FILEPATH;
        }
    }

    return log_filename;
}

/**
 * \brief Releases resources used by the Classification Config API.
 */
static void SCClassConfDeInitLocalResources(DetectEngineCtx *de_ctx, FILE *fd)
{
    if (fd != NULL) {
        fclose(fd);
    }
}

/**
 * \brief Releases resources used by the Classification Config API.
 */
void SCClassConfDeInitContext(DetectEngineCtx *de_ctx)
{
    if (de_ctx->class_conf_ht != NULL)
        HashTableFree(de_ctx->class_conf_ht);

    de_ctx->class_conf_ht = NULL;

    return;
}

/**
 * \brief Converts a string to lowercase.
 *
 * \param str Pointer to the string to be converted.
 */
static char *SCClassConfStringToLowercase(const char *str)
{
    char *new_str = NULL;
    char *temp_str = NULL;

    if ( (new_str = SCStrdup(str)) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
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
 * \brief Parses a line from the classification file and adds it to Classtype
 *        hash table in DetectEngineCtx, i.e. DetectEngineCtx->class_conf_ht.
 *
 * \param rawstr Pointer to the string to be parsed.
 * \param index  Relative index of the string to be parsed.
 * \param de_ctx Pointer to the Detection Engine Context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCClassConfAddClasstype(DetectEngineCtx *de_ctx, char *rawstr, uint16_t index)
{
    char ct_name[CLASSTYPE_NAME_MAX_LEN];
    char ct_desc[CLASSTYPE_DESC_MAX_LEN];
    char ct_priority_str[16];
    uint32_t ct_priority = 0;
    uint16_t ct_id = index;

    SCClassConfClasstype *ct_new = NULL;
    SCClassConfClasstype *ct_lookup = NULL;

    int ret = 0;

    ret = pcre2_match(regex, (PCRE2_SPTR8)rawstr, strlen(rawstr), 0, 0, regex_match, NULL);
    if (ret < 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
                "Invalid Classtype in "
                "classification.config file %s: \"%s\"",
                SCClassConfGetConfFilename(de_ctx), rawstr);
        goto error;
    }

    size_t copylen = sizeof(ct_name);
    /* retrieve the classtype name */
    ret = pcre2_substring_copy_bynumber(regex_match, 1, (PCRE2_UCHAR8 *)ct_name, &copylen);
    if (ret < 0) {
        SCLogInfo("pcre2_substring_copy_bynumber() failed");
        goto error;
    }

    /* retrieve the classtype description */
    copylen = sizeof(ct_desc);
    ret = pcre2_substring_copy_bynumber(regex_match, 2, (PCRE2_UCHAR8 *)ct_desc, &copylen);
    if (ret < 0) {
        SCLogInfo("pcre2_substring_copy_bynumber() failed");
        goto error;
    }

    /* retrieve the classtype priority */
    copylen = sizeof(ct_priority_str);
    ret = pcre2_substring_copy_bynumber(regex_match, 3, (PCRE2_UCHAR8 *)ct_priority_str, &copylen);
    if (ret < 0) {
        SCLogInfo("pcre2_substring_copy_bynumber() failed");
        goto error;
    }
    if (StringParseUint32(&ct_priority, 10, 0, (const char *)ct_priority_str) < 0) {
        goto error;
    }

    /* Create a new instance of the parsed Classtype string */
    ct_new = SCClassConfAllocClasstype(ct_id, ct_name, ct_desc, ct_priority);
    if (ct_new == NULL)
        goto error;

    /* Check if the Classtype is present in the HashTable.  In case it's present
     * ignore it, as it is a duplicate.  If not present, add it to the table */
    ct_lookup = HashTableLookup(de_ctx->class_conf_ht, ct_new, 0);
    if (ct_lookup == NULL) {
        if (HashTableAdd(de_ctx->class_conf_ht, ct_new, 0) < 0)
            SCLogDebug("HashTable Add failed");
    } else {
        SCLogDebug("Duplicate classtype found inside classification.config");
        if (ct_new->classtype_desc) SCFree(ct_new->classtype_desc);
        if (ct_new->classtype) SCFree(ct_new->classtype);
        SCFree(ct_new);
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
 * \param line String that has to be checked
 *
 * \retval 1 On the argument string being a comment or blank line
 * \retval 0 Otherwise
 */
static int SCClassConfIsLineBlankOrComment(char *line)
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
 * \brief Parses the Classification Config file and updates the
 *        DetectionEngineCtx->class_conf_ht with the Classtype information.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 */
static bool SCClassConfParseFile(DetectEngineCtx *de_ctx, FILE *fd)
{
    char line[1024];
    uint16_t i = 1;

    while (fgets(line, sizeof(line), fd) != NULL) {
        if (SCClassConfIsLineBlankOrComment(line))
            continue;

        if (SCClassConfAddClasstype(de_ctx, line, i) == -1) {
            return false;
        }
        i++;
    }

#ifdef UNITTESTS
    SCLogInfo("Added \"%d\" classification types from the classification file",
              de_ctx->class_conf_ht->count);
#endif

    return true;
}

/**
 * \internal
 * \brief Returns a new SCClassConfClasstype instance.  The classtype string
 *        is converted into lowercase, before being assigned to the instance.
 *
 * \param classtype      Pointer to the classification type.
 * \param classtype_desc Pointer to the classification type description.
 * \param priority       Holds the priority for the classification type.
 *
 * \retval ct Pointer to the new instance of SCClassConfClasstype on success;
 *            NULL on failure.
 */
static SCClassConfClasstype *SCClassConfAllocClasstype(uint16_t classtype_id,
                                                const char *classtype,
                                                const char *classtype_desc,
                                                int priority)
{
    SCClassConfClasstype *ct = NULL;

    if (classtype == NULL)
        return NULL;

    if ( (ct = SCMalloc(sizeof(SCClassConfClasstype))) == NULL)
        return NULL;
    memset(ct, 0, sizeof(SCClassConfClasstype));

    if ((ct->classtype = SCClassConfStringToLowercase(classtype)) == NULL) {
        SCClassConfDeAllocClasstype(ct);
        return NULL;
    }

    if (classtype_desc != NULL &&
        (ct->classtype_desc = SCStrdup(classtype_desc)) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");

        SCClassConfDeAllocClasstype(ct);
        return NULL;
    }

    ct->classtype_id = classtype_id;
    ct->priority = priority;

    return ct;
}

/**
 * \internal
 * \brief Frees a SCClassConfClasstype instance
 *
 * \param Pointer to the SCClassConfClasstype instance that has to be freed
 */
static void SCClassConfDeAllocClasstype(SCClassConfClasstype *ct)
{
    if (ct != NULL) {
        if (ct->classtype != NULL)
            SCFree(ct->classtype);

        if (ct->classtype_desc != NULL)
            SCFree(ct->classtype_desc);

        SCFree(ct);
    }

    return;
}

/**
 * \brief Hashing function to be used to hash the Classtype name.  Would be
 *        supplied as an argument to the HashTableInit function for
 *        DetectEngineCtx->class_conf_ht.
 *
 * \param ht      Pointer to the HashTable.
 * \param data    Pointer to the data to be hashed.  In this case, the data
 *                would be a pointer to a SCClassConfClasstype instance.
 * \param datalen Not used by this function.
 */
uint32_t SCClassConfClasstypeHashFunc(HashTable *ht, void *data, uint16_t datalen)
{
    SCClassConfClasstype *ct = (SCClassConfClasstype *)data;
    uint32_t hash = 0;
    int i = 0;

    int len = strlen(ct->classtype);

    for (i = 0; i < len; i++)
        hash += u8_tolower((unsigned char)(ct->classtype)[i]);

    hash = hash % ht->array_size;

    return hash;
}

/**
 * \brief Used to compare two Classtypes that have been stored in the HashTable.
 *        This function is supplied as an argument to the HashTableInit function
 *        for DetectionEngineCtx->class_conf_ct.
 *
 * \param data1 Pointer to the first SCClassConfClasstype to be compared.
 * \param len1  Not used by this function.
 * \param data2 Pointer to the second SCClassConfClasstype to be compared.
 * \param len2  Not used by this function.
 *
 * \retval 1 On data1 and data2 being equal.
 * \retval 0 On data1 and data2 not being equal.
 */
char SCClassConfClasstypeHashCompareFunc(void *data1, uint16_t datalen1,
                                         void *data2, uint16_t datalen2)
{
    SCClassConfClasstype *ct1 = (SCClassConfClasstype *)data1;
    SCClassConfClasstype *ct2 = (SCClassConfClasstype *)data2;
    int len1 = 0;
    int len2 = 0;

    if (ct1 == NULL || ct2 == NULL)
        return 0;

    if (ct1->classtype == NULL || ct2->classtype == NULL)
        return 0;

    len1 = strlen(ct1->classtype);
    len2 = strlen(ct2->classtype);

    if (len1 == len2 && memcmp(ct1->classtype, ct2->classtype, len1) == 0) {
        SCLogDebug("Match found inside Classification-Config hash function");
        return 1;
    }

    return 0;
}

/**
 * \brief Used to free the Classification Config Hash Data that was stored in
 *        DetectEngineCtx->class_conf_ht Hashtable.
 *
 * \param ch Pointer to the data that has to be freed.
 */
void SCClassConfClasstypeHashFree(void *ch)
{
    SCClassConfDeAllocClasstype(ch);

    return;
}

/**
 * \brief Loads the Classtype info from the classification.config file.
 *
 *        The classification.config file contains the different classtypes,
 *        that can be used to label Signatures.  Each line of the file should
 *        have the following format -
 *        classtype_name, classtype_description, priority
 *        None of the above parameters should hold a quote inside the file.
 *
 * \param de_ctx Pointer to the Detection Engine Context that should be updated
 *               with Classtype information.
 */
bool SCClassConfLoadClassficationConfigFile(DetectEngineCtx *de_ctx, FILE *fd)
{
    fd = SCClassConfInitContextAndLocalResources(de_ctx, fd);
    if (fd == NULL) {
#ifdef UNITTESTS
        if (RunmodeIsUnittests()) {
            return false;
        }
#endif
        SCLogError(SC_ERR_OPENING_FILE, "please check the \"classification-file\" "
                "option in your suricata.yaml file");
        return false;
    }

    bool ret = true;
    if (!SCClassConfParseFile(de_ctx, fd)) {
        SCLogWarning(SC_WARN_CLASSIFICATION_CONFIG,
                "Error loading classification configuration from %s",
                SCClassConfGetConfFilename(de_ctx));
        ret = false;
    }

    SCClassConfDeInitLocalResources(de_ctx, fd);

    return ret;
}

/**
 * \brief Gets the classtype from the corresponding hash table stored
 *        in the Detection Engine Context's class conf ht, given the
 *        classtype name.
 *
 * \param ct_name Pointer to the classtype name that has to be looked up.
 * \param de_ctx  Pointer to the Detection Engine Context.
 *
 * \retval lookup_ct_info Pointer to the SCClassConfClasstype instance from
 *                        the hash table on success; NULL on failure.
 */
SCClassConfClasstype *SCClassConfGetClasstype(const char *ct_name,
                                              DetectEngineCtx *de_ctx)
{
    char name[strlen(ct_name) + 1];
    size_t s;
    for (s = 0; s < strlen(ct_name); s++)
        name[s] = u8_tolower((unsigned char)ct_name[s]);
    name[s] = '\0';

    SCClassConfClasstype ct_lookup = {0, 0, name, NULL };
    SCClassConfClasstype *lookup_ct_info = HashTableLookup(de_ctx->class_conf_ht,
                                                           &ct_lookup, 0);
    return lookup_ct_info;
}

/*----------------------------------Unittests---------------------------------*/


#ifdef UNITTESTS

/**
 * \brief Creates a dummy classification file, with all valid Classtypes, for
 *        testing purposes.
 *
 * \file_path Pointer to the file_path for the dummy classification file.
 */
FILE *SCClassConfGenerateValidDummyClassConfigFD01(void)
{
    const char *buffer =
        "config classification: nothing-wrong,Nothing Wrong With Us,3\n"
        "config classification: unknown,Unknown are we,3\n"
        "config classification: bad-unknown,We think it's bad, 2\n";

    FILE *fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Classifiation Config test code");

    return fd;
}

/**
 * \brief Creates a dummy classification file, with some valid Classtypes and a
 *        couple of invalid Classtypes, for testing purposes.
 *
 * \file_path Pointer to the file_path for the dummy classification file.
 */
FILE *SCClassConfGenerateInValidDummyClassConfigFD02(void)
{
    const char *buffer =
        "config classification: not-suspicious,Not Suspicious Traffic,3\n"
        "onfig classification: unknown,Unknown Traffic,3\n"
        "config classification: _badunknown,Potentially Bad Traffic, 2\n"
        "config classification: bamboola1,Unknown Traffic,3\n"
        "config classification: misc-activity,Misc activity,-1\n"
        "config classification: policy-violation,Potential Corporate "
        "config classification: bamboola,Unknown Traffic,3\n";

    FILE *fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Classifiation Config test code");

    return fd;
}

/**
 * \brief Creates a dummy classification file, with all invalid Classtypes, for
 *        testing purposes.
 *
 * \file_path Pointer to the file_path for the dummy classification file.
 */
FILE *SCClassConfGenerateInValidDummyClassConfigFD03(void)
{
    const char *buffer =
        "conig classification: not-suspicious,Not Suspicious Traffic,3\n"
        "onfig classification: unknown,Unknown Traffic,3\n"
        "config classification: _badunknown,Potentially Bad Traffic, 2\n"
        "config classification: misc-activity,Misc activity,-1\n";

    FILE *fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Classifiation Config test code");

    return fd;
}

/**
 * \test Check that the classification file is loaded and the detection engine
 *       content class_conf_hash_table loaded with the classtype data.
 */
static int SCClassConfTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    int result = 0;

    if (de_ctx == NULL)
        return result;

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    if (de_ctx->class_conf_ht == NULL)
        return result;

    result = (de_ctx->class_conf_ht->count == 3);
    if (result == 0) printf("de_ctx->class_conf_ht->count %u: ", de_ctx->class_conf_ht->count);

    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Check that invalid classtypes present in the classification config file
 *       aren't loaded.
 */
static int SCClassConfTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    int result = 0;

    if (de_ctx == NULL)
        return result;

    FILE *fd = SCClassConfGenerateInValidDummyClassConfigFD03();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    if (de_ctx->class_conf_ht == NULL)
        return result;

    result = (de_ctx->class_conf_ht->count == 0);

    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Check that only valid classtypes are loaded into the hash table from
 *       the classfication.config file.
 */
static int SCClassConfTest03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    FAIL_IF_NULL(de_ctx);

    FILE *fd = SCClassConfGenerateInValidDummyClassConfigFD02();
    FAIL_IF(SCClassConfLoadClassficationConfigFile(de_ctx, fd));

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test Check if the classtype info from the classification.config file have
 *       been loaded into the hash table.
 */
static int SCClassConfTest04(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    int result = 1;

    if (de_ctx == NULL)
        return 0;

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    if (de_ctx->class_conf_ht == NULL)
        return 0;

    result = (de_ctx->class_conf_ht->count == 3);

    result &= (SCClassConfGetClasstype("unknown", de_ctx) != NULL);
    result &= (SCClassConfGetClasstype("unKnoWn", de_ctx) != NULL);
    result &= (SCClassConfGetClasstype("bamboo", de_ctx) == NULL);
    result &= (SCClassConfGetClasstype("bad-unknown", de_ctx) != NULL);
    result &= (SCClassConfGetClasstype("BAD-UNKnOWN", de_ctx) != NULL);
    result &= (SCClassConfGetClasstype("bed-unknown", de_ctx) == NULL);

    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Check if the classtype info from the invalid classification.config file
 *       have not been loaded into the hash table, and cross verify to check
 *       that the hash table contains no classtype data.
 */
static int SCClassConfTest05(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    int result = 1;

    if (de_ctx == NULL)
        return 0;

    FILE *fd = SCClassConfGenerateInValidDummyClassConfigFD03();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    if (de_ctx->class_conf_ht == NULL)
        return 0;

    result = (de_ctx->class_conf_ht->count == 0);

    result &= (SCClassConfGetClasstype("unknown", de_ctx) == NULL);
    result &= (SCClassConfGetClasstype("unKnoWn", de_ctx) == NULL);
    result &= (SCClassConfGetClasstype("bamboo", de_ctx) == NULL);
    result &= (SCClassConfGetClasstype("bad-unknown", de_ctx) == NULL);
    result &= (SCClassConfGetClasstype("BAD-UNKnOWN", de_ctx) == NULL);
    result &= (SCClassConfGetClasstype("bed-unknown", de_ctx) == NULL);

    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \brief This function registers unit tests for Classification Config API.
 */
void SCClassConfRegisterTests(void)
{
    UtRegisterTest("SCClassConfTest01", SCClassConfTest01);
    UtRegisterTest("SCClassConfTest02", SCClassConfTest02);
    UtRegisterTest("SCClassConfTest03", SCClassConfTest03);
    UtRegisterTest("SCClassConfTest04", SCClassConfTest04);
    UtRegisterTest("SCClassConfTest05", SCClassConfTest05);
}
#endif /* UNITTESTS */
