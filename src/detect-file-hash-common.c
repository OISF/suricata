/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 * \author Duarte Silva <duarte.silva@serializing.me>
 *
 */

#include "suricata-common.h"

#include "detect-parse.h"

#include "detect-file-hash-common.h"

/**
 * \brief Read the bytes of a hash from an hexadecimal string
 *
 * \param hash buffer to store the resulting bytes
 * \param string hexadecimal string representing the hash
 * \param filename file name from where the string was read
 * \param line_no file line number from where the string was read
 * \param expected_len the expected length of the string that was read
 *
 * \retval -1 the hexadecimal string is invalid
 * \retval 1 the hexadecimal string was read successfully
 */
int ReadHashString(uint8_t *hash, const char *string, const char *filename, int line_no,
        uint16_t expected_len)
{
    if (strlen(string) != expected_len) {
        SCLogError(SC_ERR_INVALID_HASH, "%s:%d hash string not %d characters",
                filename, line_no, expected_len);
        return -1;
    }

    int i, x;
    for (x = 0, i = 0; i < expected_len; i+=2, x++) {
        char buf[3] = { 0, 0, 0 };
        buf[0] = string[i];
        buf[1] = string[i+1];

        long value = strtol(buf, NULL, 16);
        if (value >= 0 && value <= 255)
            hash[x] = (uint8_t)value;
        else {
            SCLogError(SC_ERR_INVALID_HASH, "%s:%d hash byte out of range %ld",
                    filename, line_no, value);
            return -1;
        }
    }

    return 1;
}

/**
 * \brief Store a hash into the hash table
 *
 * \param hash_table hash table that will hold the hash
 * \param string hexadecimal string representing the hash
 * \param filename file name from where the string was read
 * \param line_no file line number from where the string was read
 * \param type the hash algorithm
 *
 * \retval -1 failed to load the hash into the hash table
 * \retval 1 successfully loaded the has into the hash table
 */
int LoadHashTable(ROHashTable *hash_table, const char *string, const char *filename,
        int line_no, uint32_t type)
{
    /* allocate the maximum size a hash can have (in this case is SHA256, 32 bytes) */
    uint8_t hash[32];
    /* specify the actual size that should be read depending on the hash algorithm */
    uint16_t size = 32;

    if (type == DETECT_FILEMD5) {
        size = 16;
    }
    else if (type == DETECT_FILESHA1) {
        size = 20;
    }

    /* every byte represented with hexadecimal digits is two characters */
    uint16_t expected_len = (size * 2);

    if (ReadHashString(hash, string, filename, line_no, expected_len) == 1) {
        if (ROHashInitQueueValue(hash_table, &hash, size) != 1)
            return -1;
    }

    return 1;
}

/**
 * \brief Match a hash stored in a hash table
 *
 * \param hash_table hash table that will hold the hash
 * \param hash buffer containing the bytes of the has
 * \param hash_len length of the hash buffer
 *
 * \retval 0 didn't find the specified hash
 * \retval 1 the hash matched a stored value
 */
static int HashMatchHashTable(ROHashTable *hash_table, uint8_t *hash,
        size_t hash_len)
{
    void *ptr = ROHashLookup(hash_table, hash, (uint16_t)hash_len);
    if (ptr == NULL)
        return 0;
    else
        return 1;
}

/**
 * \brief Match the specified file hash
 *
 * \param det_ctx pattern matcher thread local data
 * \param f *LOCKED* flow
 * \param flags direction flags
 * \param file file being inspected
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectFileHashData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectFileHashMatch (DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, File *file, const Signature *s, const SigMatchCtx *m)
{
    SCEnter();
    int ret = 0;
    DetectFileHashData *filehash = (DetectFileHashData *)m;

    if (file->state != FILE_STATE_CLOSED) {
        SCReturnInt(0);
    }

    int match = -1;

    if (s->file_flags & FILE_SIG_NEED_MD5 && file->flags & FILE_MD5) {
        match = HashMatchHashTable(filehash->hash, file->md5, sizeof(file->md5));
    }
    else if (s->file_flags & FILE_SIG_NEED_SHA1 && file->flags & FILE_SHA1) {
        match = HashMatchHashTable(filehash->hash, file->sha1, sizeof(file->sha1));
    }
    else if (s->file_flags & FILE_SIG_NEED_SHA256 && file->flags & FILE_SHA256) {
        match = HashMatchHashTable(filehash->hash, file->sha256, sizeof(file->sha256));
    }

    if (match == 1) {
        if (filehash->negated == 0)
            ret = 1;
        else
            ret = 0;
    }
    else if (match == 0) {
        if (filehash->negated == 0)
            ret = 0;
        else
            ret = 1;
    }

    SCReturnInt(ret);
}

static const char *hexcodes = "ABCDEFabcdef0123456789";

/**
 * \brief Parse the filemd5, filesha1 or filesha256 keyword
 *
 * \param det_ctx pattern matcher thread local data
 * \param str Pointer to the user provided option
 * \param type the hash algorithm
 *
 * \retval hash pointer to DetectFileHashData on success
 * \retval NULL on failure
 */
static DetectFileHashData *DetectFileHashParse (const DetectEngineCtx *de_ctx,
        const char *str, uint32_t type)
{
    DetectFileHashData *filehash = NULL;
    FILE *fp = NULL;
    char *filename = NULL;
    char *rule_filename = NULL;

    /* We have a correct hash algorithm option */
    filehash = SCMalloc(sizeof(DetectFileHashData));
    if (unlikely(filehash == NULL))
        goto error;

    memset(filehash, 0x00, sizeof(DetectFileHashData));

    if (strlen(str) && str[0] == '!') {
        filehash->negated = 1;
        str++;
    }

    if (type == DETECT_FILEMD5) {
        filehash->hash = ROHashInit(18, 16);
    }
    else if (type == DETECT_FILESHA1) {
        filehash->hash = ROHashInit(18, 20);
    }
    else if (type == DETECT_FILESHA256) {
        filehash->hash = ROHashInit(18, 32);
    }

    if (filehash->hash == NULL) {
        goto error;
    }

    /* get full filename */
    filename = DetectLoadCompleteSigPath(de_ctx, str);
    if (filename == NULL) {
        goto error;
    }

    rule_filename = SCStrdup(de_ctx->rule_file);
    if (rule_filename == NULL) {
        goto error;
    }

    char line[8192] = "";
    fp = fopen(filename, "r");
    if (fp == NULL) {
#ifdef HAVE_LIBGEN_H
        if (de_ctx->rule_file != NULL) {
            char *dir = dirname(rule_filename);
            if (dir != NULL) {
                char path[PATH_MAX];
                snprintf(path, sizeof(path), "%s/%s", dir, str);
                fp = fopen(path, "r");
                if (fp == NULL) {
                    SCLogError(SC_ERR_OPENING_RULE_FILE,
                            "opening hash file %s: %s", path, strerror(errno));
                    goto error;
                }
            }
        }
        if (fp == NULL) {
#endif
            SCLogError(SC_ERR_OPENING_RULE_FILE, "opening hash file %s: %s", filename, strerror(errno));
            goto error;
#ifdef HAVE_LIBGEN_H
        }
#endif
    }

    int line_no = 0;
    while(fgets(line, (int)sizeof(line), fp) != NULL) {
        size_t valid = 0, len = strlen(line);
        line_no++;

        while (strchr(hexcodes, line[valid]) != NULL && valid++ < len);

        /* lines that do not contain sequentially any valid character are ignored */
        if (valid == 0)
            continue;

        /* ignore anything after the sequence of valid characters */
        line[valid] = '\0';

        if (LoadHashTable(filehash->hash, line, filename, line_no, type) != 1) {
            goto error;
        }
    }
    fclose(fp);
    fp = NULL;

    if (ROHashInitFinalize(filehash->hash) != 1) {
        goto error;
    }
    SCLogInfo("Hash hash table size %u bytes%s", ROHashMemorySize(filehash->hash), filehash->negated ? ", negated match" : "");

    SCFree(rule_filename);
    SCFree(filename);
    return filehash;

error:
    if (filehash != NULL)
        DetectFileHashFree((DetectEngineCtx *) de_ctx, filehash);
    if (fp != NULL)
        fclose(fp);
    if (filename != NULL)
        SCFree(filename);
    if (rule_filename != NULL) {
        SCFree(rule_filename);
    }
    return NULL;
}

/**
 * \brief this function is used to parse filemd5, filesha1 and filesha256 options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "filemd5", "filesha1" or "filesha256" option
 * \param type type of file hash to setup
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectFileHashSetup(
        DetectEngineCtx *de_ctx, Signature *s, const char *str, uint16_t type, int list)
{
    DetectFileHashData *filehash = NULL;
    SigMatch *sm = NULL;

    filehash = DetectFileHashParse(de_ctx, str, type);
    if (filehash == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = type;
    sm->ctx = (void *)filehash;

    SigMatchAppendSMToList(s, sm, list);

    s->file_flags |= FILE_SIG_NEED_FILE;

    // Setup the file flags depending on the hashing algorithm
    if (type == DETECT_FILEMD5) {
        s->file_flags |= FILE_SIG_NEED_MD5;
    }
    if (type == DETECT_FILESHA1) {
        s->file_flags |= FILE_SIG_NEED_SHA1;
    }
    if (type == DETECT_FILESHA256) {
        s->file_flags |= FILE_SIG_NEED_SHA256;
    }
    return 0;

error:
    if (filehash != NULL)
        DetectFileHashFree(de_ctx, filehash);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectFileHashData
 *
 * \param filehash pointer to DetectFileHashData
 */
void DetectFileHashFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL) {
        DetectFileHashData *filehash = (DetectFileHashData *)ptr;
        if (filehash->hash != NULL)
            ROHashFree(filehash->hash);
        SCFree(filehash);
    }
}
