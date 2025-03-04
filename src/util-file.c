/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "flow.h"
#include "stream.h"
#include "stream-tcp.h"
#include "runmodes.h"
#include "util-hash.h"
#include "util-debug.h"
#include "util-memcmp.h"
#include "util-print.h"
#include "app-layer-parser.h"
#include "util-validate.h"
#include "rust.h"

extern int g_detect_disabled;

/** \brief mask of file flags we'll not set
 *  This mask is set based on global file settings and
 *  cannot be overridden by detection.
 */
static uint16_t g_file_flow_mask = 0;

/** \brief switch to force filestore on all files
 *         regardless of the rules.
 */
static int g_file_force_filestore = 0;

/** \brief switch to force magic checks on all files
 *         regardless of the rules.
 */
static int g_file_force_magic = 0;

/** \brief switch to force md5 calculation on all files
 *         regardless of the rules.
 */
static int g_file_force_md5 = 0;

/** \brief switch to force sha1 calculation on all files
 *         regardless of the rules.
 */
static int g_file_force_sha1 = 0;

/** \brief switch to force sha256 calculation on all files
 *         regardless of the rules.
 */
static int g_file_force_sha256 = 0;

/** \brief switch to force tracking off all files
 *         regardless of the rules.
 */
static int g_file_force_tracking = 0;

/** \brief switch to use g_file_store_reassembly_depth
 *         to reassembly files
 */
static int g_file_store_enable = 0;

/** \brief stream_config.reassembly_depth equivalent
 *         for files
 */
static uint32_t g_file_store_reassembly_depth = 0;

/* prototypes */
static void FileFree(File *, const StreamingBufferConfig *cfg);
static void FileEndSha256(File *ff);

void FileForceFilestoreEnable(void)
{
    g_file_force_filestore = 1;
    g_file_flow_mask |= (FLOWFILE_NO_STORE_TS|FLOWFILE_NO_STORE_TC);
}

void FileForceMagicEnable(void)
{
    g_file_force_magic = 1;
    g_file_flow_mask |= (FLOWFILE_NO_MAGIC_TS|FLOWFILE_NO_MAGIC_TC);
}

void FileForceMd5Enable(void)
{
    g_file_force_md5 = 1;
    g_file_flow_mask |= (FLOWFILE_NO_MD5_TS|FLOWFILE_NO_MD5_TC);
}

void FileForceSha1Enable(void)
{
    g_file_force_sha1 = 1;
    g_file_flow_mask |= (FLOWFILE_NO_SHA1_TS|FLOWFILE_NO_SHA1_TC);
}

void FileForceSha256Enable(void)
{
    g_file_force_sha256 = 1;
    g_file_flow_mask |= (FLOWFILE_NO_SHA256_TS|FLOWFILE_NO_SHA256_TC);
}

int FileForceFilestore(void)
{
    return g_file_force_filestore;
}

void FileReassemblyDepthEnable(uint32_t size)
{
    g_file_store_enable = 1;
    g_file_store_reassembly_depth = size;
}

uint32_t FileReassemblyDepth(void)
{
    if (g_file_store_enable == 1)
        return g_file_store_reassembly_depth;
    else
        return stream_config.reassembly_depth;
}

int FileForceMagic(void)
{
    return g_file_force_magic;
}

int FileForceMd5(void)
{
    return g_file_force_md5;
}

int FileForceSha1(void)
{
    return g_file_force_sha1;
}

int FileForceSha256(void)
{
    return g_file_force_sha256;
}

void FileForceTrackingEnable(void)
{
    g_file_force_tracking = 1;
    g_file_flow_mask |= (FLOWFILE_NO_SIZE_TS|FLOWFILE_NO_SIZE_TC);
}

/**
 * \brief Function to parse forced file hashing configuration.
 */
void FileForceHashParseCfg(ConfNode *conf)
{
    BUG_ON(conf == NULL);

    ConfNode *forcehash_node = NULL;

    /* legacy option */
    const char *force_md5 = ConfNodeLookupChildValue(conf, "force-md5");
    if (force_md5 != NULL) {
        SCLogWarning("deprecated 'force-md5' option "
                     "found. Please use 'force-hash: [md5]' instead");

        if (ConfValIsTrue(force_md5)) {
            if (g_disable_hashing) {
                SCLogInfo(
                        "not forcing md5 calculation for logged files: hashing globally disabled");
            } else {
                FileForceMd5Enable();
                SCLogInfo("forcing md5 calculation for logged files");
            }
        }
    }

    if (conf != NULL)
        forcehash_node = ConfNodeLookupChild(conf, "force-hash");

    if (forcehash_node != NULL) {
        ConfNode *field = NULL;

        TAILQ_FOREACH(field, &forcehash_node->head, next) {
            if (strcasecmp("md5", field->val) == 0) {
                if (g_disable_hashing) {
                    SCLogInfo("not forcing md5 calculation for logged files: hashing globally "
                              "disabled");
                } else {
                    FileForceMd5Enable();
                    SCLogConfig("forcing md5 calculation for logged or stored files");
                }
            }

            if (strcasecmp("sha1", field->val) == 0) {
                if (g_disable_hashing) {
                    SCLogInfo("not forcing sha1 calculation for logged files: hashing globally "
                              "disabled");
                } else {
                    FileForceSha1Enable();
                    SCLogConfig("forcing sha1 calculation for logged or stored files");
                }
            }

            if (strcasecmp("sha256", field->val) == 0) {
                if (g_disable_hashing) {
                    SCLogInfo("not forcing sha256 calculation for logged files: hashing globally "
                              "disabled");
                } else {
                    FileForceSha256Enable();
                    SCLogConfig("forcing sha256 calculation for logged or stored files");
                }
            }
        }
    }
}

uint16_t FileFlowFlagsToFlags(const uint16_t flow_file_flags, uint8_t direction)
{
    uint16_t flags = 0;

    if (direction == STREAM_TOSERVER) {
        if ((flow_file_flags & (FLOWFILE_NO_STORE_TS | FLOWFILE_STORE_TS)) ==
                FLOWFILE_NO_STORE_TS) {
            flags |= FILE_NOSTORE;
        } else if (flow_file_flags & FLOWFILE_STORE_TS) {
            flags |= FILE_STORE;
        }

        if (flow_file_flags & FLOWFILE_NO_MAGIC_TS) {
            flags |= FILE_NOMAGIC;
        }

        if (flow_file_flags & FLOWFILE_NO_MD5_TS) {
            flags |= FILE_NOMD5;
        }

        if (flow_file_flags & FLOWFILE_NO_SHA1_TS) {
            flags |= FILE_NOSHA1;
        }

        if (flow_file_flags & FLOWFILE_NO_SHA256_TS) {
            flags |= FILE_NOSHA256;
        }
    } else {
        if ((flow_file_flags & (FLOWFILE_NO_STORE_TC | FLOWFILE_STORE_TC)) ==
                FLOWFILE_NO_STORE_TC) {
            flags |= FILE_NOSTORE;
        } else if (flow_file_flags & FLOWFILE_STORE_TC) {
            flags |= FILE_STORE;
        }

        if (flow_file_flags & FLOWFILE_NO_MAGIC_TC) {
            flags |= FILE_NOMAGIC;
        }

        if (flow_file_flags & FLOWFILE_NO_MD5_TC) {
            flags |= FILE_NOMD5;
        }

        if (flow_file_flags & FLOWFILE_NO_SHA1_TC) {
            flags |= FILE_NOSHA1;
        }

        if (flow_file_flags & FLOWFILE_NO_SHA256_TC) {
            flags |= FILE_NOSHA256;
        }
    }
    DEBUG_VALIDATE_BUG_ON((flags & (FILE_STORE | FILE_NOSTORE)) == (FILE_STORE | FILE_NOSTORE));

    SCLogDebug("direction %02x flags %02x", direction, flags);
    return flags;
}

uint16_t FileFlowToFlags(const Flow *flow, uint8_t direction)
{
    return FileFlowFlagsToFlags(flow->file_flags, direction);
}

void FileApplyTxFlags(const AppLayerTxData *txd, const uint8_t direction, File *file)
{
    SCLogDebug("file flags %04x STORE %s NOSTORE %s", file->flags,
            (file->flags & FILE_STORE) ? "true" : "false",
            (file->flags & FILE_NOSTORE) ? "true" : "false");
    uint16_t update_flags = FileFlowFlagsToFlags(txd->file_flags, direction);
    DEBUG_VALIDATE_BUG_ON(
            (file->flags & (FILE_STORE | FILE_NOSTORE)) == (FILE_STORE | FILE_NOSTORE));
    if (file->flags & FILE_STORE)
        update_flags &= ~FILE_NOSTORE;

    file->flags |= update_flags;
    SCLogDebug("file flags %04x STORE %s NOSTORE %s", file->flags,
            (file->flags & FILE_STORE) ? "true" : "false",
            (file->flags & FILE_NOSTORE) ? "true" : "false");
    DEBUG_VALIDATE_BUG_ON(
            (file->flags & (FILE_STORE | FILE_NOSTORE)) == (FILE_STORE | FILE_NOSTORE));
}

static int FileMagicSize(void)
{
    /** \todo make this size configurable */
    return 512;
}

/**
 *  \brief get the size of the file data
 *
 *  This doesn't reflect how much of the file we have in memory, just the
 *  total size of filedata so far.
 */
uint64_t FileDataSize(const File *file)
{
    if (file != NULL && file->sb != NULL) {
        const uint64_t size = StreamingBufferGetConsecutiveDataRightEdge(file->sb);
        SCLogDebug("returning %" PRIu64, size);
        return size;
    }
    SCLogDebug("returning 0 (default)");
    return 0;
}

/**
 *  \brief get the size of the file
 *
 *  This doesn't reflect how much of the file we have in memory, just the
 *  total size of file so far.
 */
uint64_t FileTrackedSize(const File *file)
{
    if (file != NULL) {
        return file->size;
    }
    return 0;
}

/** \brief test if file is ready to be pruned
 *
 *  If a file is in the 'CLOSED' state, it means it has been processed
 *  completely by the pipeline in the correct direction. So we can
 *  prune it then.
 *
 *  For other states, as well as for files we may not need to track
 *  until the close state, more specific checks are done.
 *
 *  Also does house keeping within the file: move streaming buffer
 *  forward if possible.
 *
 *  \retval 1 prune (free) this file
 *  \retval 0 file not ready to be freed
 */
static int FilePruneFile(File *file, const StreamingBufferConfig *cfg)
{
    SCEnter();

    /* file is done when state is closed+, logging/storing is done (if any) */
    SCLogDebug("file->state %d. Is >= FILE_STATE_CLOSED: %s",
            file->state, (file->state >= FILE_STATE_CLOSED) ? "yes" : "no");
    if (file->state >= FILE_STATE_CLOSED) {
        SCReturnInt(1);
    }

#ifdef HAVE_MAGIC
    if (!(file->flags & FILE_NOMAGIC)) {
        /* need magic but haven't set it yet, bail out */
        if (file->magic == NULL)
            SCReturnInt(0);
        else
            SCLogDebug("file->magic %s", file->magic);
    } else {
        SCLogDebug("file->flags & FILE_NOMAGIC == true");
    }
#endif
    uint64_t left_edge = FileDataSize(file);
    if (file->flags & FILE_STORE) {
        left_edge = MIN(left_edge,file->content_stored);
    }

    if (!g_detect_disabled) {
        left_edge = MIN(left_edge, file->content_inspected);
        /* if file has inspect window and min size set, we
         * do some house keeping here */
        if (file->inspect_window != 0 && file->inspect_min_size != 0) {
            const uint64_t file_offset = StreamingBufferGetOffset(file->sb);
            uint32_t window = file->inspect_window;
            if (file_offset == 0)
                window = MAX(window, file->inspect_min_size);

            uint64_t file_size = FileDataSize(file);
            uint64_t data_size = file_size - file_offset;

            SCLogDebug("window %"PRIu32", file_size %"PRIu64", data_size %"PRIu64,
                    window, file_size, data_size);

            if (data_size > (window * 3)) {
                file->content_inspected = MAX(file->content_inspected, file->size - window);
                SCLogDebug("file->content_inspected now %" PRIu64, file->content_inspected);
            }

            if (left_edge > window)
                left_edge -= window;
            else
                left_edge = 0;
        }
    }

    if (left_edge) {
        SCLogDebug("sliding to %" PRIu64, left_edge);
        StreamingBufferSlideToOffset(file->sb, cfg, left_edge);
    }

    SCReturnInt(0);
}

#ifdef DEBUG
#define P(file, flag) ((file)->flags & (flag)) ? "true" : "false"
void FilePrintFlags(const File *file)
{
    SCLogDebug("file %p flags %04x "
               "FILE_TRUNCATED %s "
               "FILE_NOMAGIC %s "
               "FILE_NOMD5 %s "
               "FILE_MD5 %s "
               "FILE_NOSHA1 %s "
               "FILE_SHA1 %s "
               "FILE_NOSHA256 %s "
               "FILE_SHA256 %s "
               "FILE_LOGGED %s "
               "FILE_NOSTORE %s "
               "FILE_STORE %s "
               "FILE_STORED %s "
               "FILE_NOTRACK %s "
               "FILE_HAS_GAPS %s",
            file, file->flags, P(file, FILE_TRUNCATED), P(file, FILE_NOMAGIC), P(file, FILE_NOMD5),
            P(file, FILE_MD5), P(file, FILE_NOSHA1), P(file, FILE_SHA1), P(file, FILE_NOSHA256),
            P(file, FILE_SHA256), P(file, FILE_LOGGED), P(file, FILE_NOSTORE), P(file, FILE_STORE),
            P(file, FILE_STORED), P(file, FILE_NOTRACK), P(file, FILE_HAS_GAPS));
}
#undef P
#endif

static void FilePrune(FileContainer *ffc, const StreamingBufferConfig *cfg)
{
    SCEnter();
    SCLogDebug("ffc %p head %p", ffc, ffc->head);
    File *file = ffc->head;
    File *prev = NULL;

    while (file) {
#ifdef DEBUG
        FilePrintFlags(file);
#endif
        if (FilePruneFile(file, cfg) == 0) {
            prev = file;
            file = file->next;
            continue;
        }

        SCLogDebug("removing file %p", file);

        File *file_next = file->next;

        if (prev)
            prev->next = file_next;
        /* update head and tail */
        if (file == ffc->head)
            ffc->head = file_next;
        if (file == ffc->tail)
            ffc->tail = prev;

        FileFree(file, cfg);
        file = file_next;
    }
    SCReturn;
}

/**
 *  \brief allocate a FileContainer
 *
 *  \retval new newly allocated FileContainer
 *  \retval NULL error
 */
FileContainer *FileContainerAlloc(void)
{
    FileContainer *new = SCCalloc(1, sizeof(FileContainer));
    if (unlikely(new == NULL)) {
        SCLogError("Error allocating mem");
        return NULL;
    }
    new->head = new->tail = NULL;
    return new;
}

/**
 *  \brief Recycle a FileContainer
 *
 *  \param ffc FileContainer
 */
void FileContainerRecycle(FileContainer *ffc, const StreamingBufferConfig *cfg)
{
    SCLogDebug("ffc %p", ffc);
    if (ffc == NULL)
        return;

    File *cur = ffc->head;
    File *next = NULL;
    for (;cur != NULL; cur = next) {
        next = cur->next;
        FileFree(cur, cfg);
    }
    ffc->head = ffc->tail = NULL;
}

/**
 *  \brief Free a FileContainer
 *
 *  \param ffc FileContainer
 */
void FileContainerFree(FileContainer *ffc, const StreamingBufferConfig *cfg)
{
    SCLogDebug("ffc %p", ffc);
    if (ffc == NULL)
        return;

    File *ptr = ffc->head;
    File *next = NULL;
    for (;ptr != NULL; ptr = next) {
        next = ptr->next;
        FileFree(ptr, cfg);
    }
    ffc->head = ffc->tail = NULL;
    SCFree(ffc);
}

/**
 *  \brief Alloc a new File
 *
 *  \param name character array containing the name (not a string)
 *  \param name_len length in bytes of the name
 *
 *  \retval new File object or NULL on error
 */
static File *FileAlloc(const uint8_t *name, uint16_t name_len)
{
    File *new = SCCalloc(1, sizeof(File));
    if (unlikely(new == NULL)) {
        SCLogError("Error allocating mem");
        return NULL;
    }

    new->name = SCMalloc(name_len);
    if (new->name == NULL) {
        SCFree(new);
        return NULL;
    }

    new->name_len = name_len;
    memcpy(new->name, name, name_len);

    new->sid_cnt = 0;
    new->sid_max = 8;
    /* SCMalloc() is allowed to fail here because sid well be checked later on */
    new->sid = SCMalloc(sizeof(uint32_t) * new->sid_max);
    if (new->sid == NULL)
        new->sid_max = 0;

    return new;
}

static void FileFree(File *ff, const StreamingBufferConfig *sbcfg)
{
    SCLogDebug("ff %p", ff);
    if (ff == NULL)
        return;

    if (ff->name != NULL)
        SCFree(ff->name);
    if (ff->sid != NULL)
        SCFree(ff->sid);
#ifdef HAVE_MAGIC
    /* magic returned by libmagic is strdup'd by MagicLookup. */
    if (ff->magic != NULL)
        SCFree(ff->magic);
#endif
    if (ff->sb != NULL) {
        StreamingBufferFree(ff->sb, sbcfg);
    }

    if (ff->md5_ctx)
        SCMd5Free(ff->md5_ctx);
    if (ff->sha1_ctx)
        SCSha1Free(ff->sha1_ctx);
    if (ff->sha256_ctx)
        SCSha256Free(ff->sha256_ctx);
    SCFree(ff);
}

void FileContainerAdd(FileContainer *ffc, File *ff)
{
    SCLogDebug("ffc %p ff %p", ffc, ff);
    if (ffc->head == NULL || ffc->tail == NULL) {
        ffc->head = ffc->tail = ff;
    } else {
        ffc->tail->next = ff;
        ffc->tail = ff;
    }
}

/**
 *  \brief Tag a file for storing
 *
 *  \param ff The file to store
 */
int FileStore(File *ff)
{
    SCLogDebug("ff %p", ff);
    ff->flags |= FILE_STORE;
    SCReturnInt(0);
}

/**
 *  \brief check if we have stored enough
 *
 *  \param ff file
 *
 *  \retval 0 limit not reached yet
 *  \retval 1 limit reached
 */
static int FileStoreNoStoreCheck(File *ff)
{
    SCEnter();

    if (ff == NULL) {
        SCReturnInt(0);
    }

    if (ff->flags & FILE_NOSTORE) {
        if (ff->state == FILE_STATE_OPENED &&
            FileDataSize(ff) >= (uint64_t)FileMagicSize())
        {
            SCReturnInt(1);
        }
    }

    SCReturnInt(0);
}

static int AppendData(
        const StreamingBufferConfig *sbcfg, File *file, const uint8_t *data, uint32_t data_len)
{
    DEBUG_VALIDATE_BUG_ON(
            data_len > BIT_U32(26)); // 64MiB as a limit per chunk seems already excessive

    SCLogDebug("file %p data_len %u", file, data_len);
    if (StreamingBufferAppendNoTrack(file->sb, sbcfg, data, data_len) != 0) {
        SCLogDebug("file %p StreamingBufferAppendNoTrack failed", file);
        SCReturnInt(-1);
    }

    if (file->md5_ctx) {
        SCMd5Update(file->md5_ctx, data, data_len);
    }
    if (file->sha1_ctx) {
        SCSha1Update(file->sha1_ctx, data, data_len);
    }
    if (file->sha256_ctx) {
        SCLogDebug("SHA256 file %p data %p data_len %u", file, data, data_len);
        SCSha256Update(file->sha256_ctx, data, data_len);
    } else {
        SCLogDebug("NO SHA256 file %p data %p data_len %u", file, data, data_len);
    }
    SCReturnInt(0);
}

/** \internal
 *  \brief Flags a file as having gaps
 *
 *  \param ff the file
 */
static void FileFlagGap(File *ff) {
    ff->flags |= FILE_HAS_GAPS;
    ff->flags |= (FILE_NOMD5|FILE_NOSHA1|FILE_NOSHA256);
    ff->flags &= ~(FILE_MD5|FILE_SHA1|FILE_SHA256);
}

/** \internal
 *  \brief Store/handle a chunk of file data in the File structure
 *
 *  \param ff the file
 *  \param data data chunk
 *  \param data_len data chunk len
 *
 *  \retval  0 ok
 *  \retval -1 error
 *  \retval -2 no store for this file
 */
static int FileAppendDataDo(
        const StreamingBufferConfig *sbcfg, File *ff, const uint8_t *data, uint32_t data_len)
{
    SCEnter();
#ifdef DEBUG_VALIDATION
    BUG_ON(ff == NULL);
#endif

    ff->size += data_len;
    if (data == NULL) {
        FileFlagGap(ff);
        SCReturnInt(0);
    }

    if (ff->state != FILE_STATE_OPENED) {
        if (ff->flags & FILE_NOSTORE) {
            SCReturnInt(-2);
        }
        SCReturnInt(-1);
    }

    if (g_detect_disabled && FileStoreNoStoreCheck(ff) == 1) {
        int hash_done = 0;
        /* no storage but forced hashing */
        if (ff->md5_ctx) {
            SCMd5Update(ff->md5_ctx, data, data_len);
            hash_done = 1;
        }
        if (ff->sha1_ctx) {
            SCSha1Update(ff->sha1_ctx, data, data_len);
            hash_done = 1;
        }
        if (ff->sha256_ctx) {
            SCLogDebug("file %p data %p data_len %u", ff, data, data_len);
            SCSha256Update(ff->sha256_ctx, data, data_len);
            hash_done = 1;
        }

        if (hash_done)
            SCReturnInt(0);

        if (g_file_force_tracking || (!(ff->flags & FILE_NOTRACK)))
            SCReturnInt(0);

        ff->state = FILE_STATE_TRUNCATED;
        SCLogDebug("flowfile state transitioned to FILE_STATE_TRUNCATED");
        SCReturnInt(-2);
    }

    SCLogDebug("appending %"PRIu32" bytes", data_len);

    int r = AppendData(sbcfg, ff, data, data_len);
    if (r != 0) {
        ff->state = FILE_STATE_ERROR;
        SCReturnInt(r);
    }

    SCReturnInt(0);
}

/**
 *  \brief Store/handle a chunk of file data in the File structure
 *         The last file in the FileContainer will be used.
 *
 *  \param ffc FileContainer used to append to
 *  \param data data chunk
 *  \param data_len data chunk len
 *
 *  \retval  0 ok
 *  \retval -1 error
 *  \retval -2 no store for this file
 */
int FileAppendData(FileContainer *ffc, const StreamingBufferConfig *sbcfg, const uint8_t *data,
        uint32_t data_len)
{
    SCEnter();

    if (ffc == NULL || ffc->tail == NULL || data_len == 0 || sbcfg == NULL) {
        SCReturnInt(-1);
    }
    int r = FileAppendDataDo(sbcfg, ffc->tail, data, data_len);
    SCReturnInt(r);
}

/**
 *  \brief Store/handle a chunk of file data in the File structure
 *         The file with 'track_id' in the FileContainer will be used.
 *
 *  \param ffc FileContainer used to append to
 *  \param track_id id to lookup the file
 *  \param data data chunk
 *  \param data_len data chunk len
 *
 *  \retval  0 ok
 *  \retval -1 error
 *  \retval -2 no store for this file
 */
int FileAppendDataById(FileContainer *ffc, const StreamingBufferConfig *sbcfg, uint32_t track_id,
        const uint8_t *data, uint32_t data_len)
{
    SCEnter();

    if (ffc == NULL || ffc->tail == NULL || data == NULL || data_len == 0) {
        SCReturnInt(-1);
    }
    File *ff = ffc->head;
    for ( ; ff != NULL; ff = ff->next) {
        if (track_id == ff->file_track_id) {
            int r = FileAppendDataDo(sbcfg, ff, data, data_len);
            SCReturnInt(r);
        }
    }
    SCReturnInt(-1);
}

/**
 *  \brief Store/handle a chunk of file data in the File structure
 *         The file with 'track_id' in the FileContainer will be used.
 *
 *  \param ffc FileContainer used to append to
 *  \param track_id id to lookup the file
 *  \param data data chunk
 *  \param data_len data chunk len
 *
 *  \retval  0 ok
 *  \retval -1 error
 *  \retval -2 no store for this file
 */
int FileAppendGAPById(FileContainer *ffc, const StreamingBufferConfig *sbcfg, uint32_t track_id,
        const uint8_t *data, uint32_t data_len)
{
    SCEnter();

    if (ffc == NULL || ffc->tail == NULL || data == NULL || data_len == 0) {
        SCReturnInt(-1);
    }
    File *ff = ffc->head;
    for ( ; ff != NULL; ff = ff->next) {
        if (track_id == ff->file_track_id) {
            FileFlagGap(ff);
            SCLogDebug("FILE_HAS_GAPS set");

            int r = FileAppendDataDo(sbcfg, ff, data, data_len);
            SCReturnInt(r);
        }
    }
    SCReturnInt(-1);
}

void FileSetInspectSizes(File *file, const uint32_t win, const uint32_t min)
{
    file->inspect_window = win;
    file->inspect_min_size = min;
}

/**
 *  \brief Sets the offset range for a file.
 *
 *  \param ffc the container
 *  \param start start offset
 *  \param end end offset
 *
 *  \retval  0 ok
 *  \retval -1 error
 */
int FileSetRange(FileContainer *ffc, uint64_t start, uint64_t end)
{
    SCEnter();

    if (ffc == NULL || ffc->tail == NULL) {
        SCReturnInt(-1);
    }
    ffc->tail->start = start;
    ffc->tail->end = end;
    SCReturnInt(0);
}

/**
 *  \brief Open a new File
 *
 *  \param ffc flow container
 *  \param sbcfg buffer config
 *  \param name filename character array
 *  \param name_len filename len
 *  \param data initial data
 *  \param data_len initial data len
 *  \param flags open flags
 *
 *  \retval ff flowfile object
 *
 *  \note filename is not a string, so it's not nul terminated.
 */
static File *FileOpenFile(FileContainer *ffc, const StreamingBufferConfig *sbcfg,
        const uint8_t *name, uint16_t name_len,
        const uint8_t *data, uint32_t data_len, uint16_t flags)
{
    SCEnter();

    //PrintRawDataFp(stdout, name, name_len);

    File *ff = FileAlloc(name, name_len);
    if (ff == NULL) {
        SCReturnPtr(NULL, "File");
    }

    ff->sb = StreamingBufferInit(sbcfg);
    if (ff->sb == NULL) {
        FileFree(ff, sbcfg);
        SCReturnPtr(NULL, "File");
    }
    SCLogDebug("ff->sb %p", ff->sb);

    if (flags & FILE_STORE || g_file_force_filestore) {
        FileStore(ff);
    } else if (flags & FILE_NOSTORE) {
        SCLogDebug("not storing this file");
        ff->flags |= FILE_NOSTORE;
    }
    if (flags & FILE_NOMAGIC) {
        SCLogDebug("not doing magic for this file");
        ff->flags |= FILE_NOMAGIC;
    }
    if (flags & FILE_NOMD5) {
        SCLogDebug("not doing md5 for this file");
        ff->flags |= FILE_NOMD5;
    }
    if (flags & FILE_NOSHA1) {
        SCLogDebug("not doing sha1 for this file");
        ff->flags |= FILE_NOSHA1;
    }
    if (flags & FILE_NOSHA256) {
        SCLogDebug("not doing sha256 for this file");
        ff->flags |= FILE_NOSHA256;
    }

    if (!(ff->flags & FILE_NOMD5) || g_file_force_md5) {
        ff->md5_ctx = SCMd5New();
    }
    if (!(ff->flags & FILE_NOSHA1) || g_file_force_sha1) {
        ff->sha1_ctx = SCSha1New();
    }
    if (!(ff->flags & FILE_NOSHA256) || g_file_force_sha256) {
        ff->sha256_ctx = SCSha256New();
        SCLogDebug("ff %p ff->sha256_ctx %p", ff, ff->sha256_ctx);
    }

    ff->state = FILE_STATE_OPENED;
    SCLogDebug("flowfile state transitioned to FILE_STATE_OPENED");

    ff->fd = -1;

    FileContainerAdd(ffc, ff);

    /* set default window and min inspection size */
    FileSetInspectSizes(ff, FILEDATA_CONTENT_INSPECT_WINDOW, FILEDATA_CONTENT_INSPECT_MIN_SIZE);

    ff->size += data_len;
    if (data != NULL) {
        if (AppendData(sbcfg, ff, data, data_len) != 0) {
            ff->state = FILE_STATE_ERROR;
            SCReturnPtr(NULL, "File");
        }
        SCLogDebug("file size is now %"PRIu64, FileTrackedSize(ff));
    } else if (data_len > 0) {
        FileFlagGap(ff);
    }

    SCReturnPtr(ff, "File");
}

/**
 *  \retval 0 ok
 *  \retval -1 failed */
int FileOpenFileWithId(FileContainer *ffc, const StreamingBufferConfig *sbcfg,
        uint32_t track_id, const uint8_t *name, uint16_t name_len,
        const uint8_t *data, uint32_t data_len, uint16_t flags)
{
    SCLogDebug("ffc %p track_id %u", ffc, track_id);
    File *ff = FileOpenFile(ffc, sbcfg, name, name_len, data, data_len, flags);
    if (ff == NULL)
        return -1;

    ff->file_track_id = track_id;
    return 0;
}

int FileCloseFilePtr(File *ff, const StreamingBufferConfig *sbcfg, const uint8_t *data,
        uint32_t data_len, uint16_t flags)
{
    SCEnter();

    if (ff == NULL) {
        SCReturnInt(-1);
    }

    if (ff->state != FILE_STATE_OPENED) {
        SCReturnInt(-1);
    }

    ff->size += data_len;
    if (data != NULL) {
        if (ff->flags & FILE_NOSTORE) {
            /* no storage but hashing */
            if (ff->md5_ctx)
                SCMd5Update(ff->md5_ctx, data, data_len);
            if (ff->sha1_ctx)
                SCSha1Update(ff->sha1_ctx, data, data_len);
            if (ff->sha256_ctx) {
                SCLogDebug("file %p data %p data_len %u", ff, data, data_len);
                SCSha256Update(ff->sha256_ctx, data, data_len);
            }
        }
        if (AppendData(sbcfg, ff, data, data_len) != 0) {
            ff->state = FILE_STATE_ERROR;
            SCReturnInt(-1);
        }
    }

    if ((flags & FILE_TRUNCATED) || (ff->flags & FILE_HAS_GAPS)) {
        SCLogDebug("flags FILE_TRUNCATED %s", (flags & FILE_TRUNCATED) ? "true" : "false");
        SCLogDebug("ff->flags FILE_HAS_GAPS %s", (ff->flags & FILE_HAS_GAPS) ? "true" : "false");

        ff->state = FILE_STATE_TRUNCATED;
        SCLogDebug("flowfile state transitioned to FILE_STATE_TRUNCATED");

        if (flags & FILE_NOSTORE) {
            SCLogDebug("not storing this file");
            ff->flags |= FILE_NOSTORE;
        } else {
            if (g_file_force_sha256 && ff->sha256_ctx) {
                SCLogDebug("file %p data %p data_len %u", ff, data, data_len);
                FileEndSha256(ff);
            }
        }
    } else {
        ff->state = FILE_STATE_CLOSED;
        SCLogDebug("flowfile state transitioned to FILE_STATE_CLOSED");

        if (ff->md5_ctx) {
            SCMd5Finalize(ff->md5_ctx, ff->md5, sizeof(ff->md5));
            ff->md5_ctx = NULL;
            ff->flags |= FILE_MD5;
        }
        if (ff->sha1_ctx) {
            SCSha1Finalize(ff->sha1_ctx, ff->sha1, sizeof(ff->sha1));
            ff->sha1_ctx = NULL;
            ff->flags |= FILE_SHA1;
        }
        if (ff->sha256_ctx) {
            SCLogDebug("file %p data %p data_len %u", ff, data, data_len);
            FileEndSha256(ff);
        }
    }

    SCReturnInt(0);
}

/**
 *  \brief Close a File
 *
 *  \param ffc the container
 *  \param data final data if any
 *  \param data_len data len if any
 *  \param flags flags
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int FileCloseFile(FileContainer *ffc, const StreamingBufferConfig *sbcfg, const uint8_t *data,
        uint32_t data_len, uint16_t flags)
{
    SCEnter();

    if (ffc == NULL || ffc->tail == NULL) {
        SCReturnInt(-1);
    }

    if (FileCloseFilePtr(ffc->tail, sbcfg, data, data_len, flags) == -1) {
        SCReturnInt(-1);
    }

    SCReturnInt(0);
}

int FileCloseFileById(FileContainer *ffc, const StreamingBufferConfig *sbcfg, uint32_t track_id,
        const uint8_t *data, uint32_t data_len, uint16_t flags)
{
    SCEnter();

    if (ffc == NULL || ffc->tail == NULL) {
        SCReturnInt(-1);
    }

    File *ff = ffc->head;
    for ( ; ff != NULL; ff = ff->next) {
        if (track_id == ff->file_track_id) {
            int r = FileCloseFilePtr(ff, sbcfg, data, data_len, flags);
            SCReturnInt(r);
        }
    }
    SCReturnInt(-1);
}

/** \brief set a flow's file flags
 *  \param set_file_flags flags in both directions that are requested to set
 *
 *  This function will ignore the flags for the irrelevant direction and
 *  also mask the flags with the global settings.
 */
void FileUpdateFlowFileFlags(Flow *f, uint16_t set_file_flags, uint8_t direction)
{
    SCEnter();
    DEBUG_ASSERT_FLOW_LOCKED(f);

    /* remove flags not in our direction and
       don't disable what is globally enabled */
    if (direction == STREAM_TOSERVER) {
        set_file_flags &= ~(FLOWFILE_NONE_TC|g_file_flow_mask);
    } else {
        set_file_flags &= ~(FLOWFILE_NONE_TS|g_file_flow_mask);
    }
    f->file_flags |= set_file_flags;

    SCLogDebug("f->file_flags %04x set_file_flags %04x g_file_flow_mask %04x",
            f->file_flags, set_file_flags, g_file_flow_mask);

    if (set_file_flags != 0 && f->alproto != ALPROTO_UNKNOWN && f->alstate != NULL) {
        AppLayerStateData *sd = AppLayerParserGetStateData(f->proto, f->alproto, f->alstate);
        if (sd != NULL) {
            if ((sd->file_flags & f->file_flags) != f->file_flags) {
                SCLogDebug("state data: updating file_flags %04x with flow file_flags %04x",
                        sd->file_flags, f->file_flags);
                sd->file_flags |= f->file_flags;
            }
        }
    }
}

/**
 *  \brief disable file storing for files in a transaction
 *
 *  \param f *LOCKED* flow
 *  \param direction flow direction
 *  \param tx_id transaction id
 */
void FileDisableStoringForTransaction(Flow *f, const uint8_t direction, void *tx, uint64_t tx_id)
{
    if (g_file_force_filestore == 0) {
        AppLayerTxData *txd = AppLayerParserGetTxData(f->proto, f->alproto, tx);
        if (txd != NULL) {
            if (direction & STREAM_TOSERVER) {
                txd->file_flags |= FLOWFILE_NO_STORE_TS;
            } else {
                txd->file_flags |= FLOWFILE_NO_STORE_TC;
            }
        }
    }
}

/**
 *  \brief flag a file with id "file_id" to be stored.
 *
 *  \param fc file store
 *  \param file_id the file's id
 */
void FileStoreFileById(FileContainer *fc, uint32_t file_id)
{
    File *ptr = NULL;

    SCEnter();

    if (fc != NULL) {
        for (ptr = fc->head; ptr != NULL; ptr = ptr->next) {
            if (ptr->file_track_id == file_id) {
                FileStore(ptr);
            }
        }
    }
}

static void FileTruncateAllOpenFiles(FileContainer *fc, const StreamingBufferConfig *sbcfg)
{
    File *ptr = NULL;

    SCEnter();

    if (fc != NULL) {
        for (ptr = fc->head; ptr != NULL; ptr = ptr->next) {
            if (ptr->state == FILE_STATE_OPENED) {
                FileCloseFilePtr(ptr, sbcfg, NULL, 0, FILE_TRUNCATED);
            }
        }
    }
}

void FilesPrune(FileContainer *fc, const StreamingBufferConfig *sbcfg, const bool trunc)
{
    if (trunc) {
        FileTruncateAllOpenFiles(fc, sbcfg);
    }
    FilePrune(fc, sbcfg);
}

/**
 * \brief Finish the SHA256 calculation.
 */
static void FileEndSha256(File *ff)
{
    SCLogDebug("ff %p ff->size %" PRIu64, ff, ff->size);
    if (!(ff->flags & FILE_SHA256) && ff->sha256_ctx) {
        SCSha256Finalize(ff->sha256_ctx, ff->sha256, sizeof(ff->sha256));
        ff->sha256_ctx = NULL;
        ff->flags |= FILE_SHA256;
    }
}
