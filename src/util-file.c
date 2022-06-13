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
#include "debug.h"
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

extern int g_detect_disabled;

/** \brief mask of file flags we'll not set
 *  This mask is set based on global file settings and
 *  cannot be overriden by detection.
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
static void FileFree(File *);
#ifdef HAVE_NSS
static void FileEndSha256(File *ff);
#endif

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
        SCLogWarning(SC_ERR_DEPRECATED_CONF, "deprecated 'force-md5' option "
                "found. Please use 'force-hash: [md5]' instead");

        if (ConfValIsTrue(force_md5)) {
#ifdef HAVE_NSS
            FileForceMd5Enable();
            SCLogInfo("forcing md5 calculation for logged files");
#else
            SCLogInfo("md5 calculation requires linking against libnss");
#endif
        }
    }

    if (conf != NULL)
        forcehash_node = ConfNodeLookupChild(conf, "force-hash");

    if (forcehash_node != NULL) {
        ConfNode *field = NULL;

        TAILQ_FOREACH(field, &forcehash_node->head, next) {
            if (strcasecmp("md5", field->val) == 0) {
#ifdef HAVE_NSS
                FileForceMd5Enable();
                SCLogConfig("forcing md5 calculation for logged or stored files");
#else
                SCLogInfo("md5 calculation requires linking against libnss");
#endif
            }

            if (strcasecmp("sha1", field->val) == 0) {
#ifdef HAVE_NSS
                FileForceSha1Enable();
                SCLogConfig("forcing sha1 calculation for logged or stored files");
#else
                SCLogInfo("sha1 calculation requires linking against libnss");
#endif
            }

            if (strcasecmp("sha256", field->val) == 0) {
#ifdef HAVE_NSS
                FileForceSha256Enable();
                SCLogConfig("forcing sha256 calculation for logged or stored files");
#else
                SCLogInfo("sha256 calculation requires linking against libnss");
#endif
            }
        }
    }
}

uint16_t FileFlowToFlags(const Flow *flow, uint8_t direction)
{
    uint16_t flags = 0;

    if (direction == STREAM_TOSERVER) {
        if (flow->file_flags & FLOWFILE_NO_STORE_TS) {
            flags |= FILE_NOSTORE;
        }

        if (flow->file_flags & FLOWFILE_NO_MAGIC_TS) {
            flags |= FILE_NOMAGIC;
        }

        if (flow->file_flags & FLOWFILE_NO_MD5_TS) {
            flags |= FILE_NOMD5;
        }

        if (flow->file_flags & FLOWFILE_NO_SHA1_TS) {
            flags |= FILE_NOSHA1;
        }

        if (flow->file_flags & FLOWFILE_NO_SHA256_TS) {
            flags |= FILE_NOSHA256;
        }
    } else {
        if (flow->file_flags & FLOWFILE_NO_STORE_TC) {
            flags |= FILE_NOSTORE;
        }

        if (flow->file_flags & FLOWFILE_NO_MAGIC_TC) {
            flags |= FILE_NOMAGIC;
        }

        if (flow->file_flags & FLOWFILE_NO_MD5_TC) {
            flags |= FILE_NOMD5;
        }

        if (flow->file_flags & FLOWFILE_NO_SHA1_TC) {
            flags |= FILE_NOSHA1;
        }

        if (flow->file_flags & FLOWFILE_NO_SHA256_TC) {
            flags |= FILE_NOSHA256;
        }
    }
    return flags;
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
        SCLogDebug("returning %"PRIu64,
                file->sb->stream_offset + file->sb->buf_offset);
        return file->sb->stream_offset + file->sb->buf_offset;
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
static int FilePruneFile(File *file)
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
    if (file->flags & FILE_USE_DETECT) {
        left_edge = MIN(left_edge, file->content_inspected);

        /* if file has inspect window and min size set, we
         * do some house keeping here */
        if (file->inspect_window != 0 && file->inspect_min_size != 0) {
            uint32_t window = file->inspect_window;
            if (file->sb->stream_offset == 0)
                window = MAX(window, file->inspect_min_size);

            uint64_t file_size = FileDataSize(file);
            uint64_t data_size = file_size - file->sb->stream_offset;

            SCLogDebug("window %"PRIu32", file_size %"PRIu64", data_size %"PRIu64,
                    window, file_size, data_size);

            if (data_size > (window * 3)) {
                left_edge = file_size - window;
                SCLogDebug("file->content_inspected now %"PRIu64, left_edge);
                file->content_inspected = left_edge;
            }
        }
    }

    if (left_edge) {
        StreamingBufferSlideToOffset(file->sb, left_edge);
    }

    SCReturnInt(0);
}

void FilePrune(FileContainer *ffc)
{
    File *file = ffc->head;
    File *prev = NULL;

    while (file) {
        if (FilePruneFile(file) == 0) {
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

        FileFree(file);
        file = file_next;
    }
}

/**
 *  \brief allocate a FileContainer
 *
 *  \retval new newly allocated FileContainer
 *  \retval NULL error
 */
FileContainer *FileContainerAlloc(void)
{
    FileContainer *new = SCMalloc(sizeof(FileContainer));
    if (unlikely(new == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating mem");
        return NULL;
    }
    memset(new, 0, sizeof(FileContainer));
    new->head = new->tail = NULL;
    return new;
}

/**
 *  \brief Recycle a FileContainer
 *
 *  \param ffc FileContainer
 */
void FileContainerRecycle(FileContainer *ffc)
{
    if (ffc == NULL)
        return;

    File *cur = ffc->head;
    File *next = NULL;
    for (;cur != NULL; cur = next) {
        next = cur->next;
        FileFree(cur);
    }
    ffc->head = ffc->tail = NULL;
}

/**
 *  \brief Free a FileContainer
 *
 *  \param ffc FileContainer
 */
void FileContainerFree(FileContainer *ffc)
{
    if (ffc == NULL)
        return;

    File *ptr = ffc->head;
    File *next = NULL;
    for (;ptr != NULL; ptr = next) {
        next = ptr->next;
        FileFree(ptr);
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
    File *new = SCMalloc(sizeof(File));
    if (unlikely(new == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating mem");
        return NULL;
    }
    memset(new, 0, sizeof(File));

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

static void FileFree(File *ff)
{
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
        StreamingBufferFree(ff->sb);
    }

#ifdef HAVE_NSS
    if (ff->md5_ctx)
        HASH_Destroy(ff->md5_ctx);
    if (ff->sha1_ctx)
        HASH_Destroy(ff->sha1_ctx);
    if (ff->sha256_ctx)
        HASH_Destroy(ff->sha256_ctx);
#endif
    SCFree(ff);
}

void FileContainerAdd(FileContainer *ffc, File *ff)
{
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
    ff->flags |= FILE_STORE;
    SCReturnInt(0);
}

/**
 *  \brief Set the TX id for a file
 *
 *  \param ff The file to store
 *  \param txid the tx id
 */
int FileSetTx(File *ff, uint64_t txid)
{
    SCLogDebug("ff %p txid %"PRIu64, ff, txid);
    if (ff != NULL)
        ff->txid = txid;
    SCReturnInt(0);
}

void FileContainerSetTx(FileContainer *ffc, uint64_t tx_id)
{
    if (ffc && ffc->tail) {
        (void)FileSetTx(ffc->tail, tx_id);
    }
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

static int AppendData(File *file, const uint8_t *data, uint32_t data_len)
{
    if (StreamingBufferAppendNoTrack(file->sb, data, data_len) != 0) {
        SCReturnInt(-1);
    }

#ifdef HAVE_NSS
    if (file->md5_ctx) {
        HASH_Update(file->md5_ctx, data, data_len);
    }
    if (file->sha1_ctx) {
        HASH_Update(file->sha1_ctx, data, data_len);
    }
    if (file->sha256_ctx) {
        HASH_Update(file->sha256_ctx, data, data_len);
    }
#endif
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
static int FileAppendDataDo(File *ff, const uint8_t *data, uint32_t data_len)
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

    if ((ff->flags & FILE_USE_DETECT) == 0 &&
            FileStoreNoStoreCheck(ff) == 1) {
#ifdef HAVE_NSS
        int hash_done = 0;
        /* no storage but forced hashing */
        if (ff->md5_ctx) {
            HASH_Update(ff->md5_ctx, data, data_len);
            hash_done = 1;
        }
        if (ff->sha1_ctx) {
            HASH_Update(ff->sha1_ctx, data, data_len);
            hash_done = 1;
        }
        if (ff->sha256_ctx) {
            HASH_Update(ff->sha256_ctx, data, data_len);
            hash_done = 1;
        }

        if (hash_done)
            SCReturnInt(0);
#endif
        if (g_file_force_tracking || (!(ff->flags & FILE_NOTRACK)))
            SCReturnInt(0);

        ff->state = FILE_STATE_TRUNCATED;
        SCLogDebug("flowfile state transitioned to FILE_STATE_TRUNCATED");
        SCReturnInt(-2);
    }

    SCLogDebug("appending %"PRIu32" bytes", data_len);

    int r = AppendData(ff, data, data_len);
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
int FileAppendData(FileContainer *ffc, const uint8_t *data, uint32_t data_len)
{
    SCEnter();

    if (ffc == NULL || ffc->tail == NULL || data_len == 0) {
        SCReturnInt(-1);
    }
    int r = FileAppendDataDo(ffc->tail, data, data_len);
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
int FileAppendDataById(FileContainer *ffc, uint32_t track_id,
        const uint8_t *data, uint32_t data_len)
{
    SCEnter();

    if (ffc == NULL || ffc->tail == NULL || data == NULL || data_len == 0) {
        SCReturnInt(-1);
    }
    File *ff = ffc->head;
    for ( ; ff != NULL; ff = ff->next) {
        if (track_id == ff->file_track_id) {
            int r = FileAppendDataDo(ff, data, data_len);
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
int FileAppendGAPById(FileContainer *ffc, uint32_t track_id,
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

            int r = FileAppendDataDo(ff, data, data_len);
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
        FileFree(ff);
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
    if (!g_detect_disabled && flags & FILE_USE_DETECT) {
        SCLogDebug("considering content_inspect tracker when pruning");
        ff->flags |= FILE_USE_DETECT;
    }

#ifdef HAVE_NSS
    if (!(ff->flags & FILE_NOMD5) || g_file_force_md5) {
        ff->md5_ctx = HASH_Create(HASH_AlgMD5);
        if (ff->md5_ctx != NULL) {
            HASH_Begin(ff->md5_ctx);
        }
    }
    if (!(ff->flags & FILE_NOSHA1) || g_file_force_sha1) {
        ff->sha1_ctx = HASH_Create(HASH_AlgSHA1);
        if (ff->sha1_ctx != NULL) {
            HASH_Begin(ff->sha1_ctx);
        }
    }
    if (!(ff->flags & FILE_NOSHA256) || g_file_force_sha256) {
        ff->sha256_ctx = HASH_Create(HASH_AlgSHA256);
        if (ff->sha256_ctx != NULL) {
            HASH_Begin(ff->sha256_ctx);
        }
    }
#endif

    ff->state = FILE_STATE_OPENED;
    SCLogDebug("flowfile state transitioned to FILE_STATE_OPENED");

    ff->fd = -1;

    FileContainerAdd(ffc, ff);

    ff->size += data_len;
    if (data != NULL) {
        if (AppendData(ff, data, data_len) != 0) {
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
    File *ff = FileOpenFile(ffc, sbcfg, name, name_len, data, data_len, flags);
    if (ff == NULL)
        return -1;

    ff->file_track_id = track_id;
    return 0;
}

int FileCloseFilePtr(File *ff, const uint8_t *data,
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
#ifdef HAVE_NSS
            /* no storage but hashing */
            if (ff->md5_ctx)
                HASH_Update(ff->md5_ctx, data, data_len);
            if (ff->sha1_ctx)
                HASH_Update(ff->sha1_ctx, data, data_len);
            if (ff->sha256_ctx)
                HASH_Update(ff->sha256_ctx, data, data_len);
#endif
        } else {
            if (AppendData(ff, data, data_len) != 0) {
                ff->state = FILE_STATE_ERROR;
                SCReturnInt(-1);
            }
        }
    }

    if ((flags & FILE_TRUNCATED) || (ff->flags & FILE_HAS_GAPS)) {
        ff->state = FILE_STATE_TRUNCATED;
        SCLogDebug("flowfile state transitioned to FILE_STATE_TRUNCATED");

        if (flags & FILE_NOSTORE) {
            SCLogDebug("not storing this file");
            ff->flags |= FILE_NOSTORE;
        } else {
#ifdef HAVE_NSS
            if (g_file_force_sha256 && ff->sha256_ctx) {
                FileEndSha256(ff);
            }
#endif
        }
    } else {
        ff->state = FILE_STATE_CLOSED;
        SCLogDebug("flowfile state transitioned to FILE_STATE_CLOSED");

#ifdef HAVE_NSS
        if (ff->md5_ctx) {
            unsigned int len = 0;
            HASH_End(ff->md5_ctx, ff->md5, &len, sizeof(ff->md5));
            ff->flags |= FILE_MD5;
        }
        if (ff->sha1_ctx) {
            unsigned int len = 0;
            HASH_End(ff->sha1_ctx, ff->sha1, &len, sizeof(ff->sha1));
            ff->flags |= FILE_SHA1;
        }
        if (ff->sha256_ctx) {
            FileEndSha256(ff);
        }
#endif
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
int FileCloseFile(FileContainer *ffc, const uint8_t *data,
        uint32_t data_len, uint16_t flags)
{
    SCEnter();

    if (ffc == NULL || ffc->tail == NULL) {
        SCReturnInt(-1);
    }

    if (FileCloseFilePtr(ffc->tail, data, data_len, flags) == -1) {
        SCReturnInt(-1);
    }

    SCReturnInt(0);
}

int FileCloseFileById(FileContainer *ffc, uint32_t track_id,
        const uint8_t *data, uint32_t data_len, uint16_t flags)
{
    SCEnter();

    if (ffc == NULL || ffc->tail == NULL) {
        SCReturnInt(-1);
    }

    File *ff = ffc->head;
    for ( ; ff != NULL; ff = ff->next) {
        if (track_id == ff->file_track_id) {
            int r = FileCloseFilePtr(ff, data, data_len, flags);
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
        uint16_t per_file_flags = 0;
#ifdef HAVE_MAGIC
        if (set_file_flags & (FLOWFILE_NO_MAGIC_TS|FLOWFILE_NO_MAGIC_TC))
            per_file_flags |= FILE_NOMAGIC;
#endif
#ifdef HAVE_NSS
        if (set_file_flags & (FLOWFILE_NO_MD5_TS|FLOWFILE_NO_MD5_TC))
            per_file_flags |= FILE_NOMD5;
        if (set_file_flags & (FLOWFILE_NO_SHA1_TS|FLOWFILE_NO_SHA1_TC))
            per_file_flags |= FILE_NOSHA1;
        if (set_file_flags & (FLOWFILE_NO_SHA256_TS|FLOWFILE_NO_SHA256_TC))
            per_file_flags |= FILE_NOSHA256;
#endif
        if (set_file_flags & (FLOWFILE_NO_SIZE_TS|FLOWFILE_NO_SIZE_TC))
            per_file_flags |= FILE_NOTRACK;
        if (set_file_flags & (FLOWFILE_NO_STORE_TS|FLOWFILE_NO_STORE_TC))
            per_file_flags |= FILE_NOSTORE;

        FileContainer *ffc = AppLayerParserGetFiles(f, direction);
        if (ffc != NULL) {
            for (File *ptr = ffc->head; ptr != NULL; ptr = ptr->next) {
                ptr->flags |= per_file_flags;

#ifdef HAVE_NSS
                /* destroy any ctx we may have so far */
                if ((per_file_flags & FILE_NOSHA256) &&
                        ptr->sha256_ctx != NULL)
                {
                    HASH_Destroy(ptr->sha256_ctx);
                    ptr->sha256_ctx = NULL;
                }
                if ((per_file_flags & FILE_NOSHA1) &&
                    ptr->sha1_ctx != NULL)
                {
                    HASH_Destroy(ptr->sha1_ctx);
                    ptr->sha1_ctx = NULL;
                }
                if ((per_file_flags & FILE_NOMD5) &&
                        ptr->md5_ctx != NULL)
                {
                    HASH_Destroy(ptr->md5_ctx);
                    ptr->md5_ctx = NULL;
                }
#endif
            }
        }
    }
}



/**
 *  \brief set no store flag, close file if needed
 *
 *  \param ff file
 */
static void FileDisableStoringForFile(File *ff)
{
    SCEnter();

    if (ff == NULL) {
        SCReturn;
    }

    SCLogDebug("not storing this file");
    ff->flags |= FILE_NOSTORE;

    if (ff->state == FILE_STATE_OPENED && FileDataSize(ff) >= (uint64_t)FileMagicSize()) {
        if (g_file_force_md5 == 0 && g_file_force_sha1 == 0 && g_file_force_sha256 == 0
                && g_file_force_tracking == 0) {
            (void)FileCloseFilePtr(ff, NULL, 0,
                    (FILE_TRUNCATED|FILE_NOSTORE));
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
void FileDisableStoringForTransaction(Flow *f, uint8_t direction, uint64_t tx_id)
{
    File *ptr = NULL;

    DEBUG_ASSERT_FLOW_LOCKED(f);

    SCEnter();

    FileContainer *ffc = AppLayerParserGetFiles(f, direction);
    if (ffc != NULL) {
        for (ptr = ffc->head; ptr != NULL; ptr = ptr->next) {
            if (ptr->txid == tx_id) {
                if (ptr->flags & FILE_STORE) {
                    /* weird, already storing -- let it continue*/
                    SCLogDebug("file is already being stored");
                } else {
                    FileDisableStoringForFile(ptr);
                }
            }
        }
    }

    SCReturn;
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

void FileStoreAllFilesForTx(FileContainer *fc, uint64_t tx_id)
{
    File *ptr = NULL;

    SCEnter();

    if (fc != NULL) {
        for (ptr = fc->head; ptr != NULL; ptr = ptr->next) {
            if (ptr->txid == tx_id) {
                FileStore(ptr);
            }
        }
    }
}

void FileStoreAllFiles(FileContainer *fc)
{
    File *ptr = NULL;

    SCEnter();

    if (fc != NULL) {
        for (ptr = fc->head; ptr != NULL; ptr = ptr->next) {
            FileStore(ptr);
        }
    }
}

void FileTruncateAllOpenFiles(FileContainer *fc)
{
    File *ptr = NULL;

    SCEnter();

    if (fc != NULL) {
        for (ptr = fc->head; ptr != NULL; ptr = ptr->next) {
            if (ptr->state == FILE_STATE_OPENED) {
                FileCloseFilePtr(ptr, NULL, 0, FILE_TRUNCATED);
            }
        }
    }
}

/**
 * \brief Finish the SHA256 calculation.
 */
#ifdef HAVE_NSS
static void FileEndSha256(File *ff)
{
    if (!(ff->flags & FILE_SHA256) && ff->sha256_ctx) {
        unsigned int len = 0;
        HASH_End(ff->sha256_ctx, ff->sha256, &len, sizeof(ff->sha256));
        ff->flags |= FILE_SHA256;
    }
}
#endif
