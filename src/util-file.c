/* Copyright (C) 2007-2012 Open Information Security Foundation
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
#include "runmodes.h"
#include "util-hash.h"
#include "util-debug.h"
#include "util-memcmp.h"
#include "util-print.h"
#include "app-layer-parser.h"
#include "util-validate.h"

/** \brief switch to force magic checks on all files
 *         regardless of the rules.
 */
static int g_file_force_magic = 0;

/** \brief switch to force md5 calculation on all files
 *         regardless of the rules.
 */
static int g_file_force_md5 = 0;

/** \brief switch to force tracking off all files
 *         regardless of the rules.
 */
static int g_file_force_tracking = 0;

/* prototypes */
static void FileFree(File *);
static void FileDataFree(FileData *);

void FileForceMagicEnable(void)
{
    g_file_force_magic = 1;
}

void FileForceMd5Enable(void)
{
    g_file_force_md5 = 1;
}

int FileForceMagic(void)
{
    return g_file_force_magic;
}

int FileForceMd5(void)
{
    return g_file_force_md5;
}

void FileForceTrackingEnable(void)
{
    g_file_force_tracking = 1;
}

int FileMagicSize(void)
{
    /** \todo make this size configurable */
    return 512;
}

static int FileAppendFileDataFilePtr(File *ff, FileData *ffd)
{
    SCEnter();

    if (ff == NULL) {
        SCReturnInt(-1);
    }

    if (ff->chunks_tail == NULL) {
        ff->chunks_head = ffd;
        ff->chunks_tail = ffd;
        ff->content_len_so_far = ffd->len;
    } else {
        ff->chunks_tail->next = ffd;
        ff->chunks_tail = ffd;
        ff->content_len_so_far += ffd->len;
    }

#ifdef DEBUG
    ff->chunks_cnt++;
    if (ff->chunks_cnt > ff->chunks_cnt_max)
        ff->chunks_cnt_max = ff->chunks_cnt;
#endif

#ifdef HAVE_NSS
    if (ff->md5_ctx)
        HASH_Update(ff->md5_ctx, ffd->data, ffd->len);
#endif
    SCReturnInt(0);
}

static int FileAppendFileData(FileContainer *ffc, FileData *ffd)
{
    SCEnter();

    if (ffc == NULL) {
        SCReturnInt(-1);
    }

    if (FileAppendFileDataFilePtr(ffc->tail, ffd) == -1)
    {
        SCReturnInt(-1);
    }

    SCReturnInt(0);
}



static int FilePruneFile(File *file)
{
    SCEnter();

    SCLogDebug("file %p, file->chunks_cnt %"PRIu64, file, file->chunks_cnt);

    if (!(file->flags & FILE_NOMAGIC)) {
        /* need magic but haven't set it yet, bail out */
        if (file->magic == NULL)
            SCReturnInt(0);
        else
            SCLogDebug("file->magic %s", file->magic);
    } else {
        SCLogDebug("file->flags & FILE_NOMAGIC == true");
    }

    /* okay, we now know we can prune */
    FileData *fd = file->chunks_head;

    while (fd != NULL) {
        SCLogDebug("fd %p", fd);

        if (file->flags & FILE_NOSTORE || fd->stored == 1) {
            file->chunks_head = fd->next;
            if (file->chunks_tail == fd)
                file->chunks_tail = fd->next;

            FileDataFree(fd);

            fd = file->chunks_head;
#ifdef DEBUG
            file->chunks_cnt--;
            SCLogDebug("file->chunks_cnt %"PRIu64, file->chunks_cnt);
#endif
        } else if (fd->stored == 0) {
            fd = NULL;
            SCReturnInt(0);
            break;
        }
    }

    /* file is done when state is closed+, logging/storing is done (if any) */
    if (file->state >= FILE_STATE_CLOSED &&
        (!RunModeOutputFileEnabled() || (file->flags & FILE_LOGGED)) &&
        (!RunModeOutputFiledataEnabled() || (file->flags & FILE_STORED)))
    {
        SCReturnInt(1);
    } else {
        SCReturnInt(0);
    }
}

void FilePrune(FileContainer *ffc)
{
    File *file = ffc->head;

    while (file) {
        if (FilePruneFile(file) == 0)
            break;

        BUG_ON(file != ffc->head);

        File *file_next = file->next;

        /* update head and tail */
        ffc->head = file_next;
        if (file == ffc->tail)
            ffc->tail = NULL;

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
 *  \internal
 *
 *  \brief allocate a FileData chunk and set it up
 *
 *  \param data data chunk to store in the FileData
 *  \param data_len lenght of the data
 *
 *  \retval new FileData object
 */
static FileData *FileDataAlloc(uint8_t *data, uint32_t data_len)
{
    FileData *new = SCMalloc(sizeof(FileData));
    if (unlikely(new == NULL)) {
        return NULL;
    }
    memset(new, 0, sizeof(FileData));

    new->data = SCMalloc(data_len);
    if (new->data == NULL) {
        SCFree(new);
        return NULL;
    }

    new->len = data_len;
    memcpy(new->data, data, data_len);

    new->next = NULL;
    return new;
}

/**
 *  \internal
 *
 *  \brief free a FileData object
 *
 *  \param ffd the flow file data object to free
 */
static void FileDataFree(FileData *ffd)
{
    if (ffd == NULL)
        return;

    if (ffd->data != NULL) {
        SCFree(ffd->data);
    }

    SCFree(ffd);
}

/**
 *  \brief Alloc a new File
 *
 *  \param name character array containing the name (not a string)
 *  \param name_len length in bytes of the name
 *
 *  \retval new File object or NULL on error
 */
static File *FileAlloc(uint8_t *name, uint16_t name_len)
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

    return new;
}

static void FileFree(File *ff)
{
    if (ff == NULL)
        return;

    if (ff->name != NULL)
        SCFree(ff->name);

    /* magic returned by libmagic is strdup'd by MagicLookup. */
    if (ff->magic != NULL)
        SCFree(ff->magic);

    if (ff->chunks_head != NULL) {
        FileData *ffd = ff->chunks_head;

        while (ffd != NULL) {
            FileData *next_ffd = ffd->next;
            FileDataFree(ffd);
            ffd = next_ffd;
        }
    }

#ifdef HAVE_NSS
    if (ff->md5_ctx)
        HASH_Destroy(ff->md5_ctx);
#endif
    SCLogDebug("ff chunks_cnt %"PRIu64", chunks_cnt_max %"PRIu64,
            ff->chunks_cnt, ff->chunks_cnt_max);
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
                ff->size >= (uint64_t)FileMagicSize())
        {
            SCReturnInt(1);
        }
    }

    SCReturnInt(0);
}

/**
 *  \brief Store a chunk of file data in the flow. The open "flowfile"
 *         will be used.
 *
 *  \param ffc the container
 *  \param data data chunk
 *  \param data_len data chunk len
 *
 *  \retval  0 ok
 *  \retval -1 error
 *  \retval -2 no store for this file
 */
int FileAppendData(FileContainer *ffc, uint8_t *data, uint32_t data_len)
{
    SCEnter();

    if (ffc == NULL || ffc->tail == NULL || data == NULL || data_len == 0) {
        SCReturnInt(-1);
    }

    if (ffc->tail->state != FILE_STATE_OPENED) {
        if (ffc->tail->flags & FILE_NOSTORE) {
            SCReturnInt(-2);
        }
        SCReturnInt(-1);
    }

    ffc->tail->size += data_len;
    SCLogDebug("file size is now %"PRIu64, ffc->tail->size);

    if (FileStoreNoStoreCheck(ffc->tail) == 1) {
#ifdef HAVE_NSS
        /* no storage but forced md5 */
        if (ffc->tail->md5_ctx) {
            if (ffc->tail->md5_ctx)
                HASH_Update(ffc->tail->md5_ctx, data, data_len);

            SCReturnInt(0);
        }
#endif
        if (g_file_force_tracking || (!(ffc->tail->flags & FILE_NOTRACK)))
            SCReturnInt(0);

        ffc->tail->state = FILE_STATE_TRUNCATED;
        SCLogDebug("flowfile state transitioned to FILE_STATE_TRUNCATED");
        SCReturnInt(-2);
    }

    SCLogDebug("appending %"PRIu32" bytes", data_len);

    FileData *ffd = FileDataAlloc(data, data_len);
    if (ffd == NULL) {
        ffc->tail->state = FILE_STATE_ERROR;
        SCReturnInt(-1);
    }

    if (ffc->tail->chunks_head == NULL)
        ffd->stream_offset = 0;
    else
        ffd->stream_offset = ffc->tail->size;

    /* append the data */
    if (FileAppendFileData(ffc, ffd) < 0) {
        ffc->tail->state = FILE_STATE_ERROR;
        FileDataFree(ffd);
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

/**
 *  \brief Open a new File
 *
 *  \param ffc flow container
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
File *FileOpenFile(FileContainer *ffc, uint8_t *name,
        uint16_t name_len, uint8_t *data, uint32_t data_len, uint8_t flags)
{
    SCEnter();

    //PrintRawDataFp(stdout, name, name_len);

    File *ff = FileAlloc(name, name_len);
    if (ff == NULL) {
        SCReturnPtr(NULL, "File");
    }

    if (flags & FILE_STORE) {
        ff->flags |= FILE_STORE;
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

#ifdef HAVE_NSS
    if (!(ff->flags & FILE_NOMD5) || g_file_force_md5) {
        ff->md5_ctx = HASH_Create(HASH_AlgMD5);
        if (ff->md5_ctx != NULL) {
            HASH_Begin(ff->md5_ctx);
        }
    }
#endif

    ff->state = FILE_STATE_OPENED;
    SCLogDebug("flowfile state transitioned to FILE_STATE_OPENED");

    FileContainerAdd(ffc, ff);

    if (data != NULL) {
        //PrintRawDataFp(stdout, data, data_len);
        ff->size += data_len;
        SCLogDebug("file size is now %"PRIu64, ff->size);

        FileData *ffd = FileDataAlloc(data, data_len);
        if (ffd == NULL) {
            ff->state = FILE_STATE_ERROR;
            SCReturnPtr(NULL, "File");
        }

        /* append the data */
        if (FileAppendFileData(ffc, ffd) < 0) {
            ff->state = FILE_STATE_ERROR;
            FileDataFree(ffd);
            SCReturnPtr(NULL, "File");
        }
    }

    SCReturnPtr(ff, "File");
}

static int FileCloseFilePtr(File *ff, uint8_t *data,
        uint32_t data_len, uint8_t flags)
{
    SCEnter();

    if (ff == NULL) {
        SCReturnInt(-1);
    }

    if (ff->state != FILE_STATE_OPENED) {
        SCReturnInt(-1);
    }

    ff->size += data_len;
    SCLogDebug("file size is now %"PRIu64, ff->size);

    if (data != NULL) {
        //PrintRawDataFp(stdout, data, data_len);

        if (ff->flags & FILE_NOSTORE) {
#ifdef HAVE_NSS
            /* no storage but md5 */
            if (ff->md5_ctx)
                HASH_Update(ff->md5_ctx, data, data_len);
#endif
        } else {
            FileData *ffd = FileDataAlloc(data, data_len);
            if (ffd == NULL) {
                ff->state = FILE_STATE_ERROR;
                SCReturnInt(-1);
            }

            /* append the data */
            if (FileAppendFileDataFilePtr(ff, ffd) < 0) {
                ff->state = FILE_STATE_ERROR;
                FileDataFree(ffd);
                SCReturnInt(-1);
            }
        }
    }

    if (flags & FILE_TRUNCATED) {
        ff->state = FILE_STATE_TRUNCATED;
        SCLogDebug("flowfile state transitioned to FILE_STATE_TRUNCATED");

        if (flags & FILE_NOSTORE) {
            SCLogDebug("not storing this file");
            ff->flags |= FILE_NOSTORE;
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
int FileCloseFile(FileContainer *ffc, uint8_t *data,
        uint32_t data_len, uint8_t flags)
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

/**
 *  \brief disable file storage for a flow
 *
 *  \param f *LOCKED* flow
 *  \param direction flow direction
 */
void FileDisableStoring(Flow *f, uint8_t direction)
{
    File *ptr = NULL;

    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    if (direction == STREAM_TOSERVER)
        f->flags |= FLOW_FILE_NO_STORE_TS;
    else
        f->flags |= FLOW_FILE_NO_STORE_TC;

    FileContainer *ffc = AppLayerParserGetFiles(f->proto, f->alproto, f->alstate, direction);
    if (ffc != NULL) {
        for (ptr = ffc->head; ptr != NULL; ptr = ptr->next) {
            /* if we're already storing, we'll continue */
            if (!(ptr->flags & FILE_STORE)) {
                SCLogDebug("not storing this file");
                ptr->flags |= FILE_NOSTORE;
            }
        }
    }
    SCReturn;
}

/**
 *  \brief disable file magic lookups for this flow
 *
 *  \param f *LOCKED* flow
 *  \param direction flow direction
 */
void FileDisableMagic(Flow *f, uint8_t direction)
{
    File *ptr = NULL;

    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    if (direction == STREAM_TOSERVER)
        f->flags |= FLOW_FILE_NO_MAGIC_TS;
    else
        f->flags |= FLOW_FILE_NO_MAGIC_TC;

    FileContainer *ffc = AppLayerParserGetFiles(f->proto, f->alproto, f->alstate, direction);
    if (ffc != NULL) {
        for (ptr = ffc->head; ptr != NULL; ptr = ptr->next) {
            SCLogDebug("disabling magic for file %p from direction %s",
                    ptr, direction == STREAM_TOSERVER ? "toserver":"toclient");
            ptr->flags |= FILE_NOMAGIC;
        }
    }

    SCReturn;
}

/**
 *  \brief disable file md5 calc for this flow
 *
 *  \param f *LOCKED* flow
 *  \param direction flow direction
 */
void FileDisableMd5(Flow *f, uint8_t direction)
{
    File *ptr = NULL;

    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    if (direction == STREAM_TOSERVER)
        f->flags |= FLOW_FILE_NO_MD5_TS;
    else
        f->flags |= FLOW_FILE_NO_MD5_TC;

    FileContainer *ffc = AppLayerParserGetFiles(f->proto, f->alproto, f->alstate, direction);
    if (ffc != NULL) {
        for (ptr = ffc->head; ptr != NULL; ptr = ptr->next) {
            SCLogDebug("disabling md5 for file %p from direction %s",
                    ptr, direction == STREAM_TOSERVER ? "toserver":"toclient");
            ptr->flags |= FILE_NOMD5;

#ifdef HAVE_NSS
            /* destroy any ctx we may have so far */
            if (ptr->md5_ctx != NULL) {
                HASH_Destroy(ptr->md5_ctx);
                ptr->md5_ctx = NULL;
            }
#endif
        }
    }

    SCReturn;
}

/**
 *  \brief disable file size tracking for this flow
 *
 *  \param f *LOCKED* flow
 *  \param direction flow direction
 */
void FileDisableFilesize(Flow *f, uint8_t direction)
{
    File *ptr = NULL;

    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    if (direction == STREAM_TOSERVER)
        f->flags |= FLOW_FILE_NO_SIZE_TS;
    else
        f->flags |= FLOW_FILE_NO_SIZE_TC;

    FileContainer *ffc = AppLayerParserGetFiles(f->proto, f->alproto, f->alstate, direction);
    if (ffc != NULL) {
        for (ptr = ffc->head; ptr != NULL; ptr = ptr->next) {
            SCLogDebug("disabling size tracking for file %p from direction %s",
                    ptr, direction == STREAM_TOSERVER ? "toserver":"toclient");
            ptr->flags |= FILE_NOTRACK;
        }
    }

    SCReturn;
}


/**
 *  \brief set no store flag, close file if needed
 *
 *  \param ff file
 */
void FileDisableStoringForFile(File *ff)
{
    SCEnter();

    if (ff == NULL) {
        SCReturn;
    }

    SCLogDebug("not storing this file");
    ff->flags |= FILE_NOSTORE;

    if (ff->state == FILE_STATE_OPENED && ff->size >= (uint64_t)FileMagicSize()) {
        if (g_file_force_md5 == 0 && g_file_force_tracking == 0) {
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

    FileContainer *ffc = AppLayerParserGetFiles(f->proto, f->alproto, f->alstate, direction);
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
void FileStoreFileById(FileContainer *fc, uint16_t file_id)
{
    File *ptr = NULL;

    SCEnter();

    if (fc != NULL) {
        for (ptr = fc->head; ptr != NULL; ptr = ptr->next) {
            if (ptr->file_id == file_id) {
                ptr->flags |= FILE_STORE;
            }
        }
    }
}

void FileStoreAllFilesForTx(FileContainer *fc, uint16_t tx_id)
{
    File *ptr = NULL;

    SCEnter();

    if (fc != NULL) {
        for (ptr = fc->head; ptr != NULL; ptr = ptr->next) {
            if (ptr->txid == tx_id) {
                ptr->flags |= FILE_STORE;
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
            ptr->flags |= FILE_STORE;
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
