/* Copyright (C) 2007-2011 Open Information Security Foundation
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
#include "flow-file.h"
#include "util-hash.h"
#include "util-debug.h"
#include "util-memcmp.h"
#include "util-print.h"

/* prototypes */
static void FlowFileFree(FlowFile *);

/**
 *  \brief allocate a FlowFileContainer
 *
 *  \retval new newly allocated FlowFileContainer
 *  \retval NULL error
 */
FlowFileContainer *FlowFileContainerAlloc(void) {
    FlowFileContainer *new = SCMalloc(sizeof(FlowFileContainer));
    if (new == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating mem");
        return NULL;
    }
    memset(new, 0, sizeof(FlowFileContainer));
    new->head = new->tail = NULL;
    return new;
}

/**
 *  \brief Recycle a FlowFileContainer
 *
 *  \param ffc FlowFileContainer
 */
void FlowFileContainerRecycle(FlowFileContainer *ffc) {
    if (ffc == NULL)
        return;

    FlowFile *cur = ffc->head;
    FlowFile *next = NULL;
    for (;cur != NULL; cur = next) {
        next = cur->next;
        FlowFileFree(cur);
    }
    ffc->head = ffc->tail = NULL;
}

/**
 *  \brief Free a FlowFileContainer
 *
 *  \param ffc FlowFileContainer
 */
void FlowFileContainerFree(FlowFileContainer *ffc) {
    if (ffc == NULL)
        return;

    FlowFile *ptr = ffc->head;
    FlowFile *next = NULL;
    for (;ptr != NULL; ptr = next) {
        next = ptr->next;
        FlowFileFree(ptr);
    }
    ffc->head = ffc->tail = NULL;
    SCFree(ffc);
}

/**
 *  \internal
 *
 *  \brief allocate a FlowFileData chunk and set it up
 *
 *  \param data data chunk to store in the FlowFileData
 *  \param data_len lenght of the data
 *
 *  \retval new FlowFileData object
 */
static FlowFileData *FlowFileDataAlloc(uint8_t *data, uint32_t data_len) {
    FlowFileData *new = SCMalloc(sizeof(FlowFileData));
    if (new == NULL) {
        return NULL;
    }
    memset(new, 0, sizeof(FlowFileData));

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
 *  \brief free a FlowFileData object
 *
 *  \param ffd the flow file data object to free
 */
static void FlowFileDataFree(FlowFileData *ffd) {
    if (ffd == NULL)
        return;

    if (ffd->data != NULL) {
        SCFree(ffd->data);
    }

    SCFree(ffd);
}

static int FlowFileAppendFlowFileDataFilePtr(FlowFile *ff, FlowFileData *ffd) {
    SCEnter();

    if (ff == NULL) {
        SCReturnInt(-1);
    }

    if (ff->chunks_tail == NULL) {
        ff->chunks_head = ffd;
        ff->chunks_tail = ffd;
    } else {
        ff->chunks_tail->next = ffd;
        ff->chunks_tail = ffd;
    }

    SCReturnInt(0);
}

static int FlowFileAppendFlowFileData(FlowFileContainer *ffc, FlowFileData *ffd) {
    SCEnter();

    if (ffc == NULL) {
        SCReturnInt(-1);
    }

    if (FlowFileAppendFlowFileDataFilePtr(ffc->tail, ffd) == -1)
    {
        SCReturnInt(-1);
    }

    SCReturnInt(0);
}

/**
 *  \brief Alloc a new FlowFile
 *
 *  \param name character array containing the name (not a string)
 *  \param name_len length in bytes of the name
 *
 *  \retval new FlowFile object or NULL on error
 */
static FlowFile *FlowFileAlloc(uint8_t *name, uint16_t name_len) {
    FlowFile *new = SCMalloc(sizeof(FlowFile));
    if (new == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating mem");
        return NULL;
    }
    memset(new, 0, sizeof(FlowFile));

    new->fd = -1;

    new->name = SCMalloc(name_len);
    if (new->name == NULL) {
        SCFree(new);
        return NULL;
    }

    new->name_len = name_len;
    memcpy(new->name, name, name_len);

    return new;
}

static void FlowFileFree(FlowFile *ff) {
    if (ff == NULL)
        return;

    if (ff->fd != -1)
        close(ff->fd);

    if (ff->name != NULL)
        SCFree(ff->name);
    SCFree(ff);
}

void FlowFileContainerAdd(FlowFileContainer *ffc, FlowFile *ff) {
    if (ffc->head == NULL) {
        ffc->head = ffc->tail = ff;
    } else {
        ffc->tail->next = ff;
        ffc->tail = ff;
    }
}

/**
 *  \brief Open a new FlowFile
 *
 *  \param ffc flow container
 *  \param name filename character array
 *  \param name_len filename len
 *  \param data initial data
 *  \param data_len initial data len
 *
 *  \retval ff flowfile object
 *
 *  \note filename is not a string, so it's not nul terminated.
 */
FlowFile *FlowFileOpenFile(FlowFileContainer *ffc, uint8_t *name,
        uint16_t name_len, uint8_t *data, uint32_t data_len)
{
    SCEnter();

    //PrintRawDataFp(stdout, name, name_len);

    FlowFile *ff = FlowFileAlloc(name, name_len);
    if (ff == NULL) {
        SCReturnPtr(NULL, "FlowFile");
    }

    ff->state = FLOWFILE_STATE_OPENED;
    SCLogDebug("flowfile state transitioned to FLOWFILE_STATE_OPENED");

    FlowFileContainerAdd(ffc, ff);

    if (data != NULL) {
        //PrintRawDataFp(stdout, data, data_len);

        FlowFileData *ffd = FlowFileDataAlloc(data, data_len);
        if (ffd == NULL) {
            ff->state = FLOWFILE_STATE_ERROR;
            SCReturnPtr(NULL, "FlowFile");
        }

        /* append the data */
        if (FlowFileAppendFlowFileData(ffc, ffd) < 0) {
            ff->state = FLOWFILE_STATE_ERROR;
            FlowFileDataFree(ffd);
            SCReturnPtr(NULL, "FlowFile");
        }
    }

    SCReturnPtr(ff, "FlowFile");
}

static int FlowFileCloseFilePtr(FlowFile *ff, uint8_t *data,
        uint32_t data_len, uint8_t flags)
{
    SCEnter();

    if (ff == NULL) {
        SCReturnInt(-1);
    }

    if (ff->state != FLOWFILE_STATE_OPENED) {
        SCReturnInt(-1);
    }

    if (data != NULL) {
        //PrintRawDataFp(stdout, data, data_len);

        FlowFileData *ffd = FlowFileDataAlloc(data, data_len);
        if (ffd == NULL) {
            ff->state = FLOWFILE_STATE_ERROR;
            SCReturnInt(-1);
        }

        /* append the data */
        if (FlowFileAppendFlowFileDataFilePtr(ff, ffd) < 0) {
            ff->state = FLOWFILE_STATE_ERROR;
            FlowFileDataFree(ffd);
            SCReturnInt(-1);
        }
    }

    if (flags & FLOW_FILE_TRUNCATED) {
        ff->state = FLOWFILE_STATE_TRUNCATED;
        SCLogDebug("flowfile state transitioned to FLOWFILE_STATE_TRUNCATED");

        if (flags & FLOW_FILE_NOSTORE) {
            ff->store = -1;
        }
    } else {
        ff->state = FLOWFILE_STATE_CLOSED;
        SCLogDebug("flowfile state transitioned to FLOWFILE_STATE_CLOSED");
    }

    SCReturnInt(0);
}

/**
 *  \brief Close a FlowFile
 *
 *  \param ffc the container
 *  \param data final data if any
 *  \param data_len data len if any
 *  \param flags flags
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int FlowFileCloseFile(FlowFileContainer *ffc, uint8_t *data,
        uint32_t data_len, uint8_t flags)
{
    SCEnter();

    if (ffc == NULL || ffc->tail == NULL) {
        SCReturnInt(-1);
    }

    if (FlowFileCloseFilePtr(ffc->tail, data, data_len, flags) == -1) {
        SCReturnInt(-1);
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
int FlowFileAppendData(FlowFileContainer *ffc, uint8_t *data, uint32_t data_len) {
    SCEnter();

    if (ffc == NULL || ffc->tail == NULL || data == NULL || data_len == 0) {
        SCReturnInt(-1);
    }

    if (ffc->tail->state != FLOWFILE_STATE_OPENED) {
        if (ffc->tail->store == -1) {
            SCReturnInt(-2);
        }
        SCReturnInt(-1);
    }

    SCLogDebug("appending %"PRIu32" bytes", data_len);

    FlowFileData *ffd = FlowFileDataAlloc(data, data_len);
    if (ffd == NULL) {
        ffc->tail->state = FLOWFILE_STATE_ERROR;
        SCReturnInt(-1);
    }

    /* append the data */
    if (FlowFileAppendFlowFileData(ffc, ffd) < 0) {
        ffc->tail->state = FLOWFILE_STATE_ERROR;
        FlowFileDataFree(ffd);
        SCReturnInt(-1);
    }
    SCReturnInt(0);
}

/**
 *  \brief Tag a file for storing
 *
 *  \param ff The file to store
 */
int FlowFileStore(FlowFile *ff) {
    ff->store = 1;
    SCReturnInt(0);
}

/**
 *  \brief Set the TX id for a file
 *
 *  \param ff The file to store
 *  \param txid the tx id
 */
int FlowFileSetTx(FlowFile *ff, uint16_t txid) {
    ff->txid = txid;
    SCReturnInt(0);
}

/**
 *  \brief disable file storage for a flow
 *
 *  \param f *LOCKED* flow
 */
void FlowFileDisableStoring(Flow *f) {
    FlowFile *ptr = NULL;

    SCEnter();

    f->flags |= FLOW_FILE_NO_HANDLING;

    SCMutexLock(&f->files_m);
    if (f->files != NULL) {
        for (ptr = f->files->head; ptr != NULL; ptr = ptr->next) {
            if (ptr->state == FLOWFILE_STATE_OPENED) {
                ptr->state = FLOWFILE_STATE_CLOSED;
                SCLogDebug("flowfile state transitioned to FLOWFILE_STATE_CLOSED");
            }
        }
    }
    SCMutexUnlock(&f->files_m);
    SCReturn;
}

/**
 *  \brief disable file storing for files in a transaction
 *
 *  \param f flow
 *  \param tx_id transaction id
 */
void FlowFileDisableStoringForTransaction(struct Flow_ *f, uint16_t tx_id) {
    FlowFile *ptr = NULL;

    SCEnter();

    SCMutexLock(&f->files_m);
    if (f->files != NULL) {
        for (ptr = f->files->head; ptr != NULL; ptr = ptr->next) {
            if (ptr->state == FLOWFILE_STATE_OPENED && ptr->txid == tx_id) {
                if (ptr->store == 1) {
                    /* weird, already storing -- let it continue*/
                    SCLogDebug("file is already being stored");
                } else {
                    (void)FlowFileCloseFilePtr(ptr, NULL, 0,
                            (FLOW_FILE_TRUNCATED|FLOW_FILE_NOSTORE));
                }
            }
        }
    }
    SCMutexUnlock(&f->files_m);

    SCReturn;
}
