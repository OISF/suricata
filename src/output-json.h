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
 * \author Tom DeCanio <td@npulsetech.com>
 */

#ifndef __OUTPUT_JSON_H__
#define __OUTPUT_JSON_H__

#include "suricata-common.h"
#include "util-buffer.h"
#include "util-logopenfile.h"
#include "output.h"
#include "rust.h"

#include "app-layer-htp-xff.h"
#include "suricata-plugin.h"

void OutputJsonRegister(void);

enum OutputJsonLogDirection {
    LOG_DIR_PACKET = 0,
    LOG_DIR_FLOW,
    LOG_DIR_FLOW_TOCLIENT,
    LOG_DIR_FLOW_TOSERVER,
};

#define JSON_ADDR_LEN 46
#define JSON_PROTO_LEN 16

/* A struct to contain address info for rendering to JSON. */
typedef struct JsonAddrInfo_ {
    char src_ip[JSON_ADDR_LEN];
    char dst_ip[JSON_ADDR_LEN];
    Port sp;
    Port dp;
    char proto[JSON_PROTO_LEN];
} JsonAddrInfo;

extern const JsonAddrInfo json_addr_info_zero;

void JsonAddrInfoInit(const Packet *p, enum OutputJsonLogDirection dir,
        JsonAddrInfo *addr);

/* Suggested output buffer size */
#define JSON_OUTPUT_BUFFER_SIZE 65535

/* helper struct for OutputJSONMemBufferCallback */
typedef struct OutputJSONMemBufferWrapper_ {
    MemBuffer **buffer; /**< buffer to use & expand as needed */
    size_t expand_by;   /**< expand by this size */
} OutputJSONMemBufferWrapper;

typedef struct OutputJsonCommonSettings_ {
    bool include_metadata;
    bool include_community_id;
    bool include_ethernet;
    uint16_t community_id_seed;
} OutputJsonCommonSettings;

/*
 * Global configuration context data
 */
typedef struct OutputJsonCtx_ {
    LogFileCtx *file_ctx;
    enum LogFileType json_out;
    OutputJsonCommonSettings cfg;
    HttpXFFCfg *xff_cfg;
    SCEveFileType *plugin;
} OutputJsonCtx;

typedef struct OutputJsonThreadCtx_ {
    OutputJsonCtx *ctx;
    LogFileCtx *file_ctx;
    MemBuffer *buffer;
} OutputJsonThreadCtx;

json_t *SCJsonString(const char *val);

void CreateEveFlowId(JsonBuilder *js, const Flow *f);
void EveFileInfo(JsonBuilder *js, const File *file, const bool stored);
void EveTcpFlags(uint8_t flags, JsonBuilder *js);
void EvePacket(const Packet *p, JsonBuilder *js, unsigned long max_length);
JsonBuilder *CreateEveHeader(const Packet *p, enum OutputJsonLogDirection dir,
        const char *event_type, JsonAddrInfo *addr, OutputJsonCtx *eve_ctx);
JsonBuilder *CreateEveHeaderWithTxId(const Packet *p, enum OutputJsonLogDirection dir,
        const char *event_type, JsonAddrInfo *addr, uint64_t tx_id, OutputJsonCtx *eve_ctx);
int OutputJSONBuffer(json_t *js, LogFileCtx *file_ctx, MemBuffer **buffer);
int OutputJsonBuilderBuffer(JsonBuilder *js, OutputJsonThreadCtx *ctx);
OutputInitResult OutputJsonInitCtx(ConfNode *);

OutputInitResult OutputJsonLogInitSub(ConfNode *conf, OutputCtx *parent_ctx);
TmEcode JsonLogThreadInit(ThreadVars *t, const void *initdata, void **data);
TmEcode JsonLogThreadDeinit(ThreadVars *t, void *data);

void EveAddCommonOptions(const OutputJsonCommonSettings *cfg,
        const Packet *p, const Flow *f, JsonBuilder *js);
void EveAddMetadata(const Packet *p, const Flow *f, JsonBuilder *js);

int OutputJSONMemBufferCallback(const char *str, size_t size, void *data);

OutputJsonThreadCtx *CreateEveThreadCtx(ThreadVars *t, OutputJsonCtx *ctx);
void FreeEveThreadCtx(OutputJsonThreadCtx *ctx);

#endif /* __OUTPUT_JSON_H__ */
