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
 * \author Endace Technology Limited, Jason Ish <jason.ish@endace.com>
 */

#ifndef __OUTPUT_H__
#define __OUTPUT_H__

#include "suricata.h"
#include "tm-threads.h"

#define DEFAULT_LOG_MODE_APPEND     "yes"
#define DEFAULT_LOG_FILETYPE        "regular"

#include "output-packet.h"
#include "output-tx.h"
#include "output-file.h"
#include "output-filedata.h"

typedef struct OutputModule_ {
    char *name;
    char *conf_name;
    char *parent_name;
    OutputCtx *(*InitFunc)(ConfNode *);
    OutputCtx *(*InitSubFunc)(ConfNode *, OutputCtx *parent_ctx);

    PacketLogger PacketLogFunc;
    PacketLogCondition PacketConditionFunc;
    TxLogger TxLogFunc;
    FileLogger FileLogFunc;
    FiledataLogger FiledataLogFunc;
    uint16_t alproto;

    TAILQ_ENTRY(OutputModule_) entries;
} OutputModule;

void OutputRegisterModule(char *, char *, OutputCtx *(*)(ConfNode *));

void OutputRegisterPacketModule(char *name, char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *),
    PacketLogger LogFunc, PacketLogCondition ConditionFunc);
void OutputRegisterPacketSubModule(const char *parent_name, char *name, char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *),
    PacketLogger LogFunc, PacketLogCondition ConditionFunc);

void OutputRegisterTxModule(char *name, char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), uint16_t alproto,
    TxLogger TxLogFunc);
void OutputRegisterTxSubModule(const char *parent_name, char *name, char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *parent_ctx), uint16_t alproto,
    TxLogger TxLogFunc);

void OutputRegisterFileModule(char *name, char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), FileLogger FileLogFunc);
void OutputRegisterFileSubModule(const char *parent_name, char *name, char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *), FileLogger FileLogFunc);

void OutputRegisterFiledataModule(char *name, char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *), FiledataLogger FiledataLogFunc);
void OutputRegisterFiledataSubModule(const char *parent_name, char *name, char *conf_name,
    OutputCtx *(*InitFunc)(ConfNode *, OutputCtx *), FiledataLogger FiledataLogFunc);

OutputModule *OutputGetModuleByConfName(char *name);
void OutputDeregisterAll(void);

#endif /* ! __OUTPUT_H__ */
