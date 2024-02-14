/* Copyright (C) 2014 Open Information Security Foundation
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
 * \author Giuseppe Longo <giuseppelng@gmail.com>
 */

#ifndef __SOURCE_NFLOG_H__
#define __SOURCE_NFLOG_H__

#ifdef HAVE_NFLOG
#include <libnetfilter_log/libnetfilter_log.h>
#include <libnfnetlink/libnfnetlink.h>
#endif /* HAVE_NFLOG */

#define NFLOG_GROUP_NAME_LENGTH 48
typedef struct NflogGroupConfig_
{
    /* nflog's group */
    uint16_t group;
    /* netlink buffer size */
    uint32_t nlbufsiz;
    /* netlink max buffer size */
    uint32_t nlbufsiz_max;
    /* max amount of logs in buffer*/
    uint32_t qthreshold;
    /* max time to push log buffer */
    uint32_t qtimeout;

    /* used to initialize livedev */
    char numgroup[NFLOG_GROUP_NAME_LENGTH];

    int nful_overrun_warned;

    void (*DerefFunc)(void *);
} NflogGroupConfig;

typedef struct NFLOGPacketVars_
{
    uint32_t mark;
    uint32_t ifi;
    uint32_t ifo;
    uint16_t hw_protocol;

} NFLOGPacketVars;

void TmModuleReceiveNFLOGRegister(void);
void TmModuleDecodeNFLOGRegister(void);

#endif /* __SOURCE_NFLOG_H__ */
