/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __TM_THREADS_COMMON_H__
#define __TM_THREADS_COMMON_H__

/** \brief Thread Model Module id's.
 *
 *  \note anything added here should also be added to TmModuleTmmIdToString
 *        in tm-modules.c
 */
typedef enum {
    TMM_FLOWWORKER,
    TMM_DECODENFQ,
    TMM_VERDICTNFQ,
    TMM_RECEIVENFQ,
    TMM_RECEIVEPCAP,
    TMM_RECEIVEPCAPFILE,
    TMM_DECODEPCAP,
    TMM_DECODEPCAPFILE,
    TMM_RECEIVEPFRING,
    TMM_DECODEPFRING,
    TMM_RESPONDREJECT,
    TMM_DECODEIPFW,
    TMM_VERDICTIPFW,
    TMM_RECEIVEIPFW,
    TMM_RECEIVEERFFILE,
    TMM_DECODEERFFILE,
    TMM_RECEIVEERFDAG,
    TMM_DECODEERFDAG,
    TMM_RECEIVEAFP,
    TMM_DECODEAFP,
    TMM_RECEIVENETMAP,
    TMM_DECODENETMAP,
    TMM_ALERTPCAPINFO,
    TMM_RECEIVEMPIPE,
    TMM_DECODEMPIPE,
    TMM_RECEIVENAPATECH,
    TMM_DECODENAPATECH,
    TMM_STATSLOGGER,
    TMM_RECEIVENFLOG,
    TMM_DECODENFLOG,

    TMM_FLOWMANAGER,
    TMM_FLOWRECYCLER,
    TMM_DETECTLOADER,

    TMM_UNIXMANAGER,

    TMM_SIZE,
} TmmId;

/*Error codes for the thread modules*/
typedef enum {
    TM_ECODE_OK = 0,    /**< Thread module exits OK*/
    TM_ECODE_FAILED,    /**< Thread module exits due to failure*/
    TM_ECODE_DONE,    /**< Thread module task is finished*/
} TmEcode;

/* ThreadVars type */
enum {
    TVT_PPT,
    TVT_MGMT,
    TVT_CMD,
    TVT_MAX,
};

#endif /* __TM_THREADS_COMMON_H__ */

