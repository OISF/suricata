/* Copyright (C) 2023-2024 Open Information Security Foundation
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

/** \file
 *
 *  \author Angelo Mirabella <angelo.mirabella@broadcom.com>
 *
 *  Library runmode.
 */

#ifndef SURICATA_RUNMODE_LIB_H
#define SURICATA_RUNMODE_LIB_H

#include "threadvars.h"

/** \brief register runmodes for suricata as a library */
void RunModeIdsLibRegister(void);

/** \brief runmode for live packet processing */
int RunModeIdsLibLive(void);

/** \brief runmode for offline packet processing (pcap files) */
int RunModeIdsLibOffline(void);

/** \brief runmode default mode (live) */
const char *RunModeLibGetDefaultMode(void);

/**
 * \brief Create ThreadVars for use by a user provided thread.
 *
 * Unlike other runmodes, this does not spawn a thread, as the threads
 * are controlled by the application using Suricata as a library.
 *
 * \return Pointer to allocated ThreadVars or NULL on failure
 */
ThreadVars *SCRunModeLibCreateThreadVars(void);

/** \brief start the "fake" worker.
 *
 *  This method performs all the initialization tasks.
 */
int RunModeSpawnWorker(void *);

/** \brief destroy a worker thread */
void RunModeDestroyWorker(void *);

#endif /* SURICATA_RUNMODE_LIB_H */
