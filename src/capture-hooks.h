/* Copyright (C) 2007-2025 Open Information Security Foundation
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
 * \file capture-hooks.h
 * Small hook interface for capture modules to react to events in the
 * generic engine without creating circular dependencies.
 */

#ifndef SURICATA_CAPTURE_HOOKS_H
#define SURICATA_CAPTURE_HOOKS_H

#include "suricata-common.h"

struct Packet_;
typedef struct Packet_ Packet;

typedef void (*CaptureOnPacketWithAlertsHook)(const Packet *p);
typedef void (*CaptureOnPseudoPacketCreatedHook)(Packet *p);

/* Register/clear hooks (called by capture implementations) */
void CaptureHooksSet(CaptureOnPacketWithAlertsHook on_alerts,
        CaptureOnPseudoPacketCreatedHook on_pseudo_created);

/* Invoke hooks (called from generic code, safe if unset) */
void CaptureHooksOnPacketWithAlerts(const Packet *p);
void CaptureHooksOnPseudoPacketCreated(Packet *p);

#endif /* SURICATA_CAPTURE_HOOKS_H */
