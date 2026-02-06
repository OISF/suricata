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
 * \file
 * Lightweight indirection layer for capture-related callbacks.
 *
 * This module lets the capture implementation register small hooks that the
 * generic engine can invoke without hard dependencies. Two hooks are used:
 * - on-alerts: invoked when a packet produced alerts so capture can update
 *   per-input stats (e.g., deciding if a pcap should be deleted or kept).
 * - on-pseudo-created: invoked when the engine creates pseudo packets (e.g.,
 *   flow timeout or shutdown flush). This allows capture to retain references
 *   or track alert outcomes tied to those pseudo packets.
 */

#include "suricata-common.h"
#include "capture-hooks.h"

static CaptureOnPacketWithAlertsHook g_on_alerts_hook = NULL;
static CaptureOnPseudoPacketCreatedHook g_on_pseudo_created_hook = NULL;

void CaptureHooksSet(
        CaptureOnPacketWithAlertsHook on_alerts, CaptureOnPseudoPacketCreatedHook on_pseudo_created)
{
    g_on_alerts_hook = on_alerts;
    g_on_pseudo_created_hook = on_pseudo_created;
}

void CaptureHooksOnPacketWithAlerts(const Packet *p)
{
    if (g_on_alerts_hook != NULL) {
        g_on_alerts_hook(p);
    }
}

void CaptureHooksOnPseudoPacketCreated(Packet *p)
{
    if (g_on_pseudo_created_hook != NULL) {
        g_on_pseudo_created_hook(p);
    }
}
