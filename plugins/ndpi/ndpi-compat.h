/* Copyright (C) 2025 Open Information Security Foundation
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
 * Compatibility layer over the parts of the nDPI API that differ between
 * nDPI 4.12, 5.0 and 6.0, selected at compile time from NDPI_MAJOR so
 * that ndpi.c stays version agnostic.
 */

#ifndef SURICATA_NDPI_COMPAT_H
#define SURICATA_NDPI_COMPAT_H

#include <stdbool.h>
#include <stdint.h>

#include "ndpi_api.h"

#if NDPI_MAJOR < 4 || (NDPI_MAJOR == 4 && NDPI_MINOR < 12)
#error "the nDPI plugin requires nDPI 4.12 or later"
#endif

/**
 * \brief Allocate a detection module.
 *
 * nDPI 6.0 requires the embedding application to declare under which
 * license it uses the library. Not-for-profit use enables every dissector.
 */
static inline struct ndpi_detection_module_struct *NdpiCompatInitModule(
        struct ndpi_global_context *g_ctx)
{
#if NDPI_MAJOR >= 6
    return ndpi_init_detection_module(g_ctx, NDPI_LICENSE_NOT_FOR_PROFIT_LGPL);
#else
    return ndpi_init_detection_module(g_ctx);
#endif
}

/* nDPI 4.x needs every protocol enabled explicitly before finalization,
 * later releases enable them by default and removed the bitmask. */
static inline void NdpiCompatEnableAllProtocols(struct ndpi_detection_module_struct *ndpi)
{
#if NDPI_MAJOR < 5
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi, &all);
#else
    (void)ndpi;
#endif
}

/* Whether nDPI reached a final classification for the flow. Once it has,
 * the plugin stops feeding it packets and the keywords start matching.
 *
 * On nDPI 5.0 and later NDPI_STATE_CLASSIFIED with no extra dissection
 * pending is final, as in nDPI's ndpiReader. NDPI_STATE_MONITORING is
 * treated as final too: the classification will not change and nDPI
 * would only extract more metadata, so stopping there bounds the per
 * packet cost at the expense of that metadata. */
static inline bool NdpiCompatClassificationFinal(struct ndpi_detection_module_struct *ndpi,
        struct ndpi_flow_struct *flow, const ndpi_protocol *proto)
{
#if NDPI_MAJOR >= 5
    (void)ndpi;
    if (proto->state == NDPI_STATE_MONITORING)
        return true;
    return proto->state == NDPI_STATE_CLASSIFIED && flow->extra_packets_func == NULL;
#else
    return ndpi_is_protocol_detected(*proto) != 0 && !ndpi_is_proto_unknown(proto->proto) &&
           !ndpi_extra_dissection_possible(ndpi, flow);
#endif
}

/* Whether nDPI has no classification for the flow at all, in which case
 * giving up on it goes through ndpi_detection_giveup() for a guess. */
static inline bool NdpiCompatIsUnclassified(const ndpi_protocol *proto)
{
#if NDPI_MAJOR >= 5
    return proto->state != NDPI_STATE_CLASSIFIED && proto->state != NDPI_STATE_MONITORING;
#else
    return ndpi_is_protocol_detected(*proto) == 0;
#endif
}

/* nDPI 5.0 dropped the output argument telling whether the protocol was
 * guessed, the flow now carries it in protocol_was_guessed. */
static inline ndpi_protocol NdpiCompatGiveup(
        struct ndpi_detection_module_struct *ndpi, struct ndpi_flow_struct *flow)
{
#if NDPI_MAJOR >= 5
    return ndpi_detection_giveup(ndpi, flow);
#else
    uint8_t protocol_was_guessed;
    return ndpi_detection_giveup(ndpi, flow, &protocol_was_guessed);
#endif
}

#endif /* SURICATA_NDPI_COMPAT_H */
