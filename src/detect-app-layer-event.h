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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __DETECT_APP_LAYER_EVENT_H__
#define __DETECT_APP_LAYER_EVENT_H__

typedef struct DetectAppLayerEventData_ {
    AppProto alproto;
    uint8_t event_id;

    /* it's used to check if there are event set into the detect engine */
    bool needs_detctx;

    char *arg;
} DetectAppLayerEventData;

int DetectAppLayerEventPrepare(DetectEngineCtx *de_ctx, Signature *s);
void DetectAppLayerEventRegister(void);

#endif /* __DETECT_APP_LAYER_EVENT_H__ */
