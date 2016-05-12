/* Copyright (C) 2015 Open Information Security Foundation
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
 * DO NOT EDIT. THIS FILE IS AUTO-GENERATED.
 */

#include "suricata-common.h"

#include "util-crypt.h"

#include "app-layer-dnp3.h"
#include "app-layer-dnp3-objects.h"

void OutputJsonDNP3SetItem(json_t *js, DNP3Object *object,
    DNP3Point *point)
{

    switch (DNP3_OBJECT_CODE(object->group, object->variation)) {
        case DNP3_OBJECT_CODE(1, 1): {
            DNP3ObjectG1V1 *data = point->data;
            json_object_set_new(js, "state",
                json_integer(data->state));
            break;
        }
        case DNP3_OBJECT_CODE(1, 2): {
            DNP3ObjectG1V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "chatter_filter",
                json_integer(data->chatter_filter));
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
            json_object_set_new(js, "state",
                json_integer(data->state));
            break;
        }
        case DNP3_OBJECT_CODE(2, 1): {
            DNP3ObjectG2V1 *data = point->data;
            json_object_set_new(js, "state",
                json_integer(data->state));
            break;
        }
        case DNP3_OBJECT_CODE(2, 2): {
            DNP3ObjectG2V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "chatter_filter",
                json_integer(data->chatter_filter));
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
            json_object_set_new(js, "state",
                json_integer(data->state));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(2, 3): {
            DNP3ObjectG2V3 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "chatter_filter",
                json_integer(data->chatter_filter));
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
            json_object_set_new(js, "state",
                json_integer(data->state));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(3, 1): {
            DNP3ObjectG3V1 *data = point->data;
            json_object_set_new(js, "state",
                json_integer(data->state));
            break;
        }
        case DNP3_OBJECT_CODE(3, 2): {
            DNP3ObjectG3V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "chatter_filter",
                json_integer(data->chatter_filter));
            json_object_set_new(js, "state",
                json_integer(data->state));
            break;
        }
        case DNP3_OBJECT_CODE(4, 1): {
            DNP3ObjectG4V1 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "chatter_filter",
                json_integer(data->chatter_filter));
            json_object_set_new(js, "state",
                json_integer(data->state));
            break;
        }
        case DNP3_OBJECT_CODE(4, 2): {
            DNP3ObjectG4V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "chatter_filter",
                json_integer(data->chatter_filter));
            json_object_set_new(js, "state",
                json_integer(data->state));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(4, 3): {
            DNP3ObjectG4V3 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "chatter_filter",
                json_integer(data->chatter_filter));
            json_object_set_new(js, "state",
                json_integer(data->state));
            json_object_set_new(js, "relative_time_ms",
                json_integer(data->relative_time_ms));
            break;
        }
        case DNP3_OBJECT_CODE(10, 1): {
            DNP3ObjectG10V1 *data = point->data;
            json_object_set_new(js, "state",
                json_integer(data->state));
            break;
        }
        case DNP3_OBJECT_CODE(10, 2): {
            DNP3ObjectG10V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "state",
                json_integer(data->state));
            break;
        }
        case DNP3_OBJECT_CODE(11, 1): {
            DNP3ObjectG11V1 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "state",
                json_integer(data->state));
            break;
        }
        case DNP3_OBJECT_CODE(11, 2): {
            DNP3ObjectG11V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "state",
                json_integer(data->state));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(12, 1): {
            DNP3ObjectG12V1 *data = point->data;
            json_object_set_new(js, "opype",
                json_integer(data->opype));
            json_object_set_new(js, "qu",
                json_integer(data->qu));
            json_object_set_new(js, "cr",
                json_integer(data->cr));
            json_object_set_new(js, "tcc",
                json_integer(data->tcc));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "ontime",
                json_integer(data->ontime));
            json_object_set_new(js, "offtime",
                json_integer(data->offtime));
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
            break;
        }
        case DNP3_OBJECT_CODE(12, 2): {
            DNP3ObjectG12V2 *data = point->data;
            json_object_set_new(js, "opype",
                json_integer(data->opype));
            json_object_set_new(js, "qu",
                json_integer(data->qu));
            json_object_set_new(js, "cr",
                json_integer(data->cr));
            json_object_set_new(js, "tcc",
                json_integer(data->tcc));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "ontime",
                json_integer(data->ontime));
            json_object_set_new(js, "offtime",
                json_integer(data->offtime));
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
            break;
        }
        case DNP3_OBJECT_CODE(12, 3): {
            DNP3ObjectG12V3 *data = point->data;
            json_object_set_new(js, "point",
                json_integer(data->point));
            break;
        }
        case DNP3_OBJECT_CODE(13, 1): {
            DNP3ObjectG13V1 *data = point->data;
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            json_object_set_new(js, "commanded_state",
                json_integer(data->commanded_state));
            break;
        }
        case DNP3_OBJECT_CODE(13, 2): {
            DNP3ObjectG13V2 *data = point->data;
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            json_object_set_new(js, "commanded_state",
                json_integer(data->commanded_state));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(20, 1): {
            DNP3ObjectG20V1 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(20, 2): {
            DNP3ObjectG20V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(20, 3): {
            DNP3ObjectG20V3 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(20, 4): {
            DNP3ObjectG20V4 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(20, 5): {
            DNP3ObjectG20V5 *data = point->data;
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(20, 6): {
            DNP3ObjectG20V6 *data = point->data;
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(20, 7): {
            DNP3ObjectG20V7 *data = point->data;
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(20, 8): {
            DNP3ObjectG20V8 *data = point->data;
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(21, 1): {
            DNP3ObjectG21V1 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(21, 2): {
            DNP3ObjectG21V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(21, 3): {
            DNP3ObjectG21V3 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(21, 4): {
            DNP3ObjectG21V4 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(21, 5): {
            DNP3ObjectG21V5 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(21, 6): {
            DNP3ObjectG21V6 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(21, 7): {
            DNP3ObjectG21V7 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(21, 8): {
            DNP3ObjectG21V8 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(21, 9): {
            DNP3ObjectG21V9 *data = point->data;
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(21, 10): {
            DNP3ObjectG21V10 *data = point->data;
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(21, 11): {
            DNP3ObjectG21V11 *data = point->data;
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(21, 12): {
            DNP3ObjectG21V12 *data = point->data;
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(22, 1): {
            DNP3ObjectG22V1 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(22, 2): {
            DNP3ObjectG22V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(22, 3): {
            DNP3ObjectG22V3 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(22, 4): {
            DNP3ObjectG22V4 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(22, 5): {
            DNP3ObjectG22V5 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(22, 6): {
            DNP3ObjectG22V6 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(22, 7): {
            DNP3ObjectG22V7 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(22, 8): {
            DNP3ObjectG22V8 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(23, 1): {
            DNP3ObjectG23V1 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(23, 2): {
            DNP3ObjectG23V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(23, 3): {
            DNP3ObjectG23V3 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(23, 4): {
            DNP3ObjectG23V4 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            break;
        }
        case DNP3_OBJECT_CODE(23, 5): {
            DNP3ObjectG23V5 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(23, 6): {
            DNP3ObjectG23V6 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(23, 7): {
            DNP3ObjectG23V7 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(23, 8): {
            DNP3ObjectG23V8 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(data->rollover));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(30, 1): {
            DNP3ObjectG30V1 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(30, 2): {
            DNP3ObjectG30V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(30, 3): {
            DNP3ObjectG30V3 *data = point->data;
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(30, 4): {
            DNP3ObjectG30V4 *data = point->data;
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(30, 5): {
            DNP3ObjectG30V5 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(30, 6): {
            DNP3ObjectG30V6 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(31, 1): {
            DNP3ObjectG31V1 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(31, 2): {
            DNP3ObjectG31V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(31, 3): {
            DNP3ObjectG31V3 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(31, 4): {
            DNP3ObjectG31V4 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(31, 5): {
            DNP3ObjectG31V5 *data = point->data;
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(31, 6): {
            DNP3ObjectG31V6 *data = point->data;
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(31, 7): {
            DNP3ObjectG31V7 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(31, 8): {
            DNP3ObjectG31V8 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(32, 1): {
            DNP3ObjectG32V1 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(32, 2): {
            DNP3ObjectG32V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(32, 3): {
            DNP3ObjectG32V3 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(32, 4): {
            DNP3ObjectG32V4 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(32, 5): {
            DNP3ObjectG32V5 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(32, 6): {
            DNP3ObjectG32V6 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(32, 7): {
            DNP3ObjectG32V7 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(32, 8): {
            DNP3ObjectG32V8 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(33, 1): {
            DNP3ObjectG33V1 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(33, 2): {
            DNP3ObjectG33V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(33, 3): {
            DNP3ObjectG33V3 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(33, 4): {
            DNP3ObjectG33V4 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(33, 5): {
            DNP3ObjectG33V5 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(33, 6): {
            DNP3ObjectG33V6 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(33, 7): {
            DNP3ObjectG33V7 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(33, 8): {
            DNP3ObjectG33V8 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(34, 1): {
            DNP3ObjectG34V1 *data = point->data;
            json_object_set_new(js, "deadband_value",
                json_integer(data->deadband_value));
            break;
        }
        case DNP3_OBJECT_CODE(34, 2): {
            DNP3ObjectG34V2 *data = point->data;
            json_object_set_new(js, "deadband_value",
                json_integer(data->deadband_value));
            break;
        }
        case DNP3_OBJECT_CODE(34, 3): {
            DNP3ObjectG34V3 *data = point->data;
            json_object_set_new(js, "deadband_value",
                json_real(data->deadband_value));
            break;
        }
        case DNP3_OBJECT_CODE(40, 1): {
            DNP3ObjectG40V1 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(40, 2): {
            DNP3ObjectG40V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(40, 3): {
            DNP3ObjectG40V3 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(40, 4): {
            DNP3ObjectG40V4 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(41, 1): {
            DNP3ObjectG41V1 *data = point->data;
            json_object_set_new(js, "value",
                json_integer(data->value));
            json_object_set_new(js, "control_status",
                json_integer(data->control_status));
            break;
        }
        case DNP3_OBJECT_CODE(41, 2): {
            DNP3ObjectG41V2 *data = point->data;
            json_object_set_new(js, "value",
                json_integer(data->value));
            json_object_set_new(js, "control_status",
                json_integer(data->control_status));
            break;
        }
        case DNP3_OBJECT_CODE(41, 3): {
            DNP3ObjectG41V3 *data = point->data;
            json_object_set_new(js, "value",
                json_real(data->value));
            json_object_set_new(js, "control_status",
                json_integer(data->control_status));
            break;
        }
        case DNP3_OBJECT_CODE(41, 4): {
            DNP3ObjectG41V4 *data = point->data;
            json_object_set_new(js, "value",
                json_real(data->value));
            json_object_set_new(js, "control_status",
                json_integer(data->control_status));
            break;
        }
        case DNP3_OBJECT_CODE(42, 1): {
            DNP3ObjectG42V1 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(42, 2): {
            DNP3ObjectG42V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(42, 3): {
            DNP3ObjectG42V3 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(42, 4): {
            DNP3ObjectG42V4 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_integer(data->value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(42, 5): {
            DNP3ObjectG42V5 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(42, 6): {
            DNP3ObjectG42V6 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(42, 7): {
            DNP3ObjectG42V7 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(42, 8): {
            DNP3ObjectG42V8 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(data->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(data->reference_err));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "value",
                json_real(data->value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(43, 1): {
            DNP3ObjectG43V1 *data = point->data;
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "commanded_value",
                json_integer(data->commanded_value));
            break;
        }
        case DNP3_OBJECT_CODE(43, 2): {
            DNP3ObjectG43V2 *data = point->data;
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "commanded_value",
                json_integer(data->commanded_value));
            break;
        }
        case DNP3_OBJECT_CODE(43, 3): {
            DNP3ObjectG43V3 *data = point->data;
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "commanded_value",
                json_integer(data->commanded_value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(43, 4): {
            DNP3ObjectG43V4 *data = point->data;
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "commanded_value",
                json_integer(data->commanded_value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(43, 5): {
            DNP3ObjectG43V5 *data = point->data;
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "commanded_value",
                json_real(data->commanded_value));
            break;
        }
        case DNP3_OBJECT_CODE(43, 6): {
            DNP3ObjectG43V6 *data = point->data;
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "commanded_value",
                json_real(data->commanded_value));
            break;
        }
        case DNP3_OBJECT_CODE(43, 7): {
            DNP3ObjectG43V7 *data = point->data;
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "commanded_value",
                json_real(data->commanded_value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(43, 8): {
            DNP3ObjectG43V8 *data = point->data;
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "commanded_value",
                json_real(data->commanded_value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(50, 1): {
            DNP3ObjectG50V1 *data = point->data;
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(50, 2): {
            DNP3ObjectG50V2 *data = point->data;
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            json_object_set_new(js, "interval",
                json_integer(data->interval));
            break;
        }
        case DNP3_OBJECT_CODE(50, 3): {
            DNP3ObjectG50V3 *data = point->data;
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(50, 4): {
            DNP3ObjectG50V4 *data = point->data;
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            json_object_set_new(js, "interval_count",
                json_integer(data->interval_count));
            json_object_set_new(js, "interval_units",
                json_integer(data->interval_units));
            break;
        }
        case DNP3_OBJECT_CODE(51, 1): {
            DNP3ObjectG51V1 *data = point->data;
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(51, 2): {
            DNP3ObjectG51V2 *data = point->data;
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(52, 1): {
            DNP3ObjectG52V1 *data = point->data;
            json_object_set_new(js, "delay_secs",
                json_integer(data->delay_secs));
            break;
        }
        case DNP3_OBJECT_CODE(52, 2): {
            DNP3ObjectG52V2 *data = point->data;
            json_object_set_new(js, "delay_ms",
                json_integer(data->delay_ms));
            break;
        }
        case DNP3_OBJECT_CODE(70, 1): {
            DNP3ObjectG70V1 *data = point->data;
            json_object_set_new(js, "filename_size",
                json_integer(data->filename_size));
            json_object_set_new(js, "filetype_code",
                json_integer(data->filetype_code));
            json_object_set_new(js, "attribute_code",
                json_integer(data->attribute_code));
            json_object_set_new(js, "start_record",
                json_integer(data->start_record));
            json_object_set_new(js, "end_record",
                json_integer(data->end_record));
            json_object_set_new(js, "file_size",
                json_integer(data->file_size));
            json_object_set_new(js, "created_timestamp",
                json_integer(data->created_timestamp));
            json_object_set_new(js, "permission",
                json_integer(data->permission));
            json_object_set_new(js, "file_id",
                json_integer(data->file_id));
            json_object_set_new(js, "owner_id",
                json_integer(data->owner_id));
            json_object_set_new(js, "group_id",
                json_integer(data->group_id));
            json_object_set_new(js, "file_function_code",
                json_integer(data->file_function_code));
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            if (data->filename_size > 0) {
                /* First create a null terminated string as not all versions
                 * of jansson have json_stringn. */
                char tmpbuf[data->filename_size + 1];
                memcpy(tmpbuf, data->filename, data->filename_size);
                tmpbuf[data->filename_size] = '\0';
                json_object_set_new(js, "filename", json_string(tmpbuf));
            } else {
                json_object_set_new(js, "filename", json_string(""));
            }
            json_object_set_new(js, "data_size",
                json_integer(data->data_size));
            if (data->data_size > 0) {
                /* First create a null terminated string as not all versions
                 * of jansson have json_stringn. */
                char tmpbuf[data->data_size + 1];
                memcpy(tmpbuf, data->data, data->data_size);
                tmpbuf[data->data_size] = '\0';
                json_object_set_new(js, "data", json_string(tmpbuf));
            } else {
                json_object_set_new(js, "data", json_string(""));
            }
            break;
        }
        case DNP3_OBJECT_CODE(70, 2): {
            DNP3ObjectG70V2 *data = point->data;
            json_object_set_new(js, "username_offset",
                json_integer(data->username_offset));
            json_object_set_new(js, "username_size",
                json_integer(data->username_size));
            json_object_set_new(js, "password_offset",
                json_integer(data->password_offset));
            json_object_set_new(js, "password_size",
                json_integer(data->password_size));
            json_object_set_new(js, "authentication_key",
                json_integer(data->authentication_key));
            if (data->username_size > 0) {
                /* First create a null terminated string as not all versions
                 * of jansson have json_stringn. */
                char tmpbuf[data->username_size + 1];
                memcpy(tmpbuf, data->username, data->username_size);
                tmpbuf[data->username_size] = '\0';
                json_object_set_new(js, "username", json_string(tmpbuf));
            } else {
                json_object_set_new(js, "username", json_string(""));
            }
            if (data->password_size > 0) {
                /* First create a null terminated string as not all versions
                 * of jansson have json_stringn. */
                char tmpbuf[data->password_size + 1];
                memcpy(tmpbuf, data->password, data->password_size);
                tmpbuf[data->password_size] = '\0';
                json_object_set_new(js, "password", json_string(tmpbuf));
            } else {
                json_object_set_new(js, "password", json_string(""));
            }
            break;
        }
        case DNP3_OBJECT_CODE(70, 3): {
            DNP3ObjectG70V3 *data = point->data;
            json_object_set_new(js, "filename_offset",
                json_integer(data->filename_offset));
            json_object_set_new(js, "filename_size",
                json_integer(data->filename_size));
            json_object_set_new(js, "created",
                json_integer(data->created));
            json_object_set_new(js, "permissions",
                json_integer(data->permissions));
            json_object_set_new(js, "authentication_key",
                json_integer(data->authentication_key));
            json_object_set_new(js, "file_size",
                json_integer(data->file_size));
            json_object_set_new(js, "operational_mode",
                json_integer(data->operational_mode));
            json_object_set_new(js, "maximum_block_size",
                json_integer(data->maximum_block_size));
            json_object_set_new(js, "request_id",
                json_integer(data->request_id));
            if (data->filename_size > 0) {
                /* First create a null terminated string as not all versions
                 * of jansson have json_stringn. */
                char tmpbuf[data->filename_size + 1];
                memcpy(tmpbuf, data->filename, data->filename_size);
                tmpbuf[data->filename_size] = '\0';
                json_object_set_new(js, "filename", json_string(tmpbuf));
            } else {
                json_object_set_new(js, "filename", json_string(""));
            }
            break;
        }
        case DNP3_OBJECT_CODE(70, 4): {
            DNP3ObjectG70V4 *data = point->data;
            json_object_set_new(js, "file_handle",
                json_integer(data->file_handle));
            json_object_set_new(js, "file_size",
                json_integer(data->file_size));
            json_object_set_new(js, "maximum_block_size",
                json_integer(data->maximum_block_size));
            json_object_set_new(js, "request_id",
                json_integer(data->request_id));
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            if (data->optional_text_len > 0) {
                /* First create a null terminated string as not all versions
                 * of jansson have json_stringn. */
                char tmpbuf[data->optional_text_len + 1];
                memcpy(tmpbuf, data->optional_text, data->optional_text_len);
                tmpbuf[data->optional_text_len] = '\0';
                json_object_set_new(js, "optional_text", json_string(tmpbuf));
            } else {
                json_object_set_new(js, "optional_text", json_string(""));
            }
            break;
        }
        case DNP3_OBJECT_CODE(70, 5): {
            DNP3ObjectG70V5 *data = point->data;
            json_object_set_new(js, "file_handle",
                json_integer(data->file_handle));
            json_object_set_new(js, "block_number",
                json_integer(data->block_number));
            if (data->file_data_len > 0) {
                /* First create a null terminated string as not all versions
                 * of jansson have json_stringn. */
                char tmpbuf[data->file_data_len + 1];
                memcpy(tmpbuf, data->file_data, data->file_data_len);
                tmpbuf[data->file_data_len] = '\0';
                json_object_set_new(js, "file_data", json_string(tmpbuf));
            } else {
                json_object_set_new(js, "file_data", json_string(""));
            }
            break;
        }
        case DNP3_OBJECT_CODE(70, 6): {
            DNP3ObjectG70V6 *data = point->data;
            json_object_set_new(js, "file_handle",
                json_integer(data->file_handle));
            json_object_set_new(js, "block_number",
                json_integer(data->block_number));
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            if (data->optional_text_len > 0) {
                /* First create a null terminated string as not all versions
                 * of jansson have json_stringn. */
                char tmpbuf[data->optional_text_len + 1];
                memcpy(tmpbuf, data->optional_text, data->optional_text_len);
                tmpbuf[data->optional_text_len] = '\0';
                json_object_set_new(js, "optional_text", json_string(tmpbuf));
            } else {
                json_object_set_new(js, "optional_text", json_string(""));
            }
            break;
        }
        case DNP3_OBJECT_CODE(70, 7): {
            DNP3ObjectG70V7 *data = point->data;
            json_object_set_new(js, "filename_offset",
                json_integer(data->filename_offset));
            json_object_set_new(js, "filename_size",
                json_integer(data->filename_size));
            json_object_set_new(js, "file_type",
                json_integer(data->file_type));
            json_object_set_new(js, "file_size",
                json_integer(data->file_size));
            json_object_set_new(js, "created_timestamp",
                json_integer(data->created_timestamp));
            json_object_set_new(js, "permissions",
                json_integer(data->permissions));
            json_object_set_new(js, "request_id",
                json_integer(data->request_id));
            if (data->filename_size > 0) {
                /* First create a null terminated string as not all versions
                 * of jansson have json_stringn. */
                char tmpbuf[data->filename_size + 1];
                memcpy(tmpbuf, data->filename, data->filename_size);
                tmpbuf[data->filename_size] = '\0';
                json_object_set_new(js, "filename", json_string(tmpbuf));
            } else {
                json_object_set_new(js, "filename", json_string(""));
            }
            break;
        }
        case DNP3_OBJECT_CODE(70, 8): {
            DNP3ObjectG70V8 *data = point->data;
            if (data->file_specification_len > 0) {
                /* First create a null terminated string as not all versions
                 * of jansson have json_stringn. */
                char tmpbuf[data->file_specification_len + 1];
                memcpy(tmpbuf, data->file_specification, data->file_specification_len);
                tmpbuf[data->file_specification_len] = '\0';
                json_object_set_new(js, "file_specification", json_string(tmpbuf));
            } else {
                json_object_set_new(js, "file_specification", json_string(""));
            }
            break;
        }
        case DNP3_OBJECT_CODE(80, 1): {
            DNP3ObjectG80V1 *data = point->data;
            json_object_set_new(js, "state",
                json_integer(data->state));
            break;
        }
        case DNP3_OBJECT_CODE(81, 1): {
            DNP3ObjectG81V1 *data = point->data;
            json_object_set_new(js, "fill_percentage",
                json_integer(data->fill_percentage));
            json_object_set_new(js, "overflow_state",
                json_integer(data->overflow_state));
            json_object_set_new(js, "group",
                json_integer(data->group));
            json_object_set_new(js, "variation",
                json_integer(data->variation));
            break;
        }
        case DNP3_OBJECT_CODE(83, 1): {
            DNP3ObjectG83V1 *data = point->data;
            json_object_set_new(js, "data->vendor_code", json_string(data->vendor_code));
            json_object_set_new(js, "object_id",
                json_integer(data->object_id));
            json_object_set_new(js, "length",
                json_integer(data->length));
            unsigned long data_objects_b64_len = data->length * 2;
            uint8_t data_objects_b64[data_objects_b64_len];
            Base64Encode(data->data_objects, data->length,
                data_objects_b64, &data_objects_b64_len);
            json_object_set_new(js, "data->data_objects",
                json_string((char *)data_objects_b64));
            break;
        }
        case DNP3_OBJECT_CODE(86, 2): {
            DNP3ObjectG86V2 *data = point->data;
            json_object_set_new(js, "rd",
                json_integer(data->rd));
            json_object_set_new(js, "wr",
                json_integer(data->wr));
            json_object_set_new(js, "st",
                json_integer(data->st));
            json_object_set_new(js, "ev",
                json_integer(data->ev));
            json_object_set_new(js, "df",
                json_integer(data->df));
            json_object_set_new(js, "padding0",
                json_integer(data->padding0));
            json_object_set_new(js, "padding1",
                json_integer(data->padding1));
            json_object_set_new(js, "padding2",
                json_integer(data->padding2));
            break;
        }
        case DNP3_OBJECT_CODE(102, 1): {
            DNP3ObjectG102V1 *data = point->data;
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(120, 1): {
            DNP3ObjectG120V1 *data = point->data;
            json_object_set_new(js, "csq",
                json_integer(data->csq));
            json_object_set_new(js, "usr",
                json_integer(data->usr));
            json_object_set_new(js, "mal",
                json_integer(data->mal));
            json_object_set_new(js, "reason",
                json_integer(data->reason));
            unsigned long challenge_data_b64_len = data->challenge_data_len * 2;
            uint8_t challenge_data_b64[challenge_data_b64_len];
            Base64Encode(data->challenge_data, data->challenge_data_len,
                challenge_data_b64, &challenge_data_b64_len);
            json_object_set_new(js, "data->challenge_data",
                json_string((char *)challenge_data_b64));
            break;
        }
        case DNP3_OBJECT_CODE(120, 2): {
            DNP3ObjectG120V2 *data = point->data;
            json_object_set_new(js, "csq",
                json_integer(data->csq));
            json_object_set_new(js, "usr",
                json_integer(data->usr));
            unsigned long mac_value_b64_len = data->mac_value_len * 2;
            uint8_t mac_value_b64[mac_value_b64_len];
            Base64Encode(data->mac_value, data->mac_value_len,
                mac_value_b64, &mac_value_b64_len);
            json_object_set_new(js, "data->mac_value",
                json_string((char *)mac_value_b64));
            break;
        }
        case DNP3_OBJECT_CODE(120, 3): {
            DNP3ObjectG120V3 *data = point->data;
            json_object_set_new(js, "csq",
                json_integer(data->csq));
            json_object_set_new(js, "user_number",
                json_integer(data->user_number));
            break;
        }
        case DNP3_OBJECT_CODE(120, 4): {
            DNP3ObjectG120V4 *data = point->data;
            json_object_set_new(js, "user_number",
                json_integer(data->user_number));
            break;
        }
        case DNP3_OBJECT_CODE(120, 5): {
            DNP3ObjectG120V5 *data = point->data;
            json_object_set_new(js, "ksq",
                json_integer(data->ksq));
            json_object_set_new(js, "user_number",
                json_integer(data->user_number));
            json_object_set_new(js, "key_wrap_alg",
                json_integer(data->key_wrap_alg));
            json_object_set_new(js, "key_status",
                json_integer(data->key_status));
            json_object_set_new(js, "mal",
                json_integer(data->mal));
            json_object_set_new(js, "challenge_data_len",
                json_integer(data->challenge_data_len));
            unsigned long challenge_data_b64_len = data->challenge_data_len * 2;
            uint8_t challenge_data_b64[challenge_data_b64_len];
            Base64Encode(data->challenge_data, data->challenge_data_len,
                challenge_data_b64, &challenge_data_b64_len);
            json_object_set_new(js, "data->challenge_data",
                json_string((char *)challenge_data_b64));
            unsigned long mac_value_b64_len = data->mac_value_len * 2;
            uint8_t mac_value_b64[mac_value_b64_len];
            Base64Encode(data->mac_value, data->mac_value_len,
                mac_value_b64, &mac_value_b64_len);
            json_object_set_new(js, "data->mac_value",
                json_string((char *)mac_value_b64));
            break;
        }
        case DNP3_OBJECT_CODE(120, 6): {
            DNP3ObjectG120V6 *data = point->data;
            json_object_set_new(js, "ksq",
                json_integer(data->ksq));
            json_object_set_new(js, "usr",
                json_integer(data->usr));
            unsigned long wrapped_key_data_b64_len = data->wrapped_key_data_len * 2;
            uint8_t wrapped_key_data_b64[wrapped_key_data_b64_len];
            Base64Encode(data->wrapped_key_data, data->wrapped_key_data_len,
                wrapped_key_data_b64, &wrapped_key_data_b64_len);
            json_object_set_new(js, "data->wrapped_key_data",
                json_string((char *)wrapped_key_data_b64));
            break;
        }
        case DNP3_OBJECT_CODE(120, 7): {
            DNP3ObjectG120V7 *data = point->data;
            json_object_set_new(js, "sequence_number",
                json_integer(data->sequence_number));
            json_object_set_new(js, "usr",
                json_integer(data->usr));
            json_object_set_new(js, "association_id",
                json_integer(data->association_id));
            json_object_set_new(js, "error_code",
                json_integer(data->error_code));
            json_object_set_new(js, "time_of_error",
                json_integer(data->time_of_error));
            if (data->error_text_len > 0) {
                /* First create a null terminated string as not all versions
                 * of jansson have json_stringn. */
                char tmpbuf[data->error_text_len + 1];
                memcpy(tmpbuf, data->error_text, data->error_text_len);
                tmpbuf[data->error_text_len] = '\0';
                json_object_set_new(js, "error_text", json_string(tmpbuf));
            } else {
                json_object_set_new(js, "error_text", json_string(""));
            }
            break;
        }
        case DNP3_OBJECT_CODE(120, 8): {
            DNP3ObjectG120V8 *data = point->data;
            json_object_set_new(js, "key_change_method",
                json_integer(data->key_change_method));
            json_object_set_new(js, "certificate_type",
                json_integer(data->certificate_type));
            unsigned long certificate_b64_len = data->certificate_len * 2;
            uint8_t certificate_b64[certificate_b64_len];
            Base64Encode(data->certificate, data->certificate_len,
                certificate_b64, &certificate_b64_len);
            json_object_set_new(js, "data->certificate",
                json_string((char *)certificate_b64));
            break;
        }
        case DNP3_OBJECT_CODE(120, 9): {
            DNP3ObjectG120V9 *data = point->data;
            unsigned long mac_value_b64_len = data->mac_value_len * 2;
            uint8_t mac_value_b64[mac_value_b64_len];
            Base64Encode(data->mac_value, data->mac_value_len,
                mac_value_b64, &mac_value_b64_len);
            json_object_set_new(js, "data->mac_value",
                json_string((char *)mac_value_b64));
            break;
        }
        case DNP3_OBJECT_CODE(120, 10): {
            DNP3ObjectG120V10 *data = point->data;
            json_object_set_new(js, "key_change_method",
                json_integer(data->key_change_method));
            json_object_set_new(js, "operation",
                json_integer(data->operation));
            json_object_set_new(js, "scs",
                json_integer(data->scs));
            json_object_set_new(js, "user_role",
                json_integer(data->user_role));
            json_object_set_new(js, "user_role_expiry_interval",
                json_integer(data->user_role_expiry_interval));
            json_object_set_new(js, "username_len",
                json_integer(data->username_len));
            json_object_set_new(js, "user_public_key_len",
                json_integer(data->user_public_key_len));
            json_object_set_new(js, "certification_data_len",
                json_integer(data->certification_data_len));
            if (data->username_len > 0) {
                /* First create a null terminated string as not all versions
                 * of jansson have json_stringn. */
                char tmpbuf[data->username_len + 1];
                memcpy(tmpbuf, data->username, data->username_len);
                tmpbuf[data->username_len] = '\0';
                json_object_set_new(js, "username", json_string(tmpbuf));
            } else {
                json_object_set_new(js, "username", json_string(""));
            }
            unsigned long user_public_key_b64_len = data->user_public_key_len * 2;
            uint8_t user_public_key_b64[user_public_key_b64_len];
            Base64Encode(data->user_public_key, data->user_public_key_len,
                user_public_key_b64, &user_public_key_b64_len);
            json_object_set_new(js, "data->user_public_key",
                json_string((char *)user_public_key_b64));
            unsigned long certification_data_b64_len = data->certification_data_len * 2;
            uint8_t certification_data_b64[certification_data_b64_len];
            Base64Encode(data->certification_data, data->certification_data_len,
                certification_data_b64, &certification_data_b64_len);
            json_object_set_new(js, "data->certification_data",
                json_string((char *)certification_data_b64));
            break;
        }
        case DNP3_OBJECT_CODE(120, 11): {
            DNP3ObjectG120V11 *data = point->data;
            json_object_set_new(js, "key_change_method",
                json_integer(data->key_change_method));
            json_object_set_new(js, "username_len",
                json_integer(data->username_len));
            json_object_set_new(js, "master_challenge_data_len",
                json_integer(data->master_challenge_data_len));
            if (data->username_len > 0) {
                /* First create a null terminated string as not all versions
                 * of jansson have json_stringn. */
                char tmpbuf[data->username_len + 1];
                memcpy(tmpbuf, data->username, data->username_len);
                tmpbuf[data->username_len] = '\0';
                json_object_set_new(js, "username", json_string(tmpbuf));
            } else {
                json_object_set_new(js, "username", json_string(""));
            }
            unsigned long master_challenge_data_b64_len = data->master_challenge_data_len * 2;
            uint8_t master_challenge_data_b64[master_challenge_data_b64_len];
            Base64Encode(data->master_challenge_data, data->master_challenge_data_len,
                master_challenge_data_b64, &master_challenge_data_b64_len);
            json_object_set_new(js, "data->master_challenge_data",
                json_string((char *)master_challenge_data_b64));
            break;
        }
        case DNP3_OBJECT_CODE(120, 12): {
            DNP3ObjectG120V12 *data = point->data;
            json_object_set_new(js, "ksq",
                json_integer(data->ksq));
            json_object_set_new(js, "user_number",
                json_integer(data->user_number));
            json_object_set_new(js, "challenge_data_len",
                json_integer(data->challenge_data_len));
            unsigned long challenge_data_b64_len = data->challenge_data_len * 2;
            uint8_t challenge_data_b64[challenge_data_b64_len];
            Base64Encode(data->challenge_data, data->challenge_data_len,
                challenge_data_b64, &challenge_data_b64_len);
            json_object_set_new(js, "data->challenge_data",
                json_string((char *)challenge_data_b64));
            break;
        }
        case DNP3_OBJECT_CODE(120, 13): {
            DNP3ObjectG120V13 *data = point->data;
            json_object_set_new(js, "ksq",
                json_integer(data->ksq));
            json_object_set_new(js, "user_number",
                json_integer(data->user_number));
            json_object_set_new(js, "encrypted_update_key_len",
                json_integer(data->encrypted_update_key_len));
            unsigned long encrypted_update_key_data_b64_len = data->encrypted_update_key_len * 2;
            uint8_t encrypted_update_key_data_b64[encrypted_update_key_data_b64_len];
            Base64Encode(data->encrypted_update_key_data, data->encrypted_update_key_len,
                encrypted_update_key_data_b64, &encrypted_update_key_data_b64_len);
            json_object_set_new(js, "data->encrypted_update_key_data",
                json_string((char *)encrypted_update_key_data_b64));
            break;
        }
        case DNP3_OBJECT_CODE(120, 14): {
            DNP3ObjectG120V14 *data = point->data;
            unsigned long digital_signature_b64_len = data->digital_signature_len * 2;
            uint8_t digital_signature_b64[digital_signature_b64_len];
            Base64Encode(data->digital_signature, data->digital_signature_len,
                digital_signature_b64, &digital_signature_b64_len);
            json_object_set_new(js, "data->digital_signature",
                json_string((char *)digital_signature_b64));
            break;
        }
        case DNP3_OBJECT_CODE(120, 15): {
            DNP3ObjectG120V15 *data = point->data;
            unsigned long mac_b64_len = data->mac_len * 2;
            uint8_t mac_b64[mac_b64_len];
            Base64Encode(data->mac, data->mac_len,
                mac_b64, &mac_b64_len);
            json_object_set_new(js, "data->mac",
                json_string((char *)mac_b64));
            break;
        }
        case DNP3_OBJECT_CODE(121, 1): {
            DNP3ObjectG121V1 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "association_id",
                json_integer(data->association_id));
            json_object_set_new(js, "count_value",
                json_integer(data->count_value));
            break;
        }
        case DNP3_OBJECT_CODE(122, 1): {
            DNP3ObjectG122V1 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "association_id",
                json_integer(data->association_id));
            json_object_set_new(js, "count_value",
                json_integer(data->count_value));
            break;
        }
        case DNP3_OBJECT_CODE(122, 2): {
            DNP3ObjectG122V2 *data = point->data;
            json_object_set_new(js, "online",
                json_integer(data->online));
            json_object_set_new(js, "restart",
                json_integer(data->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(data->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(data->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(data->local_forced));
            json_object_set_new(js, "reserved0",
                json_integer(data->reserved0));
            json_object_set_new(js, "discontinuity",
                json_integer(data->discontinuity));
            json_object_set_new(js, "reserved1",
                json_integer(data->reserved1));
            json_object_set_new(js, "association_id",
                json_integer(data->association_id));
            json_object_set_new(js, "count_value",
                json_integer(data->count_value));
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        default:
            SCLogDebug("Unknown object: %d:%d", object->group,
                object->variation);
            break;
    }

}