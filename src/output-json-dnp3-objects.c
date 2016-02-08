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
        case DNP3_OBJECT_CODE(12, 1): {
            DNP3ObjectG12V1 *data = point->data;
            json_object_set_new(js, "op_type",
                json_integer(data->op_type));
            json_object_set_new(js, "qu",
                json_integer(data->qu));
            json_object_set_new(js, "cr",
                json_integer(data->cr));
            json_object_set_new(js, "tcc",
                json_integer(data->tcc));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "on_time",
                json_integer(data->on_time));
            json_object_set_new(js, "off_time",
                json_integer(data->off_time));
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
            break;
        }
        case DNP3_OBJECT_CODE(12, 2): {
            DNP3ObjectG12V2 *data = point->data;
            json_object_set_new(js, "op_type",
                json_integer(data->op_type));
            json_object_set_new(js, "qu",
                json_integer(data->qu));
            json_object_set_new(js, "cr",
                json_integer(data->cr));
            json_object_set_new(js, "tcc",
                json_integer(data->tcc));
            json_object_set_new(js, "count",
                json_integer(data->count));
            json_object_set_new(js, "on_time",
                json_integer(data->on_time));
            json_object_set_new(js, "off_time",
                json_integer(data->off_time));
            json_object_set_new(js, "status_code",
                json_integer(data->status_code));
            json_object_set_new(js, "res",
                json_integer(data->res));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
            json_object_set_new(js, "count",
                json_integer(data->count));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
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
            json_object_set_new(js, "reserved",
                json_integer(data->reserved));
            json_object_set_new(js, "value",
                json_integer(data->value));
            break;
        }
        case DNP3_OBJECT_CODE(50, 1): {
            DNP3ObjectG50V1 *data = point->data;
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(50, 3): {
            DNP3ObjectG50V3 *data = point->data;
            json_object_set_new(js, "timestamp",
                json_integer(data->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(52, 1): {
            DNP3ObjectG52V1 *data = point->data;
            json_object_set_new(js, "delay_ms",
                json_integer(data->delay_ms));
            break;
        }
        case DNP3_OBJECT_CODE(52, 2): {
            DNP3ObjectG52V2 *data = point->data;
            json_object_set_new(js, "delay_ms",
                json_integer(data->delay_ms));
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
            json_object_set_new(js, "filename",
                json_string(data->filename));
            break;
        }
        case DNP3_OBJECT_CODE(80, 1): {
            DNP3ObjectG80V1 *data = point->data;
            json_object_set_new(js, "state",
                json_integer(data->state));
            break;
        }
        default:
            SCLogDebug("Unknown object: %d:%d", object->group,
                object->variation);
            break;
    }

}