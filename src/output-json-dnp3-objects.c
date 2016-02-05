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
    DNP3ObjectItem *item)
{

    switch (DNP3_OBJECT_CODE(object->group, object->variation)) {
        case DNP3_OBJECT_CODE(1, 1): {
            DNP3ObjectG1V1 *point = item->item;
            json_object_set_new(js, "state",
                json_integer(point->state));
            break;
        }
        case DNP3_OBJECT_CODE(1, 2): {
            DNP3ObjectG1V2 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "chatter_filter",
                json_integer(point->chatter_filter));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "state",
                json_integer(point->state));
            break;
        }
        case DNP3_OBJECT_CODE(2, 1): {
            DNP3ObjectG2V1 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "chatter_filter",
                json_integer(point->chatter_filter));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "state",
                json_integer(point->state));
            break;
        }
        case DNP3_OBJECT_CODE(2, 2): {
            DNP3ObjectG2V2 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "chatter_filter",
                json_integer(point->chatter_filter));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "state",
                json_integer(point->state));
            json_object_set_new(js, "timestamp",
                json_integer(point->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(3, 1): {
            DNP3ObjectG3V1 *point = item->item;
            json_object_set_new(js, "state",
                json_integer(point->state));
            break;
        }
        case DNP3_OBJECT_CODE(3, 2): {
            DNP3ObjectG3V2 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "chatter_filter",
                json_integer(point->chatter_filter));
            json_object_set_new(js, "state",
                json_integer(point->state));
            break;
        }
        case DNP3_OBJECT_CODE(4, 1): {
            DNP3ObjectG4V1 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "chatter_filter",
                json_integer(point->chatter_filter));
            json_object_set_new(js, "state",
                json_integer(point->state));
            break;
        }
        case DNP3_OBJECT_CODE(10, 1): {
            DNP3ObjectG10V1 *point = item->item;
            json_object_set_new(js, "state",
                json_integer(point->state));
            break;
        }
        case DNP3_OBJECT_CODE(10, 2): {
            DNP3ObjectG10V2 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "reserved0",
                json_integer(point->reserved0));
            json_object_set_new(js, "reserved1",
                json_integer(point->reserved1));
            json_object_set_new(js, "state",
                json_integer(point->state));
            break;
        }
        case DNP3_OBJECT_CODE(12, 1): {
            DNP3ObjectG12V1 *point = item->item;
            json_object_set_new(js, "op_type",
                json_integer(point->op_type));
            json_object_set_new(js, "qu",
                json_integer(point->qu));
            json_object_set_new(js, "cr",
                json_integer(point->cr));
            json_object_set_new(js, "tcc",
                json_integer(point->tcc));
            json_object_set_new(js, "count",
                json_integer(point->count));
            json_object_set_new(js, "on_time",
                json_integer(point->on_time));
            json_object_set_new(js, "off_time",
                json_integer(point->off_time));
            json_object_set_new(js, "status_code",
                json_integer(point->status_code));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            break;
        }
        case DNP3_OBJECT_CODE(12, 2): {
            DNP3ObjectG12V2 *point = item->item;
            json_object_set_new(js, "op_type",
                json_integer(point->op_type));
            json_object_set_new(js, "qu",
                json_integer(point->qu));
            json_object_set_new(js, "cr",
                json_integer(point->cr));
            json_object_set_new(js, "tcc",
                json_integer(point->tcc));
            json_object_set_new(js, "count",
                json_integer(point->count));
            json_object_set_new(js, "on_time",
                json_integer(point->on_time));
            json_object_set_new(js, "off_time",
                json_integer(point->off_time));
            json_object_set_new(js, "status_code",
                json_integer(point->status_code));
            json_object_set_new(js, "res",
                json_integer(point->res));
            break;
        }
        case DNP3_OBJECT_CODE(20, 1): {
            DNP3ObjectG20V1 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(point->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(point->discontinuity));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "count",
                json_integer(point->count));
            break;
        }
        case DNP3_OBJECT_CODE(20, 2): {
            DNP3ObjectG20V2 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(point->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(point->discontinuity));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "count",
                json_integer(point->count));
            break;
        }
        case DNP3_OBJECT_CODE(21, 1): {
            DNP3ObjectG21V1 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(point->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(point->discontinuity));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "count",
                json_integer(point->count));
            break;
        }
        case DNP3_OBJECT_CODE(21, 2): {
            DNP3ObjectG21V2 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(point->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(point->discontinuity));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "count",
                json_integer(point->count));
            break;
        }
        case DNP3_OBJECT_CODE(22, 1): {
            DNP3ObjectG22V1 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(point->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(point->discontinuity));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "count",
                json_integer(point->count));
            break;
        }
        case DNP3_OBJECT_CODE(22, 2): {
            DNP3ObjectG22V2 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "rollover",
                json_integer(point->rollover));
            json_object_set_new(js, "discontinuity",
                json_integer(point->discontinuity));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "count",
                json_integer(point->count));
            break;
        }
        case DNP3_OBJECT_CODE(30, 1): {
            DNP3ObjectG30V1 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(point->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(point->reference_err));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "value",
                json_integer(point->value));
            break;
        }
        case DNP3_OBJECT_CODE(30, 2): {
            DNP3ObjectG30V2 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(point->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(point->reference_err));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "value",
                json_integer(point->value));
            break;
        }
        case DNP3_OBJECT_CODE(30, 4): {
            DNP3ObjectG30V4 *point = item->item;
            json_object_set_new(js, "value",
                json_integer(point->value));
            break;
        }
        case DNP3_OBJECT_CODE(30, 5): {
            DNP3ObjectG30V5 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(point->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(point->reference_err));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            break;
        }
        case DNP3_OBJECT_CODE(32, 1): {
            DNP3ObjectG32V1 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(point->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(point->reference_err));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "value",
                json_integer(point->value));
            break;
        }
        case DNP3_OBJECT_CODE(32, 2): {
            DNP3ObjectG32V2 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(point->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(point->reference_err));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "value",
                json_integer(point->value));
            break;
        }
        case DNP3_OBJECT_CODE(32, 3): {
            DNP3ObjectG32V3 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(point->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(point->reference_err));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "value",
                json_integer(point->value));
            json_object_set_new(js, "timestamp",
                json_integer(point->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(32, 5): {
            DNP3ObjectG32V5 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(point->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(point->reference_err));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            break;
        }
        case DNP3_OBJECT_CODE(32, 7): {
            DNP3ObjectG32V7 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(point->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(point->reference_err));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "timestamp",
                json_integer(point->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(34, 1): {
            DNP3ObjectG34V1 *point = item->item;
            json_object_set_new(js, "deadband_value",
                json_integer(point->deadband_value));
            break;
        }
        case DNP3_OBJECT_CODE(40, 1): {
            DNP3ObjectG40V1 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(point->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(point->reference_err));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "value",
                json_integer(point->value));
            break;
        }
        case DNP3_OBJECT_CODE(40, 2): {
            DNP3ObjectG40V2 *point = item->item;
            json_object_set_new(js, "online",
                json_integer(point->online));
            json_object_set_new(js, "restart",
                json_integer(point->restart));
            json_object_set_new(js, "comm_lost",
                json_integer(point->comm_lost));
            json_object_set_new(js, "remote_forced",
                json_integer(point->remote_forced));
            json_object_set_new(js, "local_forced",
                json_integer(point->local_forced));
            json_object_set_new(js, "over_range",
                json_integer(point->over_range));
            json_object_set_new(js, "reference_err",
                json_integer(point->reference_err));
            json_object_set_new(js, "reserved",
                json_integer(point->reserved));
            json_object_set_new(js, "value",
                json_integer(point->value));
            break;
        }
        case DNP3_OBJECT_CODE(50, 1): {
            DNP3ObjectG50V1 *point = item->item;
            json_object_set_new(js, "timestamp",
                json_integer(point->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(50, 3): {
            DNP3ObjectG50V3 *point = item->item;
            json_object_set_new(js, "timestamp",
                json_integer(point->timestamp));
            break;
        }
        case DNP3_OBJECT_CODE(52, 1): {
            DNP3ObjectG52V1 *point = item->item;
            json_object_set_new(js, "delay_ms",
                json_integer(point->delay_ms));
            break;
        }
        case DNP3_OBJECT_CODE(52, 2): {
            DNP3ObjectG52V2 *point = item->item;
            json_object_set_new(js, "delay_ms",
                json_integer(point->delay_ms));
            break;
        }
        case DNP3_OBJECT_CODE(70, 3): {
            DNP3ObjectG70V3 *point = item->item;
            json_object_set_new(js, "filename_offset",
                json_integer(point->filename_offset));
            json_object_set_new(js, "filename_size",
                json_integer(point->filename_size));
            json_object_set_new(js, "created",
                json_integer(point->created));
            json_object_set_new(js, "permissions",
                json_integer(point->permissions));
            json_object_set_new(js, "authentication_key",
                json_integer(point->authentication_key));
            json_object_set_new(js, "file_size",
                json_integer(point->file_size));
            json_object_set_new(js, "operational_mode",
                json_integer(point->operational_mode));
            json_object_set_new(js, "maximum_block_size",
                json_integer(point->maximum_block_size));
            json_object_set_new(js, "request_id",
                json_integer(point->request_id));
            json_object_set_new(js, "filename",
                json_string(point->filename));
            break;
        }
        case DNP3_OBJECT_CODE(80, 1): {
            DNP3ObjectG80V1 *point = item->item;
            json_object_set_new(js, "state",
                json_integer(point->state));
            break;
        }
        default:
            SCLogDebug("Unknown object: %d:%d", object->group,
                object->variation);
            break;
    }

}