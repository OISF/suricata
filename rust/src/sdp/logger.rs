/* Copyright (C) 2024 Open Information Security Foundation
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

// written by Giuseppe Longo <giuseppe@glongo.it>

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::sip::log::SipLogBudget;

use super::parser::{MediaDescription, SdpMessage, TimeDescription};

pub(crate) fn sdp_log(
    msg: &SdpMessage, js: &mut JsonBuilder, budget: &mut SipLogBudget,
) -> Result<(), JsonError> {
    js.open_object("sdp")?;

    budget.set_string(js, "origin", &msg.origin)?;
    budget.set_string(js, "session_name", &msg.session_name)?;

    if let Some(session_info) = &msg.session_info {
        budget.set_string(js, "session_info", session_info)?;
    }
    if let Some(uri) = &msg.uri {
        budget.set_string(js, "uri", uri)?;
    }
    if let Some(email) = &msg.email {
        budget.set_string(js, "email", email)?;
    }
    if let Some(phone_number) = &msg.phone_number {
        budget.set_string(js, "phone_number", phone_number)?;
    }
    if let Some(conn_data) = &msg.connection_data {
        budget.set_string(js, "connection_data", conn_data)?;
    }
    if let Some(bws) = &msg.bandwidths {
        log_bandwidth(bws, js, budget)?;
    }
    log_time_description(&msg.time_description, js, budget)?;
    if let Some(tz) = &msg.time_zone {
        budget.set_string(js, "timezone", tz)?;
    }
    if let Some(enc_key) = &msg.encryption_key {
        budget.set_string(js, "encryption_key", enc_key)?;
    }
    if let Some(attrs) = &msg.attributes {
        if log_attributes(attrs, js, budget)? {
            js.set_bool("attributes_redacted", true)?;
        }
    }
    if let Some(media) = &msg.media_description {
        log_media_description(media, js, budget)?;
    }
    js.close()?;
    Ok(())
}

fn log_time_description(
    time: &Vec<TimeDescription>, js: &mut JsonBuilder, budget: &mut SipLogBudget,
) -> Result<(), JsonError> {
    if time.is_empty() || !budget.spend(32) {
        return Ok(());
    }
    js.open_array("time_descriptions")?;
    for t in time {
        if !budget.spend(32) {
            break;
        }
        js.start_object()?;
        budget.set_string(js, "time", &t.time)?;
        if let Some(repeat_time) = &t.repeat_time {
            budget.set_string(js, "repeat_time", repeat_time)?;
        }
        js.close()?;
    }
    js.close()?;
    Ok(())
}

fn log_media_description(
    media: &Vec<MediaDescription>, js: &mut JsonBuilder, budget: &mut SipLogBudget,
) -> Result<(), JsonError> {
    if !media.is_empty() && budget.spend(32) {
        js.open_array("media_descriptions")?;
        for m in media {
            if !budget.spend(32) {
                break;
            }
            js.start_object()?;
            budget.set_string(js, "media", &m.media)?;
            if let Some(session_info) = &m.session_info {
                budget.set_string(js, "media_info", session_info)?;
            };
            if let Some(bws) = &m.bandwidths {
                log_bandwidth(bws, js, budget)?;
            }
            if let Some(conn_data) = &m.connection_data {
                budget.set_string(js, "connection_data", conn_data)?;
            }
            if let Some(enc_key) = &m.encryption_key {
                budget.set_string(js, "encryption_key", enc_key)?;
            }
            if let Some(attrs) = &m.attributes {
                if log_attributes(attrs, js, budget)? {
                    js.set_bool("attributes_redacted", true)?;
                }
            }
            js.close()?;
        }
        js.close()?;
    }

    Ok(())
}

fn log_bandwidth(
    bws: &Vec<String>, js: &mut JsonBuilder, budget: &mut SipLogBudget,
) -> Result<(), JsonError> {
    if !bws.is_empty() && budget.spend(8) {
        js.open_array("bandwidths")?;
        for bw in bws {
            if !budget.append_string(js, bw)? {
                break;
            }
        }
        js.close()?;
    }
    Ok(())
}

fn log_attributes(
    attrs: &Vec<String>, js: &mut JsonBuilder, budget: &mut SipLogBudget,
) -> Result<bool, JsonError> {
    if !attrs.is_empty() && budget.spend(8) {
        js.open_array("attributes")?;
        for attr in attrs {
            if !budget.append_string(js, attr)? {
                break;
            }
        }
        js.close()?;
    }
    Ok(false)
}
