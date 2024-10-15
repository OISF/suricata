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

use super::parser::{MediaDescription, SdpMessage, TimeDescription};

pub fn sdp_log(msg: &SdpMessage, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("sdp")?;

    js.set_string("origin", &msg.origin)?;
    js.set_string("session_name", &msg.session_name)?;

    if let Some(session_info) = &msg.session_info {
        js.set_string("session_info", session_info)?;
    }
    if let Some(uri) = &msg.uri {
        js.set_string("uri", uri)?;
    }
    if let Some(email) = &msg.email {
        js.set_string("email", email)?;
    }
    if let Some(phone_number) = &msg.phone_number {
        js.set_string("phone_number", phone_number)?;
    }
    if let Some(conn_data) = &msg.connection_data {
        js.set_string("connection_data", conn_data)?;
    }
    if let Some(bws) = &msg.bandwidths {
        log_bandwidth(bws, js)?;
    }
    log_time_description(&msg.time_description, js)?;
    if let Some(tz) = &msg.time_zone {
        js.set_string("timezone", tz)?;
    }
    if let Some(enc_key) = &msg.encryption_key {
        js.set_string("encryption_key", enc_key)?;
    }
    if let Some(attrs) = &msg.attributes {
        log_attributes(attrs, js)?;
    }
    if let Some(media) = &msg.media_description {
        log_media_description(media, js)?;
    }
    js.close()?;
    Ok(())
}

fn log_time_description(
    time: &Vec<TimeDescription>, js: &mut JsonBuilder,
) -> Result<(), JsonError> {
    js.open_array("time_descriptions")?;
    for t in time {
        js.start_object()?;
        js.set_string("time", &t.time)?;
        if let Some(repeat_time) = &t.repeat_time {
            js.set_string("repeat_time", repeat_time)?;
        }
        js.close()?;
    }
    js.close()?;
    Ok(())
}

fn log_media_description(
    media: &Vec<MediaDescription>, js: &mut JsonBuilder,
) -> Result<(), JsonError> {
    if !media.is_empty() {
        js.open_array("media_descriptions")?;
        for m in media {
            js.start_object()?;
            js.set_string("media", &m.media)?;
            if let Some(session_info) = &m.session_info {
                js.set_string("media_info", session_info)?;
            };
            if let Some(bws) = &m.bandwidths {
                log_bandwidth(bws, js)?;
            }
            if let Some(conn_data) = &m.connection_data {
                js.set_string("connection_data", conn_data)?;
            }
            if let Some(enc_key) = &m.encryption_key {
                js.set_string("encryption_key", enc_key)?;
            }
            if let Some(attrs) = &m.attributes {
                log_attributes(attrs, js)?;
            }
            js.close()?;
        }
        js.close()?;
    }

    Ok(())
}

fn log_bandwidth(bws: &Vec<String>, js: &mut JsonBuilder) -> Result<(), JsonError> {
    if !bws.is_empty() {
        js.open_array("bandwidths")?;
        for bw in bws {
            js.append_string(bw)?;
        }
        js.close()?;
    }
    Ok(())
}

fn log_attributes(attrs: &Vec<String>, js: &mut JsonBuilder) -> Result<(), JsonError> {
    if !attrs.is_empty() {
        js.open_array("attributes")?;
        for attr in attrs {
            js.append_string(attr)?;
        }
        js.close()?;
    }
    Ok(())
}
