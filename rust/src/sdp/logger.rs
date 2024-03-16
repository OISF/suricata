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

use super::parser::{ConnectionData, MediaDescription, SdpMessage};

pub fn sdp_log(msg: &SdpMessage, js: &mut JsonBuilder) -> Result<(), JsonError> {
    js.open_object("sdp")?;

    let origin = format!(
        "{} {} {} {} {} {}",
        &msg.origin.username,
        &msg.origin.sess_id,
        &msg.origin.sess_version,
        &msg.origin.nettype,
        &msg.origin.addrtype,
        &msg.origin.unicast_address
    );

    js.set_string("origin", &origin)?;
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
        log_connection_data(conn_data, js)?;
    }
    if let Some(bws) = &msg.bandwidths {
        log_bandwidth(bws, js)?;
    }
    js.set_string("time", &msg.time)?;
    if let Some(repeat_time) = &msg.repeat_time {
        js.set_string("repeat_time", repeat_time)?;
    }
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

fn log_media_description(
    media: &Vec<MediaDescription>, js: &mut JsonBuilder,
) -> Result<(), JsonError> {
    if !media.is_empty() {
        js.open_array("media_descriptions")?;
        for m in media {
            js.start_object()?;
            let port = if let Some(num_ports) = m.number_of_ports {
                format!("{}/{}", m.port, num_ports)
            } else {
                format!("{}", m.port)
            };
            let mut media = format!("{} {} {}", &m.media, &port, &m.proto);
            for f in &m.fmt {
                media = format!("{} {}", media, f);
            }
            js.set_string("media", &media)?;

            if let Some(session_info) = &m.session_info {
                js.set_string("media_info", session_info)?;
            };
            if let Some(bws) = &m.bandwidths {
                log_bandwidth(bws, js)?;
            }
            if let Some(conn_data) = &m.connection_data {
                log_connection_data(conn_data, js)?;
            }
            if let Some(attrs) = &m.attributes {
                log_attributes(attrs, js)?;
            }
            js.close()?;
        }
    }
    js.close()?;

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

fn log_connection_data(conn_data: &ConnectionData, js: &mut JsonBuilder) -> Result<(), JsonError> {
    let mut conn = format!(
        "{} {} {}",
        &conn_data.nettype,
        &conn_data.addrtype,
        &conn_data.connection_address.to_string()
    );
    if let Some(ttl) = conn_data.ttl {
        conn = format!("{}/{}", conn, ttl);
        js.set_uint("ttl", ttl as u64)?;
    }
    if let Some(num_addrs) = conn_data.number_of_addresses {
        conn = format!("{}/{}", conn, num_addrs);
    }
    js.set_string("connection_data", &conn)?;
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
