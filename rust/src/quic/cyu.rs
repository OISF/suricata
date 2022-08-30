/* Copyright (C) 2021-2022 Open Information Security Foundation
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

use super::{
    frames::Frame,
    parser::{QuicHeader, QuicVersion},
};
use md5::{Digest, Md5};

#[derive(Debug, PartialEq)]
pub struct Cyu {
    pub string: String,
    pub hash: String,
}

impl Cyu {
    pub(crate) fn new(string: String, hash: String) -> Self {
        Self { string, hash }
    }

    pub(crate) fn generate(header: &QuicHeader, frames: &[Frame]) -> Vec<Cyu> {
        let version = match header.version {
            QuicVersion::Q043 => Some("43"),
            QuicVersion::Q044 => Some("44"),
            QuicVersion::Q045 => Some("44"),
            QuicVersion::Q046 => Some("46"),
            _ => {
                SCLogDebug!(
                    "Cannot match QUIC version {:?} to CYU version",
                    header.version
                );
                None
            }
        };

        let mut cyu_hashes = Vec::new();

        if let Some(version) = version {
            for frame in frames {
                if let Frame::Stream(stream) = frame {
                    if let Some(tags) = &stream.tags {
                        let tags = tags
                            .iter()
                            .map(|(tag, _value)| tag.to_string())
                            .collect::<Vec<String>>()
                            .join("-");

                        let cyu_string = format!("{},{}", version, tags);

                        let mut hasher = Md5::new();
                        hasher.update(&cyu_string.as_bytes());
                        let hash = hasher.finalize();

                        let cyu_hash = format!("{:x}", hash);

                        cyu_hashes.push(Cyu::new(cyu_string, cyu_hash));
                    }
                }
            }
        }

        cyu_hashes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::frames::{Frame, Stream, StreamTag};
    use crate::quic::parser::{PublicFlags, QuicType};
    use test_case::test_case;

    macro_rules! mock_header_and_frames {
        ($version:expr, $($variants:expr),+) => {{
            let header = QuicHeader::new(
                PublicFlags::new(0x80),
                QuicType::Initial,
                $version,
                vec![],
                vec![],
            );

            let frames = vec![
                Frame::Stream(Stream {
                    fin: false,
                    stream_id: vec![],
                    offset: vec![],
                    tags: Some(vec![$(($variants, vec![])),*])
                })
            ];

            (header, frames)
        }};
    }

    // Salesforce tests here:
    // https://engineering.salesforce.com/gquic-protocol-analysis-and-fingerprinting-in-zeek-a4178855d75f
    #[test_case(
        mock_header_and_frames!(
            // version
            QuicVersion::Q046,
            // tags
            StreamTag::Pad, StreamTag::Sni,
            StreamTag::Stk, StreamTag::Ver,
            StreamTag::Ccs, StreamTag::Nonc,
            StreamTag::Aead, StreamTag::Uaid,
            StreamTag::Scid, StreamTag::Tcid,
            StreamTag::Pdmd, StreamTag::Smhl,
            StreamTag::Icsl, StreamTag::Nonp,
            StreamTag::Pubs, StreamTag::Mids,
            StreamTag::Scls, StreamTag::Kexs,
            StreamTag::Xlct, StreamTag::Csct,
            StreamTag::Copt, StreamTag::Ccrt,
            StreamTag::Irtt, StreamTag::Cfcw,
            StreamTag::Sfcw
        ),
        Cyu {
            string: "46,PAD-SNI-STK-VER-CCS-NONC-AEAD-UAID-SCID-TCID-PDMD-SMHL-ICSL-NONP-PUBS-MIDS-SCLS-KEXS-XLCT-CSCT-COPT-CCRT-IRTT-CFCW-SFCW".to_string(),
            hash: "a46560d4548108cf99308319b3b85346".to_string(),
        }; "test cyu 1"
    )]
    #[test_case(
        mock_header_and_frames!(
            // version
            QuicVersion::Q043,
            // tags
            StreamTag::Pad, StreamTag::Sni,
            StreamTag::Ver, StreamTag::Ccs,
            StreamTag::Pdmd, StreamTag::Icsl,
            StreamTag::Mids, StreamTag::Cfcw,
            StreamTag::Sfcw
        ),
        Cyu {
            string: "43,PAD-SNI-VER-CCS-PDMD-ICSL-MIDS-CFCW-SFCW".to_string(),
            hash: "e030dea1f2eea44ac7db5fe4de792acd".to_string(),
        }; "test cyu 2"
    )]
    #[test_case(
        mock_header_and_frames!(
            // version
            QuicVersion::Q043,
            // tags
            StreamTag::Pad, StreamTag::Sni,
            StreamTag::Stk, StreamTag::Ver,
            StreamTag::Ccs, StreamTag::Scid,
            StreamTag::Pdmd, StreamTag::Icsl,
            StreamTag::Mids, StreamTag::Cfcw,
            StreamTag::Sfcw
        ),
        Cyu {
            string: "43,PAD-SNI-STK-VER-CCS-SCID-PDMD-ICSL-MIDS-CFCW-SFCW".to_string(),
            hash: "0811fab28e41e8c8a33e220a15b964d9".to_string(),
        }; "test cyu 3"
    )]
    #[test_case(
        mock_header_and_frames!(
            // version
            QuicVersion::Q043,
            // tags
            StreamTag::Pad, StreamTag::Sni,
            StreamTag::Stk, StreamTag::Ver,
            StreamTag::Ccs, StreamTag::Nonc,
            StreamTag::Aead, StreamTag::Scid,
            StreamTag::Pdmd, StreamTag::Icsl,
            StreamTag::Pubs, StreamTag::Mids,
            StreamTag::Kexs, StreamTag::Xlct,
            StreamTag::Cfcw, StreamTag::Sfcw
        ),
        Cyu {
            string: "43,PAD-SNI-STK-VER-CCS-NONC-AEAD-SCID-PDMD-ICSL-PUBS-MIDS-KEXS-XLCT-CFCW-SFCW".to_string(),
            hash: "d8b208b236d176c89407500dbefb04c2".to_string(),
        }; "test cyu 4"
    )]
    fn test_cyu_generate(input: (QuicHeader, Vec<Frame>), expected: Cyu) {
        let (header, frames) = input;

        let cyu = Cyu::generate(&header, &frames);
        assert_eq!(1, cyu.len());
        assert_eq!(expected, cyu[0]);
    }
}
