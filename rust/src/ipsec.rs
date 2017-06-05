extern crate libc;

use std;
use std::mem;
use libc::c_char;

use rparser::*;

use ipsec_parser::*;
use num_traits::cast::FromPrimitive;

use nom::IResult;

#[derive(Debug,PartialEq)]
pub struct SimpleProposal {
    pub enc: u16,
    pub prf: u16,
    pub int: u16,
    pub dhg: u16,
    pub esn: u16,
}

pub struct IPsecParser<'a> {
    _name: Option<&'a[u8]>,

    pub client_proposals: Vec<SimpleProposal>,

    pub dh_group: Option<IkeTransformDHType>,
}

impl<'a> RParser for IPsecParser<'a> {
    fn parse(&mut self, i: &[u8], _direction: u8) -> u32 {
        match parse_ikev2_header(i) {
            IResult::Done(rem,ref hdr) => {
                debug!("parse_ikev2_header: {:?}",hdr);
                if rem.len() == 0 && hdr.length == 28 {
                    return R_STATUS_OK;
                }
                match parse_ikev2_payload_list(rem,hdr.next_payload) {
                    IResult::Done(_,ref p) => {
                        debug!("parse_ikev2_payload_with_type: {:?}",p);
                        for payload in p {
                            match payload.content {
                                IkeV2PayloadContent::SA(ref prop) => {
                                    if hdr.flags & IKEV2_FLAG_INITIATOR != 0 {
                                        self.add_client_proposals(prop);
                                    }
                                },
                                IkeV2PayloadContent::KE(ref kex) => {
                                    self.dh_group = IkeTransformDHType::from_u16(kex.dh_group);
                                    // XXX if self.dh_group == None, raise decoder event
                                    debug!("KEX {}/{:?}", kex.dh_group, self.dh_group);
                                },
                                _ => {
                                    debug!("Unknown payload content {:?}", payload.content);
                                },
                            }
                        }
                    },
                    e @ _ => warn!("parse_ikev2_payload_with_type: {:?}",e),
                };
            },
            e @ _ => warn!("parse_ikev2_header: {:?}",e),
        };
        R_STATUS_OK
    }
}

impl<'a> IPsecParser<'a> {
    pub fn new(name: &'a[u8]) -> IPsecParser<'a> {
        IPsecParser{
            _name: Some(name),
            client_proposals: Vec::new(),
            dh_group: None,
        }
    }

    fn add_client_proposals(&mut self, prop: &Vec<IkeV2Proposal>) {
        debug!("num_proposals: {}",prop.len());
        for ref p in prop {
            debug!("proposal: {:?}",p);
            debug!("num_transforms: {}",p.num_transforms);
            for ref xform in &p.transforms {
                debug!("transform: {:?}",xform);
                let xty = IkeTransformType::from_u8(xform.transform_type);
                debug!("\ttype: {:?} / {}",xty,xform.transform_type);
                match xty {
                    Some(IkeTransformType::EncryptionAlgorithm) => {
                        debug!("\tEncryptionAlgorithm: {:?}",IkeTransformEncType::from_u16(xform.transform_id));
                    },
                    Some(IkeTransformType::PseudoRandomFunction) => {
                        debug!("\tPseudoRandomFunction: {:?}",IkeTransformPRFType::from_u16(xform.transform_id));
                    },
                    Some(IkeTransformType::IntegrityAlgorithm) => {
                        debug!("\tIntegrityAlgorithm: {:?}",IkeTransformAuthType::from_u16(xform.transform_id));
                    },
                    Some(IkeTransformType::DiffieHellmanGroup) => {
                        debug!("\tDiffieHellmanGroup: {:?}",IkeTransformDHType::from_u16(xform.transform_id));
                    },
                    Some(IkeTransformType::ExtendedSequenceNumbers) => {
                        debug!("\tExtendedSequenceNumbers: {:?}",IkeTransformESNType::from_u16(xform.transform_id));
                    },
                    _ => warn!("\tUnknown transform type {}",xform.transform_type),
                }
                if xform.transform_id == 0 {
                    warn!("\tTransform ID == 0 (choice left to responder)");
                };
            }
            // "uncompress" the IPsec ciphersuites proposals
            // Despite the apparent complexity, the number of transforms should be small.
            let mut prop_enc : Vec<u16> = Vec::new();
            let mut prop_prf : Vec<u16> = Vec::new();
            let mut prop_int : Vec<u16> = Vec::new();
            let mut prop_dhg : Vec<u16> = Vec::new();
            let mut prop_esn : Vec<u16> = Vec::new();
            for ref xform in &p.transforms {
                let xty = IkeTransformType::from_u8(xform.transform_type);
                match xty {
                    Some(IkeTransformType::EncryptionAlgorithm)     => prop_enc.push(xform.transform_id),
                    Some(IkeTransformType::PseudoRandomFunction)    => prop_prf.push(xform.transform_id),
                    Some(IkeTransformType::IntegrityAlgorithm)      => prop_int.push(xform.transform_id),
                    Some(IkeTransformType::DiffieHellmanGroup)      => prop_dhg.push(xform.transform_id),
                    Some(IkeTransformType::ExtendedSequenceNumbers) => prop_esn.push(xform.transform_id),
                    _ => (),
                }
            }
            if prop_int.len() == 0 { prop_int.push(IkeTransformAuthType::None as u16); }
            if prop_dhg.len() == 0 { prop_int.push(IkeTransformDHType::None as u16); }
            if prop_esn.len() == 0 { prop_esn.push(IkeTransformESNType::NoESN as u16); }
            for enc in &prop_enc {
                for prf in &prop_prf {
                    for int in &prop_int {
                        for dhg in &prop_dhg {
                            for esn in &prop_esn {
                                let item = SimpleProposal{
                                    enc:*enc,
                                    prf:*prf,
                                    int:*int,
                                    dhg:*dhg,
                                    esn:*esn,
                                };
                                if ! self.client_proposals.contains(&item) {
                                    self.client_proposals.push(item);
                                }
                            };
                        };
                    };
                };
            };
            debug!("Proposals: {:?}",self.client_proposals);
        }
    }
}

fn ipsec_probe(i: &[u8]) -> bool {
    if i.len() <= 2 { return false; }
    true
}

r_declare_state_new!(r_ipsec_state_new,IPsecParser,b"IPsec state");
r_declare_state_free!(r_ipsec_state_free,IPsecParser,{ () });

r_implement_probe!(r_ipsec_probe,ipsec_probe);
r_implement_parse!(r_ipsec_parse,IPsecParser);

