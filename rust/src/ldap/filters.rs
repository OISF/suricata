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

use crate::ldap::types::LdapString;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    EqualityMatch(AttributeValueAssertion),
    Substrings(SubstringFilter),
    GreaterOrEqual(AttributeValueAssertion),
    LessOrEqual(AttributeValueAssertion),
    Present(LdapString),
    ApproxMatch(AttributeValueAssertion),
    ExtensibleMatch(MatchingRuleAssertion),
}

impl<'a> From<ldap_parser::filter::Filter<'a>> for Filter {
    fn from(f: ldap_parser::filter::Filter) -> Self {
        match f {
            ldap_parser::filter::Filter::And(val) => {
                let mut vec = Vec::new();
                for filter in val {
                    vec.push(filter.into());
                }
                Filter::And(vec)
            }
            ldap_parser::filter::Filter::Or(val) => {
                let mut vec = Vec::new();
                for filter in val {
                    vec.push(filter.into());
                }
                Filter::Or(vec)
            }
            ldap_parser::filter::Filter::Not(val) => {
                let f = *val;
                let f2: Filter = f.into();
                Filter::Not(Box::from(f2))
            }
            ldap_parser::filter::Filter::EqualityMatch(val) => {
                Filter::EqualityMatch(AttributeValueAssertion {
                    attribute_desc: LdapString(val.attribute_desc.0.to_string()),
                    assertion_value: val.assertion_value.to_vec(),
                })
            }
            ldap_parser::filter::Filter::Substrings(val) => {
                let filter_type = LdapString(val.filter_type.0.to_string());
                let mut substrings: Vec<Substring> = Vec::new();
                for s in val.substrings {
                    substrings.push(s.into());
                }
                Filter::Substrings(SubstringFilter {
                    filter_type,
                    substrings,
                })
            }
            ldap_parser::filter::Filter::GreaterOrEqual(val) => {
                Filter::GreaterOrEqual(AttributeValueAssertion {
                    attribute_desc: LdapString(val.attribute_desc.0.to_string()),
                    assertion_value: val.assertion_value.to_vec(),
                })
            }
            ldap_parser::filter::Filter::LessOrEqual(val) => {
                Filter::LessOrEqual(AttributeValueAssertion {
                    attribute_desc: LdapString(val.attribute_desc.0.to_string()),
                    assertion_value: val.assertion_value.to_vec(),
                })
            }
            ldap_parser::filter::Filter::Present(val) => {
                Filter::Present(LdapString(val.0.to_string()))
            }
            ldap_parser::filter::Filter::ApproxMatch(val) => {
                Filter::ApproxMatch(AttributeValueAssertion {
                    attribute_desc: LdapString(val.attribute_desc.0.to_string()),
                    assertion_value: val.assertion_value.to_vec(),
                })
            }
            ldap_parser::filter::Filter::ExtensibleMatch(val) => {
                let matching_rule = if let Some(mr) = val.matching_rule {
                    Some(LdapString(mr.0.to_string()))
                } else {
                    None
                };
                let rule_type = if let Some(rt) = val.rule_type {
                    Some(AttributeDescription(rt.0.to_string()))
                } else {
                    None
                };
                let assertion_value = AssertionValue(val.assertion_value.0.to_vec());
                let dn_attributes = val.dn_attributes;
                Filter::ExtensibleMatch(MatchingRuleAssertion {
                    matching_rule,
                    rule_type,
                    assertion_value,
                    dn_attributes,
                })
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialAttribute {
    pub attr_type: LdapString,
    pub attr_vals: Vec<AttributeValue>,
}

impl<'a> From<&ldap_parser::filter::PartialAttribute<'a>> for PartialAttribute {
    fn from(value: &ldap_parser::filter::PartialAttribute) -> Self {
        let attr_type = LdapString(value.attr_type.0.to_string());
        let attr_vals: Vec<AttributeValue> = value
            .attr_vals
            .iter()
            .map(|a| AttributeValue(a.0.to_vec()))
            .collect();

        Self {
            attr_type,
            attr_vals,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attribute {
    pub attr_type: LdapString,
    pub attr_vals: Vec<AttributeValue>,
}

impl<'a> From<&ldap_parser::filter::Attribute<'a>> for Attribute {
    fn from(value: &ldap_parser::filter::Attribute) -> Self {
        let attr_type = LdapString(value.attr_type.0.to_string());
        let attr_vals: Vec<AttributeValue> = value
            .attr_vals
            .iter()
            .map(|a| AttributeValue(a.0.to_vec()))
            .collect();

        Self {
            attr_type,
            attr_vals,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttributeValueAssertion {
    pub attribute_desc: LdapString,
    pub assertion_value: Vec<u8>,
}
impl<'a> From<&ldap_parser::filter::AttributeValueAssertion<'a>> for AttributeValueAssertion {
    fn from(value: &ldap_parser::filter::AttributeValueAssertion) -> Self {
        let attribute_desc = LdapString(value.attribute_desc.0.to_string());
        let assertion_value = value.assertion_value.to_vec();
        Self {
            attribute_desc,
            assertion_value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttributeDescription(pub String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchingRuleAssertion {
    pub matching_rule: Option<LdapString>,
    pub rule_type: Option<AttributeDescription>,
    pub assertion_value: AssertionValue,
    pub dn_attributes: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchingRuleId(pub String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubstringFilter {
    pub filter_type: LdapString,
    pub substrings: Vec<Substring>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Substring {
    Initial(AssertionValue),
    Any(AssertionValue),
    Final(AssertionValue),
}
impl<'a> From<ldap_parser::filter::Substring<'a>> for Substring {
    fn from(value: ldap_parser::filter::Substring) -> Self {
        match value {
            ldap_parser::filter::Substring::Initial(val) => {
                Substring::Initial(AssertionValue(val.0.to_vec()))
            }
            ldap_parser::filter::Substring::Any(val) => {
                Substring::Any(AssertionValue(val.0.to_vec()))
            }
            ldap_parser::filter::Substring::Final(val) => {
                Substring::Final(AssertionValue(val.0.to_vec()))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssertionValue(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttributeValue(pub Vec<u8>);
