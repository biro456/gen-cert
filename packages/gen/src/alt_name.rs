use std::net::IpAddr;
use std::str::FromStr;

use der::asn1::{Ia5String, OctetString};
use enum_iterator::Sequence;
use num_enum::{FromPrimitive, IntoPrimitive};
use parse_display::Display;
use x509_cert::ext::pkix::name::GeneralName;

use common::*;

#[derive(
	Debug, Clone, Copy, PartialEq, Display, Sequence, Default, FromPrimitive, IntoPrimitive,
)]
#[repr(u8)]
pub enum AltNameType {
	#[default]
	DNS,
	IP,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AltName {
	DNS(String),
	IP(IpAddr),
}

impl AltName {
	pub fn parse(typ: AltNameType, val: &str) -> Self {
		match typ {
			AltNameType::DNS => AltName::DNS(val.to_owned()),
			AltNameType::IP => AltName::IP(IpAddr::from_str(val).unwrap()),
		}
	}

	pub fn r#type(&self) -> &'static str {
		match self {
			AltName::DNS(_) => "DNS",
			AltName::IP(_) => "IP",
		}
	}

	pub fn text(&self) -> String {
		match self {
			AltName::DNS(name) => name.clone(),
			AltName::IP(ip) => ip.to_string(),
		}
	}
}

impl TryFrom<AltName> for GeneralName {
	type Error = Error;

	fn try_from(value: AltName) -> Result<GeneralName, Self::Error> {
		Ok(match value {
			AltName::DNS(name) => GeneralName::DnsName(Ia5String::new(&name)?),
			AltName::IP(ip) => GeneralName::IpAddress(match ip {
				IpAddr::V4(ip) => OctetString::new(ip.octets())?,
				IpAddr::V6(ip) => OctetString::new(ip.octets())?,
			}),
		})
	}
}
