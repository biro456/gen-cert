use std::time::Duration;

use const_oid::AssociatedOid;
use der::asn1::{BitString, GeneralizedTime, OctetString};
use der::Encode;
use derive_builder::Builder;
use time::{OffsetDateTime, PrimitiveDateTime};
use uuid::Uuid;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages, SubjectAltName};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate, Version};

use crate::error::*;
use crate::gen::scheme::PrivateKey;

use super::alt_name::AltName;

#[derive(Debug, Builder)]
#[builder(pattern = "owned")]
pub struct Options {
	#[builder(setter(into))]
	issuer: Name,
	#[builder(setter)]
	subject: Name,
	#[builder(setter(into))]
	duration: Duration,
	#[builder(default = "false", setter(custom))]
	is_ca: bool,
	#[builder(setter(into))]
	alt_names: Vec<AltName>,
}

impl OptionsBuilder {
	pub fn is_ca(mut self) -> Self {
		self.is_ca = Some(true);

		self
	}
}

pub fn gen_tbs_certificate(
	key: impl AsRef<dyn PrivateKey>,
	options: Options,
) -> Result<TbsCertificate> {
	let key = key.as_ref();

	let now = OffsetDateTime::now_utc();
	let expiry = now.clone() + options.duration;

	let not_before = Time::GeneralTime(GeneralizedTime::from_date_time(
		PrimitiveDateTime::new(now.date(), now.time()).try_into()?,
	));
	let not_after = Time::GeneralTime(GeneralizedTime::from_date_time(
		PrimitiveDateTime::new(expiry.date(), expiry.time()).try_into()?,
	));

	let tbs_certificate = TbsCertificate {
		version: Version::V3,

		serial_number: SerialNumber::new(Uuid::new_v4().as_bytes())?,
		signature: key.signature_algorithm(),

		issuer: options.issuer,
		issuer_unique_id: None,

		subject: options.subject,
		subject_unique_id: None,
		subject_public_key_info: key.to_subject_public_key_info()?,

		validity: Validity {
			not_before,
			not_after,
		},

		extensions: Some(vec![
			BasicConstraints {
				ca: options.is_ca,
				path_len_constraint: None,
			}
			.to_extension(true)?,
			KeyUsage::from(if options.is_ca {
				KeyUsages::DigitalSignature | KeyUsages::KeyCertSign
			} else {
				KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment
			})
			.to_extension(options.is_ca)?,
			SubjectAltName::from(
				options
					.alt_names
					.into_iter()
					.map(TryFrom::try_from)
					.collect::<Result<Vec<GeneralName>>>()?,
			)
			.to_extension(true)?,
		]),
	};

	Ok(tbs_certificate)
}

pub fn sign_certificate(
	key: impl AsRef<dyn PrivateKey>,
	tbs_certificate: TbsCertificate,
) -> Result<Certificate> {
	let key = key.as_ref();

	let signature = key.sign(&tbs_certificate.to_der()?)?;

	let certificate = Certificate {
		tbs_certificate,
		signature_algorithm: key.signature_algorithm(),
		signature: BitString::from_bytes(&signature)?,
	};

	Ok(certificate)
}

trait ToExtension: AssociatedOid + Encode {
	fn to_extension(&self, critical: bool) -> Result<Extension> {
		Ok(Extension {
			extn_id: Self::OID,
			extn_value: OctetString::new(self.to_der()?)?,
			critical,
		})
	}
}

impl<T: AssociatedOid + Encode> ToExtension for T {}
