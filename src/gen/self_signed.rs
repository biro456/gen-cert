use std::rc::Rc;
use std::time::Duration;

use der::EncodePem;
use pkcs8::LineEnding;
use x509_cert::name::Name;

use crate::prelude::*;

use super::alt_name::AltName;
use super::certificate::{gen_tbs_certificate, sign_certificate, OptionsBuilder};
use super::scheme::SchemeTrait;

#[derive(Debug, Clone)]
pub struct SelfSignedCertOptions {
	pub issuer: Name,
	pub subject: Name,
	pub duration: Duration,
	pub san: Vec<AltName>,
}

pub fn gen_self_signed(
	scheme: Rc<dyn SchemeTrait>,
	options: SelfSignedCertOptions,
) -> Result<(String, String)> {
	let key = scheme.generate_key()?;

	let tbs_cert = gen_tbs_certificate(
		&key,
		OptionsBuilder::default()
			.issuer(options.issuer)
			.subject(options.subject)
			.duration(options.duration)
			.is_ca()
			.alt_names(options.san)
			.build()?,
	)?;

	let crt = sign_certificate(&key, tbs_cert)?;

	Ok((key.to_pem(LineEnding::LF)?, crt.to_pem(LineEnding::LF)?))
}
