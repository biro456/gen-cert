use std::time::Duration;

use der::EncodePem;
use pkcs8::LineEnding;
use x509_cert::name::Name;

use common::*;

use super::alt_name::AltName;
use super::certificate::{gen_tbs_certificate, sign_certificate, OptionsBuilder};
use super::scheme::SignatureStrategy;

#[derive(Debug, Clone)]
pub struct SelfSignedCertOptions {
	pub issuer: Name,
	pub subject: Name,
	pub duration: Duration,
	pub san: Vec<AltName>,
}

pub fn gen_self_signed(
	strategy: &dyn SignatureStrategy,
	options: SelfSignedCertOptions,
) -> Result<(String, String)> {
	let key = strategy.generate_key()?;

	let tbs_cert = gen_tbs_certificate(
		strategy,
		key.as_ref(),
		OptionsBuilder::default()
			.issuer(options.issuer)
			.subject(options.subject)
			.duration(options.duration)
			.is_ca()
			.alt_names(options.san)
			.build()?,
	)?;

	let crt = sign_certificate(strategy, key.as_ref(), tbs_cert)?;

	Ok((key.to_pem(LineEnding::LF)?, crt.to_pem(LineEnding::LF)?))
}
