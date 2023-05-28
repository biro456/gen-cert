use std::rc::Rc;

use enum_iterator::Sequence;
use parse_display::Display;
use yew::prelude::*;

use gen::scheme::ecdsa::{EcdsaK256, EcdsaP256, EcdsaP384};
use gen::scheme::ed25519::Ed25519;
use gen::scheme::rsa::{
	Rsa2048WithSha256, Rsa2048WithSha384, Rsa2048WithSha512, Rsa4096WithSha256, Rsa4096WithSha384,
	Rsa4096WithSha512,
};
use gen::scheme::{new_scheme, SignatureStrategy};

use crate::ui::components::basic::*;
use crate::ui::hooks::*;

#[derive(PartialEq, Properties)]
pub struct SchemeSelectorProps {
	#[prop_or_default]
	pub onchange: Option<Callback<Option<Rc<dyn SignatureStrategy>>, ()>>,
}

#[function_component]
pub fn Scheme(props: &SchemeSelectorProps) -> Html {
	let signature_algorithm: Slot<Option<SchemeName>> = use_slot(|| None);

	let onchange = props.onchange.clone();

	use_effect_with_deps(
		move |signature_algorithm| {
			if let Some(onchange) = onchange {
				onchange.emit(signature_algorithm.map(|alg| alg.into_scheme()))
			}
		},
		*signature_algorithm,
	);

	html! {
		<div>
			<Select<SchemeName> slot={ signature_algorithm } />
		</div>
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Display, Sequence)]
enum SchemeName {
	#[display("EdDSA using Curve25519 with SHA-512")]
	Ed25519,
	#[display("ECDSA using P-256 with SHA-256")]
	EcdsaP256,
	#[display("ECDSA using P-384 with SHA-384")]
	EcdsaP384,
	#[display("ECDSA using K-256 curve with SHA-256")]
	EcdsaK256,
	#[display("RSA using 2048 bit key with SHA-256")]
	Rsa2048WithSha256,
	#[display("RSA using 4096 bit key with SHA-256")]
	Rsa4096WithSha256,
	#[display("RSA using 2048 bit key with SHA-384")]
	Rsa2048WithSha384,
	#[display("RSA using 4096 bit key with SHA-384")]
	Rsa4096WithSha384,
	#[display("RSA using 2048 bit key with SHA-512")]
	Rsa2048WithSha512,
	#[display("RSA using 4096 bit key with SHA-512")]
	Rsa4096WithSha512,
}

impl SchemeName {
	fn into_scheme(&self) -> Rc<dyn SignatureStrategy> {
		match self {
			SchemeName::Ed25519 => new_scheme::<Ed25519>(),
			SchemeName::EcdsaP256 => new_scheme::<EcdsaP256>(),
			SchemeName::EcdsaP384 => new_scheme::<EcdsaP384>(),
			SchemeName::EcdsaK256 => new_scheme::<EcdsaK256>(),
			SchemeName::Rsa2048WithSha256 => new_scheme::<Rsa2048WithSha256>(),
			SchemeName::Rsa4096WithSha256 => new_scheme::<Rsa4096WithSha256>(),
			SchemeName::Rsa2048WithSha384 => new_scheme::<Rsa2048WithSha384>(),
			SchemeName::Rsa4096WithSha384 => new_scheme::<Rsa4096WithSha384>(),
			SchemeName::Rsa2048WithSha512 => new_scheme::<Rsa2048WithSha512>(),
			SchemeName::Rsa4096WithSha512 => new_scheme::<Rsa4096WithSha512>(),
		}
	}
}
