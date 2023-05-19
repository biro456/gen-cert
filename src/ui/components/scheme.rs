use std::rc::Rc;

use enum_iterator::Sequence;
use num_enum::{FromPrimitive, IntoPrimitive};
use parse_display::Display;
use yew::prelude::*;

use crate::gen::scheme::ecdsa::Ecdsa;
use crate::gen::scheme::ed25519::Ed25519;
use crate::gen::scheme::rsa::Rsa;
use crate::gen::scheme::SchemeTrait as SchemeTrait;
use crate::ui::components::basic::*;
use crate::ui::hooks::*;

#[derive(PartialEq, Properties)]
pub struct SchemeSelectorProps {
	#[prop_or_default]
	pub onchange: Option<Callback<Option<Rc<dyn SchemeTrait>>, ()>>,
}

#[function_component]
pub fn Scheme(props: &SchemeSelectorProps) -> Html {
	let signature_algorithm = use_slot(|| SchemeName::None);

	let onchange = props.onchange.clone();

	use_effect_with_deps(
		move |signature_algorithm| {
			if let Some(onchange) = onchange {
				onchange.emit(signature_algorithm.into_scheme())
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

#[derive(Debug, Clone, Copy, PartialEq, Display, Sequence, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
enum SchemeName {
	#[display("")]
	#[num_enum(default)]
	None,
	#[display("EdDSA using Curve25519 with SHA-512")]
	Ed25519,
	#[display("EdDSA using Curve448 with SHAKE256")]
	Ed448,
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
	fn into_scheme(&self) -> Option<Rc<dyn SchemeTrait>> {
		match self {
			SchemeName::None => None,
			SchemeName::Rsa2048WithSha256 => {
				Some(Rc::new(Rsa::<2048, sha2::Sha256>::default()))
			}
			SchemeName::Rsa4096WithSha256 => {
				Some(Rc::new(Rsa::<4096, sha2::Sha256>::default()))
			}
			SchemeName::Rsa2048WithSha384 => {
				Some(Rc::new(Rsa::<2048, sha2::Sha384>::default()))
			}
			SchemeName::Rsa4096WithSha384 => {
				Some(Rc::new(Rsa::<4096, sha2::Sha384>::default()))
			}
			SchemeName::Rsa2048WithSha512 => {
				Some(Rc::new(Rsa::<2048, sha2::Sha512>::default()))
			}
			SchemeName::Rsa4096WithSha512 => {
				Some(Rc::new(Rsa::<4096, sha2::Sha512>::default()))
			}
			SchemeName::EcdsaP256 => {
				Some(Rc::new(Ecdsa::<p256::NistP256, sha2::Sha256>::default()))
			}
			SchemeName::EcdsaP384 => {
				Some(Rc::new(Ecdsa::<p384::NistP384, sha2::Sha384>::default()))
			}
			SchemeName::EcdsaK256 => {
				Some(Rc::new(Ecdsa::<k256::Secp256k1, sha2::Sha256>::default()))
			}
			SchemeName::Ed25519 => Some(Rc::new(Ed25519::default())),
			SchemeName::Ed448 => todo!(),
		}
	}
}
