pub mod ecdsa;
pub mod ed25519;
pub mod rsa;

use std::rc::Rc;

use pkcs8::LineEnding;
use spki::{
	DynAssociatedAlgorithmIdentifier, DynSignatureAlgorithmIdentifier, SubjectPublicKeyInfoOwned,
};

use common::*;

pub trait SignatureStrategy:
	DynAssociatedAlgorithmIdentifier + DynSignatureAlgorithmIdentifier
{
	fn generate_key(&self) -> Result<Box<dyn PrivateKey>>;
}

pub trait PrivateKey {
	fn to_subject_public_key_info(&self) -> Result<SubjectPublicKeyInfoOwned>;
	fn to_pem(&self, line_ending: LineEnding) -> Result<String>;

	fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
}

pub fn new_scheme<S: SignatureStrategy + Default + 'static>() -> Rc<dyn SignatureStrategy> {
	Rc::new(S::default())
}
