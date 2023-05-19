pub mod ecdsa;
pub mod ed25519;
pub mod rsa;

mod oid;

use pkcs8::LineEnding;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

use crate::error::*;

use self::oid::SignatureOid;

pub trait SchemeTrait {
	fn generate_key(&self) -> Result<Box<dyn PrivateKey>>;
}

pub trait PrivateKey: SignatureOid {
	fn to_subject_public_key_info(&self) -> Result<SubjectPublicKeyInfoOwned>;
	fn to_pem(&self, line_ending: LineEnding) -> Result<String>;

	fn signature_algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned {
			oid: self.signature_oid(),
			parameters: None,
		}
	}

	fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
}
