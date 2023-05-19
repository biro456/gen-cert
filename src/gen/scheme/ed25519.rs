use const_oid::ObjectIdentifier;
use der::asn1::BitString;
use der::referenced::RefToOwned;
use ed25519_dalek::pkcs8::{KeypairBytes, ALGORITHM_ID, ALGORITHM_OID};
use ed25519_dalek::{Signer, SigningKey};
use pkcs8::{EncodePrivateKey, LineEnding};
use spki::SubjectPublicKeyInfoOwned;

use crate::error::*;

use super::oid::SignatureOid;
use super::{PrivateKey, SchemeTrait};

#[derive(Default)]
pub struct Ed25519;

impl SchemeTrait for Ed25519 {
	fn generate_key(&self) -> Result<Box<dyn PrivateKey>> {
		let mut rng = rand::thread_rng();

		Ok(Box::new(Ed25519Key(SigningKey::generate(&mut rng))))
	}
}

pub struct Ed25519Key(SigningKey);

impl SignatureOid for Ed25519Key {
	fn signature_oid(&self) -> ObjectIdentifier {
		ALGORITHM_OID
	}
}

impl PrivateKey for Ed25519Key {
	fn to_subject_public_key_info(&self) -> Result<SubjectPublicKeyInfoOwned> {
		let public_key = self.0.verifying_key();

		Ok(SubjectPublicKeyInfoOwned {
			algorithm: ALGORITHM_ID.ref_to_owned(),
			subject_public_key: BitString::from_bytes(public_key.as_bytes())?,
		})
	}

	fn to_pem(&self, line_ending: LineEnding) -> Result<String> {
		let keypair_bytes = KeypairBytes {
			secret_key: self.0.to_bytes(),
			public_key: None,
		};

		Ok(keypair_bytes.to_pkcs8_pem(line_ending)?.to_string())
	}

	fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
		Ok(self.0.try_sign(data)?.to_vec())
	}
}
