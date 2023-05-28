use der::{AnyRef, Decode};
use ed25519_dalek::pkcs8::{KeypairBytes, ALGORITHM_ID};
use ed25519_dalek::{Signer, SigningKey};
use pkcs8::{EncodePrivateKey, LineEnding};
use spki::{
	AlgorithmIdentifier, AlgorithmIdentifierRef, AssociatedAlgorithmIdentifier, EncodePublicKey,
	SignatureAlgorithmIdentifier, SubjectPublicKeyInfoOwned,
};

use common::*;

use super::{PrivateKey, SignatureStrategy};

#[derive(Default)]
pub struct Ed25519;

impl AssociatedAlgorithmIdentifier for Ed25519 {
	type Params = AnyRef<'static>;

	const ALGORITHM_IDENTIFIER: AlgorithmIdentifierRef<'static> = ALGORITHM_ID;
}

impl SignatureAlgorithmIdentifier for Ed25519 {
	type Params = AnyRef<'static>;

	const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> = ALGORITHM_ID;
}

impl SignatureStrategy for Ed25519 {
	fn generate_key(&self) -> Result<Box<dyn PrivateKey>> {
		let mut rng = rand::thread_rng();

		Ok(Box::new(Ed25519Key(SigningKey::generate(&mut rng))))
	}
}

pub struct Ed25519Key(SigningKey);

impl PrivateKey for Ed25519Key {
	fn to_subject_public_key_info(&self) -> Result<SubjectPublicKeyInfoOwned> {
		let public_key = self.0.verifying_key();

		Ok(SubjectPublicKeyInfoOwned::from_der(
			public_key.to_public_key_der()?.as_bytes(),
		)?)
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
