use std::marker::PhantomData;

use const_oid::AssociatedOid;
use der::Decode;
use pkcs8::{EncodePrivateKey, LineEnding};
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::{RandomizedSigner, SignatureEncoding};
use spki::{
	AlgorithmIdentifier, AssociatedAlgorithmIdentifier, EncodePublicKey,
	SignatureAlgorithmIdentifier, SubjectPublicKeyInfoOwned,
};

use common::*;

use super::{PrivateKey, SignatureStrategy};

pub type Rsa2048WithSha256 = Rsa<2048, Sha256>;
pub type Rsa2048WithSha384 = Rsa<2048, Sha384>;
pub type Rsa2048WithSha512 = Rsa<2048, Sha512>;

pub type Rsa4096WithSha256 = Rsa<4096, Sha256>;
pub type Rsa4096WithSha384 = Rsa<4096, Sha384>;
pub type Rsa4096WithSha512 = Rsa<4096, Sha512>;

#[derive(Default)]
pub struct Rsa<const SIZE: usize, D>(PhantomData<D>);

impl<const SIZE: usize, D: Digest + 'static> AssociatedAlgorithmIdentifier for Rsa<SIZE, D>
where
	SigningKey<D>: AssociatedAlgorithmIdentifier,
{
	type Params = <SigningKey<D> as AssociatedAlgorithmIdentifier>::Params;

	const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
		SigningKey::<D>::ALGORITHM_IDENTIFIER;
}

impl<const SIZE: usize, D: Digest + 'static> SignatureAlgorithmIdentifier for Rsa<SIZE, D>
where
	SigningKey<D>: SignatureAlgorithmIdentifier,
{
	type Params = <SigningKey<D> as SignatureAlgorithmIdentifier>::Params;

	const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
		<SigningKey<D> as SignatureAlgorithmIdentifier>::SIGNATURE_ALGORITHM_IDENTIFIER;
}

impl<const SIZE: usize, D: Digest + AssociatedOid + 'static> SignatureStrategy for Rsa<SIZE, D>
where
	SigningKey<D>: SignatureAlgorithmIdentifier,
{
	fn generate_key(&self) -> Result<Box<dyn PrivateKey>> {
		let mut rng = rand::thread_rng();

		Ok(Box::new(RsaKey(SigningKey::<D>::random(&mut rng, SIZE)?)))
	}
}

struct RsaKey<D: Digest>(SigningKey<D>);

impl<D: Digest + AssociatedOid> PrivateKey for RsaKey<D> {
	fn to_subject_public_key_info(&self) -> Result<SubjectPublicKeyInfoOwned> {
		let public_key = VerifyingKey::<D>::new(RsaPublicKey::from(self.0.as_ref()));

		Ok(SubjectPublicKeyInfoOwned::from_der(
			public_key.to_public_key_der()?.as_bytes(),
		)?)
	}

	fn to_pem(&self, line_ending: LineEnding) -> Result<String> {
		Ok(self.0.to_pkcs8_pem(line_ending)?.as_str().to_owned())
	}

	fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
		let mut rng = rand::thread_rng();

		Ok(self.0.try_sign_with_rng(&mut rng, data)?.to_vec())
	}
}
