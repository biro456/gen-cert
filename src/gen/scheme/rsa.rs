use std::marker::PhantomData;

use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::BitString;
use der::referenced::RefToOwned;
use der::Encode;
use pkcs1::UintRef;
use pkcs8::{EncodePrivateKey, LineEnding};
use rsa::pkcs1v15::SigningKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::{RandomizedSigner, SignatureEncoding};
use spki::{SubjectPublicKeyInfoOwned};

use crate::error::*;

use super::{PrivateKey, SchemeTrait};
use super::oid::SignatureOid;

#[derive(Default)]
pub struct Rsa<const SIZE: usize, D: Digest + AssociatedOid>(PhantomData<D>);

impl<const SIZE: usize, D: Digest + AssociatedOid + 'static> SchemeTrait for Rsa<SIZE, D>
where
	RsaKey<D>: SignatureOid,
{
	fn generate_key(&self) -> Result<Box<dyn PrivateKey>> {
		let mut rng = rand::thread_rng();

		Ok(Box::new(RsaKey::<D>(
			RsaPrivateKey::new(&mut rng, SIZE)?,
			PhantomData,
		)))
	}
}

struct RsaKey<D: Digest>(RsaPrivateKey, PhantomData<D>);

impl SignatureOid for RsaKey<Sha256> {
	fn signature_oid(&self) -> ObjectIdentifier {
		const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION
	}
}

impl SignatureOid for RsaKey<Sha384> {
	fn signature_oid(&self) -> ObjectIdentifier {
		const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION
	}
}

impl SignatureOid for RsaKey<Sha512> {
	fn signature_oid(&self) -> ObjectIdentifier {
		const_oid::db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION
	}
}

impl<D: Digest + AssociatedOid> PrivateKey for RsaKey<D>
where
	Self: SignatureOid,
{
	fn to_subject_public_key_info(&self) -> Result<SubjectPublicKeyInfoOwned> {
		let modulus = self.0.n().to_bytes_be();
		let public_exponent = self.0.e().to_bytes_be();

		let subject_public_key = pkcs1::RsaPublicKey {
			modulus: UintRef::new(&modulus)?,
			public_exponent: UintRef::new(&public_exponent)?,
		}
		.to_der()?;

		Ok(SubjectPublicKeyInfoOwned {
			algorithm: pkcs1::ALGORITHM_ID.ref_to_owned(),
			subject_public_key: BitString::from_bytes(&subject_public_key)?,
		})
	}

	fn to_pem(&self, line_ending: LineEnding) -> Result<String> {
		Ok(self.0.to_pkcs8_pem(line_ending)?.as_str().to_owned())
	}

	fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
		let mut rng = rand::thread_rng();

		let signing_key = SigningKey::<D>::new(self.0.clone());

		Ok(signing_key.try_sign_with_rng(&mut rng, data)?.to_vec())
	}
}
