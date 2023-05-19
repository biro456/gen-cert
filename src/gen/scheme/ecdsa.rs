use std::marker::PhantomData;

use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::BitString;
use der::Any;
use ecdsa::hazmat::{DigestPrimitive, SignPrimitive};
use ecdsa::{
	Signature, SignatureSize, SigningKey, ECDSA_SHA224_OID, ECDSA_SHA256_OID, ECDSA_SHA384_OID,
	ECDSA_SHA512_OID,
};
use elliptic_curve::generic_array::ArrayLength;
use elliptic_curve::ops::Invert;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::subtle::CtOption;
use elliptic_curve::{
	AffinePoint, CurveArithmetic, FieldBytesSize, PrimeCurve, PublicKey, Scalar, SecretKey,
};
use pkcs8::{EncodePrivateKey, LineEnding};
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use signature::hazmat::RandomizedPrehashSigner;
use spki::{AlgorithmIdentifierOwned, AssociatedAlgorithmIdentifier, SubjectPublicKeyInfoOwned};

use crate::error::*;

use super::oid::SignatureOid;
use super::{PrivateKey, SchemeTrait};

#[derive(Default)]
pub struct Ecdsa<C, D: Digest>(PhantomData<C>, PhantomData<D>)
where
	C: PrimeCurve + CurveArithmetic + AssociatedOid,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>;

impl<C, D: Digest + 'static> SchemeTrait for Ecdsa<C, D>
where
	EcdsaKey<C, D>: SignatureOid,
	C: PrimeCurve + CurveArithmetic + AssociatedOid + DigestPrimitive,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
	FieldBytesSize<C>: ModulusSize,
{
	fn generate_key(&self) -> Result<Box<dyn PrivateKey>> {
		let mut rng = rand::thread_rng();

		Ok(Box::new(EcdsaKey::<C, D>(
			SecretKey::<C>::random(&mut rng),
			PhantomData,
		)))
	}
}

pub struct EcdsaKey<C, D: Digest>(SecretKey<C>, PhantomData<D>)
where
	C: PrimeCurve + CurveArithmetic + DigestPrimitive,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>;

impl<C> SignatureOid for EcdsaKey<C, Sha224>
where
	C: PrimeCurve + CurveArithmetic + DigestPrimitive,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
{
	fn signature_oid(&self) -> ObjectIdentifier {
		ECDSA_SHA224_OID
	}
}

impl<C> SignatureOid for EcdsaKey<C, Sha256>
where
	C: PrimeCurve + CurveArithmetic + DigestPrimitive,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
{
	fn signature_oid(&self) -> ObjectIdentifier {
		ECDSA_SHA256_OID
	}
}

impl<C> SignatureOid for EcdsaKey<C, Sha384>
where
	C: PrimeCurve + CurveArithmetic + DigestPrimitive,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
{
	fn signature_oid(&self) -> ObjectIdentifier {
		ECDSA_SHA384_OID
	}
}

impl<C> SignatureOid for EcdsaKey<C, Sha512>
where
	C: PrimeCurve + CurveArithmetic + DigestPrimitive,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
{
	fn signature_oid(&self) -> ObjectIdentifier {
		ECDSA_SHA512_OID
	}
}

impl<C, D: Digest> PrivateKey for EcdsaKey<C, D>
where
	Self: SignatureOid,
	C: PrimeCurve + CurveArithmetic + AssociatedOid + DigestPrimitive,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
	FieldBytesSize<C>: ModulusSize,
{
	fn to_subject_public_key_info(&self) -> Result<SubjectPublicKeyInfoOwned> {
		let public_key_bytes = self.0.public_key().to_encoded_point(true);

		Ok(SubjectPublicKeyInfoOwned {
			algorithm: AlgorithmIdentifierOwned {
				oid: PublicKey::<C>::ALGORITHM_IDENTIFIER.oid,
				parameters: PublicKey::<C>::ALGORITHM_IDENTIFIER
					.parameters
					.map(Any::from),
			},
			subject_public_key: BitString::from_bytes(public_key_bytes.as_bytes())?,
		})
	}

	fn to_pem(&self, line_ending: LineEnding) -> Result<String> {
		Ok(self.0.to_pkcs8_pem(line_ending)?.as_str().to_owned())
	}

	fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
		let mut rng = rand::thread_rng();

		let signing_key: SigningKey<C> = self.0.clone().into();

		let digest = D::new_with_prefix(data);

		let signature: Signature<C> =
			signing_key.sign_prehash_with_rng(&mut rng, &digest.finalize())?;

		Ok(signature.to_vec())
	}
}
