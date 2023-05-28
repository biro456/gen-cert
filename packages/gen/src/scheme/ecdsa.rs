use std::marker::PhantomData;

use const_oid::AssociatedOid;
use der::asn1::BitString;
use der::{Any, AnyRef};
use ecdsa::hazmat::{DigestPrimitive, SignPrimitive};
use ecdsa::{Signature, SignatureSize, SigningKey};
use elliptic_curve::generic_array::ArrayLength;
use elliptic_curve::ops::Invert;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::subtle::CtOption;
use elliptic_curve::{
	AffinePoint, CurveArithmetic, FieldBytesSize, PrimeCurve, PublicKey, Scalar, SecretKey,
};
use k256::Secp256k1;
use p256::NistP256;
use p384::NistP384;
use pkcs8::{EncodePrivateKey, LineEnding};
use signature::RandomizedSigner;
use spki::{
	AlgorithmIdentifier, AlgorithmIdentifierOwned, AssociatedAlgorithmIdentifier,
	SignatureAlgorithmIdentifier, SubjectPublicKeyInfoOwned,
};

use common::*;

use super::{PrivateKey, SignatureStrategy};

pub type EcdsaP256 = Ecdsa<NistP256>;
pub type EcdsaP384 = Ecdsa<NistP384>;
pub type EcdsaK256 = Ecdsa<Secp256k1>;

#[derive(Default)]
pub struct Ecdsa<C>(PhantomData<C>);

impl<C> AssociatedAlgorithmIdentifier for Ecdsa<C>
where
	C: AssociatedOid + CurveArithmetic + PrimeCurve,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
{
	type Params = <SigningKey<C> as AssociatedAlgorithmIdentifier>::Params;

	const ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
		SigningKey::<C>::ALGORITHM_IDENTIFIER;
}

impl<C> SignatureAlgorithmIdentifier for Ecdsa<C>
where
	C: PrimeCurve + CurveArithmetic,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
	Signature<C>: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
	type Params = <SigningKey<C> as SignatureAlgorithmIdentifier>::Params;

	const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
		SigningKey::<C>::SIGNATURE_ALGORITHM_IDENTIFIER;
}

impl<C> SignatureStrategy for Ecdsa<C>
where
	C: PrimeCurve + CurveArithmetic + AssociatedOid + DigestPrimitive,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>,
	AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
	FieldBytesSize<C>: ModulusSize,
	<C as DigestPrimitive>::Digest: AssociatedOid,
{
	fn generate_key(&self) -> Result<Box<dyn PrivateKey>> {
		let mut rng = rand::thread_rng();

		Ok(Box::new(EcdsaKey(SecretKey::<C>::random(&mut rng))))
	}
}

pub struct EcdsaKey<C>(SecretKey<C>)
where
	C: PrimeCurve + CurveArithmetic + DigestPrimitive,
	Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
	SignatureSize<C>: ArrayLength<u8>;

impl<C> PrivateKey for EcdsaKey<C>
where
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

		Ok(signing_key.try_sign_with_rng(&mut rng, data)?.to_vec())
	}
}
