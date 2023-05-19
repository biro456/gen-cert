use const_oid::ObjectIdentifier;

pub trait SignatureOid {
	fn signature_oid(&self) -> ObjectIdentifier;
}
