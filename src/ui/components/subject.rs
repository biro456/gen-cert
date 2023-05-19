use const_oid::db::rfc4519;
use const_oid::ObjectIdentifier;
use der::asn1::{PrintableStringRef, SetOfVec, Utf8StringRef};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use yew::prelude::*;

use crate::prelude::*;

use crate::ui::components::basic::*;
use crate::ui::hooks::*;

#[derive(PartialEq, Properties)]
pub struct SubjectProps {
	#[prop_or_default]
	pub onchange: Option<Callback<Name, ()>>,
}

#[function_component]
pub fn Subject(props: &SubjectProps) -> Html {
	let common_name = use_string();
	let organization = use_string();
	let organizational_unit = use_string();
	let locality = use_string();
	let state = use_string();
	let country = use_string();

	let onchange = props.onchange.clone();

	use_effect_with_deps(
		|(cn, o, ou, l, s, c)| {
			if let Some(onchange) = onchange {
				let mut parts = Vec::<RelativeDistinguishedName>::default();

				push_if_not_empty::<Utf8StringRef>(&mut parts, rfc4519::CN, &cn);
				push_if_not_empty::<Utf8StringRef>(&mut parts, rfc4519::O, &o);
				push_if_not_empty::<Utf8StringRef>(&mut parts, rfc4519::OU, &ou);
				push_if_not_empty::<Utf8StringRef>(&mut parts, rfc4519::L, &l);
				push_if_not_empty::<Utf8StringRef>(&mut parts, rfc4519::ST, &s);
				push_if_not_empty::<PrintableStringRef>(&mut parts, rfc4519::C, &c);

				let value = RdnSequence(parts);

				onchange.emit(value);
			}
		},
		(
			common_name.get(),
			organization.get(),
			organizational_unit.get(),
			locality.get(),
			state.get(),
			country.get(),
		),
	);

	html! {
		<div>
			<label>
				<span>{ "Common Name (CN)" }</span>
				<Input slot={ common_name } />
			</label>
			<label>
				<span>{ "Organization (O)" }</span>
				<Input slot={ organization } />
			</label>
			<label>
				<span>{ "Organizational Unit (OU)" }</span>
				<Input slot={ organizational_unit } />
			</label>
			<label>
				<span>{ "Locality (L)" }</span>
				<Input slot={ locality } />
			</label>
			<label>
				<span>{ "State (ST)" }</span>
				<Input slot={ state } />
			</label>
			<label>
				<span>{ "Country Name (C)" }</span>
				<Input slot={ country } />
			</label>
		</div>
	}
}

#[inline]
fn push_if_not_empty<'a, T: IntoAttributeTypeAndValue<'a>>(
	parts: &mut Vec<RelativeDistinguishedName>,
	oid: ObjectIdentifier,
	value: &'a str,
) {
	if value == "" {
		return;
	};

	if let Ok(set) =
		T::into_attr(oid, value.as_bytes()).and_then(|attr| Ok(SetOfVec::try_from([attr])?))
	{
		parts.push(RelativeDistinguishedName(set));
	}
}

trait IntoAttributeTypeAndValue<'a> {
	fn into_attr(oid: ObjectIdentifier, bytes: &'a [u8]) -> Result<AttributeTypeAndValue>;
}

impl<'a> IntoAttributeTypeAndValue<'a> for Utf8StringRef<'a> {
	fn into_attr(oid: ObjectIdentifier, bytes: &'a [u8]) -> Result<AttributeTypeAndValue> {
		let value = Utf8StringRef::new(bytes)?;

		Ok(AttributeTypeAndValue {
			oid,
			value: value.into(),
		})
	}
}

impl<'a> IntoAttributeTypeAndValue<'a> for PrintableStringRef<'a> {
	fn into_attr(oid: ObjectIdentifier, bytes: &'a [u8]) -> Result<AttributeTypeAndValue> {
		let value = PrintableStringRef::new(bytes)?;

		Ok(AttributeTypeAndValue {
			oid,
			value: value.into(),
		})
	}
}
