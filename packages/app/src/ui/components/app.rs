use std::rc::Rc;

use closure::closure;
use x509_cert::name::Name;
use yew::prelude::*;

use crate::ui::components::basic::*;
use crate::ui::components::*;
use crate::ui::hooks::*;
use gen::alt_name::AltName;
use gen::duration::parse_duration_str;
use gen::scheme::SignatureStrategy;
use gen::self_signed::gen_self_signed;
use gen::self_signed::SelfSignedCertOptions;

#[function_component]
pub fn App() -> Html {
	let scheme: Slot<Option<Rc<dyn SignatureStrategy>>> = use_slot_with_default();

	let subject: Slot<Name> = use_slot_with_default();
	let duration: Slot<String> = use_slot_with_default();

	let san: Slot<Vec<AltName>> = use_slot_with_default();

	let key: Slot<String> = use_slot_with_default();
	let crt: Slot<String> = use_slot_with_default();

	let onclick_generate = closure!(
		clone scheme,
		clone subject,
		clone duration,
		clone san,
		clone key,
		clone crt,
		|_| {
			if let Some(scheme) = (*scheme).as_ref() {
				let pair = gen_self_signed(
					scheme.as_ref(),
					SelfSignedCertOptions {
						issuer: subject.get(),
						subject: subject.get(),
						duration: parse_duration_str(&duration).unwrap(),
						san: (*san).clone(),
					},
				)
				.unwrap();

				key.set(pair.0);
				crt.set(pair.1);
			}
		}
	);

	html! {
		<div>
			<Scheme onchange={ scheme.change_handler() } />
			<Subject onchange={ subject.change_handler() } />
			<label>
				<span>{ "Duration" }</span>
				<Input slot={ duration } />
			</label>
			<SANList slot={ san } />
			<div>
				<button onclick={onclick_generate}>{ "Generate" }</button>
			</div>
			<Output title="Private Key" slot={ key } />
			<Output title="Certificate" slot={ crt } />
		</div>
	}
}
