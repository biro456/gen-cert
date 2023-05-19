use std::rc::Rc;

use closure::closure;
use x509_cert::name::Name;
use yew::prelude::*;

use crate::gen::alt_name::AltName;
use crate::gen::duration::parse_duration_str;
use crate::gen::scheme::SchemeTrait;
use crate::gen::self_signed::gen_self_signed;
use crate::gen::self_signed::SelfSignedCertOptions;
use crate::ui::components::basic::*;
use crate::ui::components::*;
use crate::ui::hooks::*;

#[function_component]
pub fn App() -> Html {
	let scheme: Slot<Option<Rc<dyn SchemeTrait>>> = use_slot_with_default();

	let subject: Slot<Name> = use_slot_with_default();
	let duration = use_string();

	let san: Slot<Vec<AltName>> = use_slot_with_default();

	let key = use_string();
	let crt = use_string();

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
					(*scheme).clone(),
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
