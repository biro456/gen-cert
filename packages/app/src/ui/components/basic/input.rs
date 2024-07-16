use web_sys::HtmlInputElement;
use yew::prelude::*;

use crate::ui::hooks::Slot;

#[derive(Properties, PartialEq)]
pub struct InputProps {
	#[prop_or_default]
	pub slot: Option<Slot<String>>,
}

#[function_component]
pub fn Input(props: &InputProps) -> Html {
	let (value, onchange) = props
		.slot
		.clone()
		.map(|slot| {
			let callback = slot.change_handler();

			(slot.get(), move |evt: Event| {
				let target = evt.target_dyn_into::<HtmlInputElement>().unwrap();

				callback.emit(target.value());
			})
		})
		.unzip();

	html! {
		<input {value} {onchange} />
	}
}
