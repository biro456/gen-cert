use std::fmt::Display;
use std::str::FromStr;

use enum_iterator::Sequence;
use web_sys::HtmlInputElement;
use yew::prelude::*;

use crate::ui::hooks::Slot;

pub trait Selectable:
	Copy + PartialEq + Display + Sequence + From<u8> + Into<u8> + 'static
{
	fn from_value(value: &str) -> Self {
		u8::from_str(&value).map(|val| val.into()).unwrap()
	}

	fn into_value(&self) -> String {
		Into::<u8>::into(*self).to_string()
	}
}

impl<T: Copy + PartialEq + Display + Sequence + From<u8> + Into<u8> + 'static> Selectable for T {}

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
