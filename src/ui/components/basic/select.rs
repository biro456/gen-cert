use std::fmt::Display;
use std::str::FromStr;

use enum_iterator::Sequence;
use wasm_bindgen::JsCast;
use web_sys::{HtmlOptionElement, HtmlSelectElement};
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
pub struct SelectProps<T: Selectable> {
	#[prop_or_default]
	pub slot: Option<Slot<T>>,
}

#[function_component]
pub fn Select<T: Selectable>(props: &SelectProps<T>) -> Html {
	let (value, onchange) = props
		.slot
		.clone()
		.map(|slot| {
			let callback = slot.change_handler();

			(slot.get(), move |evt: Event| {
				let target = evt.target_dyn_into::<HtmlSelectElement>().unwrap();
				let selected = target
					.selected_options()
					.get_with_index(0)
					.unwrap()
					.dyn_into::<HtmlOptionElement>()
					.unwrap();

				callback.emit(T::from_value(&selected.value()));
			})
		})
		.unzip();

	html! {
		<select {onchange}>
			{
				for enum_iterator::all::<T>()
					.map(|item| {
						html!(
							<option value={ item.into_value() }
								selected={ value == Some(item) }>
								{ format!("{}", item) }
							</option>
						)
					})
			}
		</select>
	}
}
