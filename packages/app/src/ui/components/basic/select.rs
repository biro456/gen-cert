use std::fmt::Display;

use closure::closure;
use enum_iterator::Sequence;
use wasm_bindgen::JsCast;
use web_sys::{HtmlOptionElement, HtmlSelectElement};
use yew::prelude::*;

use crate::ui::hooks::Slot;

pub trait Selectable: Copy + PartialEq + Display + Sequence + 'static {}

impl<T: Copy + PartialEq + Display + Sequence + 'static> Selectable for T {}

#[derive(Properties, PartialEq)]
pub struct SelectProps<T: Selectable> {
	#[prop_or_default]
	pub slot: Option<Slot<Option<T>>>,
}

#[function_component]
pub fn Select<T: Selectable>(props: &SelectProps<T>) -> Html {
	let items: Vec<_> = enum_iterator::all::<T>().collect();

	let (value, onchange) = props
		.slot
		.clone()
		.map(closure!(clone items, |slot| {
			let callback = slot.change_handler();

			(slot.get(), move |evt: Event| {
				let target = evt.target_dyn_into::<HtmlSelectElement>().unwrap();
				let selected = target
					.selected_options()
					.get_with_index(0)
					.unwrap()
					.dyn_into::<HtmlOptionElement>()
					.unwrap();

				let value = usize::from_str_radix(&selected.value(), 10).unwrap();

				callback.emit(if value == 0 { None } else { Some(items.get(value - 1).unwrap().clone()) });
			})
		}))
		.unzip();

	let value = value.flatten();

	html! {
		<select {onchange}>
			<option value="0" selected={ value.is_none() } />
			{
				for items
					.clone()
					.into_iter()
					.enumerate()
					.map(|(index, item)| {
						html!(
							<option value={ (index + 1).to_string() }
								selected={ value == Some(item) }>
								{ format!("{}", item) }
							</option>
						)
					})
			}
		</select>
	}
}
