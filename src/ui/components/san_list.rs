use std::str::FromStr;

use enum_iterator::all;
use num_enum::FromPrimitive;
use wasm_bindgen::JsCast;
use web_sys::{HtmlInputElement, HtmlOptionElement, HtmlSelectElement};
use yew::prelude::*;

use crate::gen::alt_name::{AltName, AltNameType};
use crate::ui::hooks::*;

#[derive(Debug, PartialEq, Properties)]
pub struct SANListProps {
	#[prop_or_default]
	pub slot: Option<Slot<Vec<AltName>>>,
}

#[derive(Debug)]
pub struct SANList {
	list: Vec<AltName>,
	to_add_type: AltNameType,
	to_add_value: String,
}

#[derive(Debug)]
pub enum SANListMessage {
	UpdateToAddType(AltNameType),
	UpdateToAddValue(String),
	Add,
	Remove(usize),
}

impl Component for SANList {
	type Properties = SANListProps;
	type Message = SANListMessage;

	fn create(ctx: &Context<Self>) -> Self {
		Self {
			list: ctx
				.props()
				.slot
				.clone()
				.map(|s| s.get())
				.unwrap_or_default(),
			to_add_type: AltNameType::default(),
			to_add_value: String::default(),
		}
	}

	fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
		match msg {
			SANListMessage::UpdateToAddType(value) => {
				self.to_add_type = value.clone();
				false
			}
			SANListMessage::UpdateToAddValue(value) => {
				self.to_add_value = value.clone();
				false
			}
			SANListMessage::Add => {
				self.list
					.push(AltName::parse(self.to_add_type, &self.to_add_value));

				true
			}
			SANListMessage::Remove(index) => {
				self.list.remove(index);

				true
			}
		}
	}

	fn view(&self, ctx: &Context<Self>) -> Html {
		let onchange_to_add_type = ctx.link().callback(|evt: Event| {
			let target = evt.target_dyn_into::<HtmlSelectElement>().unwrap();
			let selected = target
				.selected_options()
				.item(0)
				.unwrap()
				.dyn_into::<HtmlOptionElement>()
				.unwrap();

			let value = AltNameType::from_primitive(FromStr::from_str(&selected.value()).unwrap());

			SANListMessage::UpdateToAddType(value)
		});

		let onchange_to_add_value = ctx.link().callback(|evt: Event| {
			let target = evt.target_dyn_into::<HtmlInputElement>().unwrap();
			let value = target.value();

			SANListMessage::UpdateToAddValue(value)
		});

		let onclick_add = ctx.link().callback(|_| SANListMessage::Add);

		let onclick_remove = ctx
			.link()
			.callback(|index: usize| SANListMessage::Remove(index));

		html! {
			<div>
				<span>{ "Subject Alternative Name" }</span>
				<ul>
					{
						for self.list.iter()
							.enumerate()
							.map(|(index, alt_name)| {
								let onclick_remove = onclick_remove.clone();

								html!(
									<SANItem alt_name={ alt_name.clone() } onremove={ move |_| { onclick_remove.emit(index) } } />
								)
							})
					}
				</ul>
				<div>
					<select onchange={ onchange_to_add_type }>
						{ for all::<AltNameType>().map(|ant| {
							html!(
								<option value={ u8::from(ant).to_string() }
									selected={ self.to_add_type == ant }>
									{ format!("{}", ant) }
								</option>
							)
						}) }
					</select>
					<input value={ self.to_add_value.clone() } onchange={ onchange_to_add_value } />
					<button onclick={ onclick_add }>{ "Add" }</button>
				</div>
			</div>
		}
	}
}

#[derive(Debug, Properties, PartialEq)]
struct SANItemProps {
	alt_name: AltName,
	onremove: Callback<()>,
}

#[function_component]
fn SANItem(props: &SANItemProps) -> Html {
	let SANItemProps { alt_name, onremove } = props;
	let onremove = onremove.clone();

	html!(
		<li>
			<p>{ alt_name.r#type() }</p>
			<p>{ alt_name.text() }</p>
			<button onclick={ move |_| { onremove.emit(()) } }>{ "Remove" }</button>
		</li>
	)
}
