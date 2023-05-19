use closure::closure;
use web_sys::HtmlTextAreaElement;
use yew::prelude::*;

use crate::ui::hooks::*;

#[derive(PartialEq, Properties)]
pub struct OutputProps {
	pub slot: Slot<String>,
	#[prop_or_default]
	pub title: String,
}

#[function_component]
pub fn Output(props: &OutputProps) -> Html {
	let node = use_node_ref();
	let onclick = closure!(clone node, |_| node.cast::<HtmlTextAreaElement>().unwrap().select());

	html! {
		<div>
			<p>{ props.title.clone() }</p>
			<textarea
				readonly=true
				ref={ node }
				value={ props.slot.get() }
				{onclick}
			/>
		</div>
	}
}
