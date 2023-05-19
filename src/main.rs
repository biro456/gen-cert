mod error;
mod gen;
mod prelude;
mod ui;

use crate::ui::components::App;

fn main() {
	yew::Renderer::<App>::new().render();
}
