mod ui;

use crate::ui::components::App;

fn main() {
	yew::Renderer::<App>::new().render();
}
