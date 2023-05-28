use std::borrow::Borrow;
use std::ops::Deref;

use yew::prelude::*;

#[derive(Debug, Clone)]
pub struct Slot<T: Clone>(pub UseStateHandle<T>);

impl<T: Clone> Slot<T> {
	#[inline]
	pub fn get(&self) -> T {
		(*self.0).clone()
	}

	#[inline]
	pub fn set(&self, value: impl Borrow<T>) {
		self.0.set(value.borrow().clone());
	}

	#[inline]
	pub fn change_handler(&self) -> Callback<T, ()>
	where
		T: 'static,
	{
		let setter = self.0.setter();

		Callback::from(move |value| setter.set(value))
	}
}

impl<T: Clone> Deref for Slot<T> {
	type Target = <UseStateHandle<T> as Deref>::Target;

	#[inline]
	fn deref(&self) -> &Self::Target {
		self.0.deref()
	}
}

impl<T: Clone + AsRef<R>, R: ?Sized> AsRef<R> for Slot<T> {
	fn as_ref(&self) -> &R {
		(*self.0).as_ref()
	}
}

impl<T: Clone + PartialEq> PartialEq for Slot<T> {
	fn eq(&self, rhs: &Self) -> bool {
		*self.0 == *rhs.0
	}
}

#[hook]
pub fn use_slot<T: Clone + 'static>(initial: impl FnOnce() -> T) -> Slot<T> {
	Slot(use_state(initial))
}

#[hook]
pub fn use_slot_with_default<T: Clone + Default + 'static>() -> Slot<T> {
	Slot(use_state(|| T::default()))
}
