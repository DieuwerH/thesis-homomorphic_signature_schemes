mod schemes;
mod util;

fn main() {
	// schemes::mklhs::test();

	// schemes::k_w_2008::test();

	// schemes::boneh2009::test();

	// schemes::boneh2009::bench();

	// schemes::k_w_2008::bench();

	schemes::mklhs::bench();
}