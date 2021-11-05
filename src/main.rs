mod schemes;
mod util;

const BENCH: bool = false;
const TEST: bool = false;
const SINGLE: bool = true;

fn main() {
	if TEST {
		schemes::mklhs::test();
		schemes::k_w_2008::test();
		schemes::boneh2009::test();
	}

	if BENCH {
		schemes::boneh2009::bench();

		schemes::k_w_2008::bench();

		schemes::mklhs::bench();
	}

	if SINGLE {
		// schemes::schab2019::test_run();
		// schemes::schab2019::inverTest();
		schemes::schab2019::step_wise();
	}
}
