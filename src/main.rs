#![allow(dead_code)]

mod schemes;
mod util;
mod tmp;

const BENCH: bool = true;
const TEST: bool = false;
const SINGLE: bool = false;

fn main() {
	if TEST {
		schemes::mklhs::test();
		schemes::k_w_2008::test();
		schemes::boneh2009::test();
	}

	if BENCH {
		println!("===========");				
		schemes::boneh2009::bench();
		println!("===========");			
		schemes::k_w_2008::bench();
		println!("===========");			
		schemes::mklhs::bench();
		println!("===========");			
		schemes::hon21::bench();
		println!("===========");			
		schemes::gennaro2010::bench();
	}

	if SINGLE {
		// schemes::schab2019::test_run();
		// schemes::schab2019::inverTest();
		// schemes::schab2019::step_wise();
		// tmp::test();
		// schemes::hon21::test();
		// schemes::hon21::bench();
		// schemes::schab2019_bn::test();
		// schemes::schab2019_bn::test_struct();
		schemes::gennaro2010::test();
	}
}
