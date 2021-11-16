use crate::util::bls_util;
use bls12_381::Pair;
use curv::arithmetic::Converter;
use curv::elliptic::curves::{
	bls12_381, Bls12_381_1, Bls12_381_2, ECPoint, Generator, Point, Scalar,
};
use curv::BigInt;

type P1 = Point<Bls12_381_1>;
type P2 = Point<Bls12_381_2>;
type S1 = Scalar<Bls12_381_1>;
type S2 = Scalar<Bls12_381_2>;

pub fn test() {
	//Setup
	let g1 = P1::generator();
	let g2 = P2::generator();

	//KeyGen
	let id = 123u32;
	let sk = BigInt::from_bytes(&[123, 254, 111]);
	let pk = g2 * bls_util::bi_to_s2(&sk);

	//Sign
	let msg: usize = 123456;
	let msg_as_s1 = S1::from_bigint(&BigInt::from_bytes(&msg.to_be_bytes()));
	let tag = 456u32;

	let label = (&id, &tag);
	let l2 = (&id, &455u32);

	let hash_label = hash_to_curve(&label);
	let sig = (&hash_label + (g1 * &msg_as_s1)) * &bls_util::bi_to_s1(&sk);

	//Verify
	println!("Verifies? {}",verify(&msg_as_s1, &sig, &pk, &label));

	let m2:usize = 7654321;
	let m2s1 = S1::from_bigint(&BigInt::from_bytes(&m2.to_be_bytes()));
	let s2 = sign(&sk, &l2, &m2s1);
	let v2 = verify(&m2s1, &s2, &pk, &l2);
	println!("Verifies2? {}", v2);

	let sc = sig + s2;
	// let 

}

#[derive(Clone)]
struct Label {
	id: u32,
	tg: u32,
}
struct Prog {
	ls: Vec<Label>
}

fn ver_mult(p: &Prog, pks: &Vec<P2>, m: S1, s: P1) -> bool {
	true
}

fn verify(msg: &S1, s: &P1, pk: &P2, l: &(&u32, &u32)) -> bool {
	let hl = hash_to_curve(l);
	let c = Pair::compute_pairing(&((P1::generator() * msg) + &hl), &pk);
	let c2 = Pair::compute_pairing(&s, &P2::generator());
	c == c2
}

fn sign(sk: &BigInt, l: &(&u32, &u32), m: &S1) -> P1 {
	let hl = hash_to_curve(&l);
	let sig = hl + (P1::generator() * m);
	sig * S1::from_bigint(sk)
}

fn hash_to_curve(label: &(&u32, &u32)) -> P1 {
	let hashed = bls12_381::g1::GE1::hash_to_curve(&label.0.to_be_bytes());
	let hashed = P1::from_coords(&hashed.x_coord().unwrap(), &hashed.y_coord().unwrap())
		.expect("Coords not unwrappable");
	hashed
}
