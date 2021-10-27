use crate::util::bls_util::bi_to_s1;
use crate::util::bls_util::bi_to_s2;
use crate::util::bls_util::prod_hash_ids;
use crate::util::bls_util::u32_to_bi;
use crate::util::bls_util::u32_to_s1;
use crate::util::bls_util::{P1, P2, S1, S2};
use curv::elliptic::curves::bls12_381;
use curv::elliptic::curves::Bls12_381_2;
use curv::elliptic::curves::Generator;
use curv::BigInt;
use rand::Rng;

type PK = P2;
type SK = BigInt;
type ID = u32;
type V = Vec<u32>;
type Sig = P1;

pub struct Key {
	pk: PK,
	sk: SK,
}

pub struct B2009 {
	h: Generator<Bls12_381_2>,
}

impl B2009 {
	pub fn setup() -> Self {
		Self { h: P2::generator() }
	}

	pub fn key_gen(&self, rng: &mut rand::prelude::ThreadRng) -> Key {
		let alpha: u32 = rng.gen();
		let sk = u32_to_bi(&alpha);
		let u = self.h * bi_to_s2(&sk);
		Key { pk: u, sk }
	}

	pub fn sign(&self, sk: &SK, id: &ID, vector: &V) -> Sig {
		prod_hash_ids(id, vector) * S1::from_bigint(sk)
	}

	pub fn combine(weights: &V, signatures: &Vec<Sig>) -> Sig {
		let mut sigma = P1::zero();

		for (s_i, w_i) in signatures.iter().zip(weights) {
			sigma = sigma + (s_i * u32_to_s1(&w_i));
		}
		sigma
	}

	pub fn verify(&self, pk: &PK, id: &ID, vector: &V, signature: &Sig) -> bool {
		let gam1 = bls12_381::Pair::compute_pairing(signature, &self.h);
		let prod_hash = prod_hash_ids(id, vector);
		let gam2 = bls12_381::Pair::compute_pairing(&prod_hash, pk);

		gam1 == gam2
	}

	pub fn combine_msg(weights: &V, msgs: &Vec<V>) -> V {
		let mut v: V = vec![0; msgs[0].len()];

		for (i, (msg, weight)) in msgs.iter().zip(weights).enumerate() {
			let v_i: V = msg.iter().map(|m| m * weight).collect();
			v = v.iter().zip(v_i).map(|(v1, v2)| v1 + v2).collect();
		}

		v
	}
}

pub fn test() {
	println!("[*] B2009");
	let scheme = B2009::setup();
	let mut rng = rand::thread_rng();
	let k1 = scheme.key_gen(&mut rng);
	let m1: Vec<u32> = vec![1, 2, 3];
	let m2: Vec<u32> = vec![4, 5, 6];
	let m3: Vec<u32> = vec![7, 8, 9];
	let id = 123;
	let s1 = scheme.sign(&k1.sk, &id, &m1);
	let v1 = scheme.verify(&k1.pk, &id, &m1, &s1);
	println!("V1 verifies? {}", v1);

	let file = vec![&m1, &m2, &m3];
	let s2 = scheme.sign(&k1.sk, &id, &m2);
	let s3 = scheme.sign(&k1.sk, &id, &m3);

	let weights: V = vec![2, 5, 3];
	let msgs: Vec<V> = vec![m1, m2];
	let m_comb = B2009::combine_msg(&weights, &msgs);

	let s_comb = B2009::combine(&weights, &vec![s1, s2]);
	let v_comb = scheme.verify(&k1.pk, &id, &m_comb, &s_comb);
	println!(
		"Signature for combined message {:?} verifies: {:?}",
		&m_comb, v_comb
	);
}
