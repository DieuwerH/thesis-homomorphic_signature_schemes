use crate::util::bls_util::bi_to_s1;
use crate::util::bls_util::bi_to_s2;
use crate::util::bls_util::prod_hash_ids;
use crate::util::bls_util::u32_to_bi;
use crate::util::bls_util::u32_to_s1;
use crate::util::bls_util::{P1, P2, S1, S2};
use core::mem::size_of;
use curv::elliptic::curves::bls12_381;
use curv::elliptic::curves::Bls12_381_2;
use curv::elliptic::curves::Generator;
use curv::BigInt;
use rand::Rng;
use std::time::{Duration, Instant};

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
	println!("Size of signature: {}", size_of::<Sig>());
}

const BENCH_ITERATIONS: usize = 100;

pub fn bench() {
	println!("[BenchMark] Scheme: Boneh2009");
	println!("[BenchMark] Byte size sig:\t{}", size_of::<Sig>());
	println!("[BenchMark] Byte size pk:\t{}", size_of::<PK>());
	println!("[BenchMark] Byte size sk:\t{}", size_of::<SK>());
	println!();
	println!(
		"[BenchMark] Averaging over num runs: {}",
		&BENCH_ITERATIONS
	);
	let scheme = bench_setup();
	let key = bench_key_gen(&scheme);
	let m: V = vec![1, 2, 3, 4, 5, 6, 7, 8];
	let m2: V = vec![8, 7, 6, 5, 4, 3, 2, 1];
	let sig = bench_sign(&scheme, &key, &m);
	bench_verify(&scheme, &key, &m, &sig, "original signature");
	let s2 = scheme.sign(&key.sk, &123, &m2);
	let weights: V = vec![1, 2, 3, 4, 5, 6, 7, 8];
	let s_c = bench_combine(&weights, &vec![sig, s2]);
	bench_verify(
		&scheme,
		&key,
		&B2009::combine_msg(&weights, &vec![m, m2]),
		&s_c,
		"combined signature",
	);
}

fn bench_setup() -> B2009 {
	let mut results: [Duration; BENCH_ITERATIONS] = [Duration::ZERO; BENCH_ITERATIONS];
	for i in 0..BENCH_ITERATIONS {
		let start = Instant::now();
		B2009::setup();
		let duration = start.elapsed();
		results[i] = duration;
	}
	let total_duration: Duration = results.iter().sum();
	let avg_duration = total_duration / BENCH_ITERATIONS as u32;
	println!("[BenchMark] Setup:\t {:?}", avg_duration);
	B2009::setup()
}

fn bench_key_gen(s: &B2009) -> Key {
	let mut results: [Duration; BENCH_ITERATIONS] = [Duration::ZERO; BENCH_ITERATIONS];
	let mut rng = rand::thread_rng();
	for i in 0..BENCH_ITERATIONS {
		let start = Instant::now();
		s.key_gen(&mut rng);
		let duration = start.elapsed();
		results[i] = duration;
	}
	let total_duration: Duration = results.iter().sum();
	let avg_duration = total_duration / BENCH_ITERATIONS as u32;

	println!("[BenchMark] KeyGen:\t {:?}", avg_duration);
	s.key_gen(&mut rng)
}

fn bench_sign(s: &B2009, k: &Key, m: &V) -> Sig {
	let mut results: [Duration; BENCH_ITERATIONS] = [Duration::ZERO; BENCH_ITERATIONS];
	for i in 0..BENCH_ITERATIONS {
		let start = Instant::now();
		s.sign(&k.sk, &123, m);
		let duration = start.elapsed();
		results[i] = duration;
	}
	let total_duration: Duration = results.iter().sum();
	let avg_duration = total_duration / BENCH_ITERATIONS as u32;
	println!("[BenchMark] Sign:\t {:?}", avg_duration);
	s.sign(&k.sk, &123, m)
}

fn bench_verify(s: &B2009, k: &Key, m: &V, sig: &Sig, comment: &str) -> bool {
	let mut results: [Duration; BENCH_ITERATIONS] = [Duration::ZERO; BENCH_ITERATIONS];
	for i in 0..BENCH_ITERATIONS {
		let start = Instant::now();
		s.verify(&k.pk, &123, m, sig);
		let duration = start.elapsed();
		results[i] = duration;
	}
	let total_duration: Duration = results.iter().sum();
	let avg_duration = total_duration / BENCH_ITERATIONS as u32;
	println!("[BenchMark] Verify ({})\t {:?}", comment, avg_duration);
	s.verify(&k.pk, &123, m, sig)
}

fn bench_combine(weights: &V, signatures: &Vec<Sig>) -> Sig {
	let mut results: [Duration; BENCH_ITERATIONS] = [Duration::ZERO; BENCH_ITERATIONS];
	for i in 0..BENCH_ITERATIONS {
		let start = Instant::now();
		B2009::combine(weights, signatures);
		let duration = start.elapsed();
		results[i] = duration;
	}
	let total_duration: Duration = results.iter().sum();
	let avg_duration = total_duration / BENCH_ITERATIONS as u32;
	println!("[BenchMark] Combine:\t {:?}", avg_duration);
	B2009::combine(weights, signatures)
}
