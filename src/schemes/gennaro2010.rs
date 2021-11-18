use rand::distributions::Uniform;
use rsa::{RsaPublicKey, RsaPrivateKey, PublicKeyParts, BigUint};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
// use num_bigint::{BigUint, ToBigUint};
use num_traits::pow::Pow;
use std::time::{Duration, Instant};
use core::mem::size_of;


struct Gennaro2010 {
	n: usize,
	bits: usize,
}

impl Gennaro2010 {
	fn setup(n: usize, bits: usize) -> Self {
		Self { n, bits }
	}
	fn key_gen(&self, rng: &mut OsRng) -> Key {
		let priv_key = RsaPrivateKey::new(rng, self.bits).expect("failed to generate a key");
		let pub_key = RsaPublicKey::from(&priv_key);
		let n = pub_key.n();
		let mut gs: Vec<BigUint> = Vec::new();

		for _ in 0..self.n {
			let g: u32 = rng.next_u32();
			let g = BigUint::new(vec![g]);
			gs.push(g);
		}

		Key { sk: priv_key, vk: VK { rsa_pk: pub_key, gs } }
	}	
	fn sign(&self, key: &Key, msg: &MSG ) -> Sig {
		let mut sig = BigUint::new(vec![0]);
		let n = key.vk.rsa_pk.n();
		for i in 0..self.n {
			sig = sig * key.vk.gs[i].modpow(&msg[i], &n);
		};
		sig = sig.modpow(key.sk.d(), &n);
		sig
	}
	fn verify(&self, vk: &VK, msg: &MSG, sig: &Sig) -> bool {
		let mut c = BigUint::new(vec![0]);
		let n = vk.rsa_pk.n();
		for i in 0..self.n {
			c = c * vk.gs[i].modpow(&msg[i], &n);
		}
		let c2 = sig.modpow(vk.rsa_pk.e(), &n);
		c == c2
	}
	fn combine(&self, signatures: &Vec<&Sig>, coefs: &Vec<&u32>) -> Sig {
		let mut sig = BigUint::new(vec![0]);
		for (sig_current, coef) in signatures.iter().zip(coefs) {
			let cur = sig_current.pow(*coef);
			sig = sig * cur;
		};
		sig
	}
}

type MSG = Vec<BigUint>;
type Sig = BigUint;
type SK = RsaPrivateKey;
struct VK {
	rsa_pk : RsaPublicKey,
	gs: Vec<BigUint>,
}

struct Key {
	sk: SK,
	vk: VK,
}

pub fn test() {
	let scheme = Gennaro2010::setup(1, 3072);
	let rng = &mut OsRng {};
	let k = scheme.key_gen(rng);
	let msg = vec![BigUint::new(vec![123])];
	let s = scheme.sign(&k, &msg);
	let v = scheme.verify(&k.vk, &msg, &s);
	println!("V(vk, msg, S(sk, msg))? {}", v);

	let msg2 = vec![BigUint::new(vec![321])];
	let msg_combined = vec![BigUint::new(vec![444])];
	
	let s2 = scheme.sign(&k, &msg2);
	let s_combined = scheme.combine(&vec![&s, &s2], &vec![&1,&1]);
	let v_combined = scheme.verify(&k.vk, &msg_combined, &s_combined);
	println!("V(vk, m1 + m2, C(S(sk, m1), S(sk, m2), [1,1])? {}", v_combined);	

	let msg_combined_2 = vec![BigUint::new(vec![(123*2) + (321 * 3)])]; 
	let s_combined_2 = scheme.combine(&vec![&s, &s2], &vec![&2,&3]);
	let v_combined_2 = scheme.verify(&k.vk, &msg_combined_2, &s_combined_2);
	println!("V(vk, m1*a + m2*b, C(S(sk, m1), S(sk, m2), [a,b])? {}", v_combined_2);	
}


const BENCH_ITERATIONS: usize = 100;

pub fn bench() {
	println!("[BenchMark] Scheme: Gennaro2010");
	println!("[BenchMark] Byte size sig:\t{}", size_of::<Sig>());
	println!("[BenchMark] Byte size pk:\t{}", size_of::<VK>());
	println!("[BenchMark] Byte size sk:\t{}", size_of::<SK>());
	println!();
	println!(
		"[BenchMark] Averaging over num runs: {}",
		&BENCH_ITERATIONS
	);
	bench_setup(1,3072);
	let s = Gennaro2010::setup(1, 3072);
	bench_key_gen(&s);
	let k = s.key_gen(&mut OsRng{});
	let (msgs, sigs) = bench_sign(&s, &k);
	bench_verify(&s, &msgs, &sigs, &k.vk);
	let (c_sigs, coefs) = bench_combine(&s, &sigs);
	let mut c_msgs: Vec<MSG> = Vec::new();
	for i in 0..BENCH_ITERATIONS {
		let msgs_a = &msgs[i];
		let msgs_b = &msgs[(i+1)%BENCH_ITERATIONS];
		let coef_a = &coefs[i];
		let coef_b = &coefs[(i+1)%BENCH_ITERATIONS];
		let res = (msgs_a[0].clone() * coef_a) + (msgs_b[0].clone() * coef_b);
		c_msgs.push(vec![res]);
	};
	bench_verify(&s, &c_msgs, &c_sigs, &k.vk);
}

fn bench_setup(n: usize, bits: usize) {
	let mut results: [Duration; BENCH_ITERATIONS] = [Duration::ZERO; BENCH_ITERATIONS];
	for i in 0..BENCH_ITERATIONS {
		let start = Instant::now();
		Gennaro2010::setup(n, bits);
		let duration = start.elapsed();
		results[i] = duration;
	}
	let total_duration: Duration = results.iter().sum();
	let avg_duration = total_duration / BENCH_ITERATIONS as u32;
	println!("[BenchMark] Setup:\t {:?}", avg_duration);
}

fn bench_key_gen(s: &Gennaro2010) {
	let mut results: [Duration; BENCH_ITERATIONS] = [Duration::ZERO; BENCH_ITERATIONS];
	let rng = &mut OsRng {};
	for i in 0..BENCH_ITERATIONS {
		let start = Instant::now();
		s.key_gen(rng);
		let duration = start.elapsed();
		results[i] = duration;
	}
	let total_duration: Duration = results.iter().sum();
	let avg_duration = total_duration / BENCH_ITERATIONS as u32;

	println!("[BenchMark] KeyGen:\t {:?}", avg_duration);
}

fn bench_sign(s: &Gennaro2010, k: &Key) -> (Vec<MSG>, Vec<Sig>) {
	let mut results: [Duration; BENCH_ITERATIONS] = [Duration::ZERO; BENCH_ITERATIONS];
    let range = Uniform::from(0..u32::MAX);
    let msgs: Vec<MSG> = rand::thread_rng().sample_iter(&range).take(BENCH_ITERATIONS).map(|num| vec![BigUint::new(vec![num])]).collect();
	let mut sigs: Vec<Sig> = Vec::new();
	for i in 0..BENCH_ITERATIONS {
		let start = Instant::now();
		let sig = s.sign(k, &msgs[i]);
		sigs.push(sig);
		let duration = start.elapsed();
		results[i] = duration;
	}
	let total_duration: Duration = results.iter().sum();
	let avg_duration = total_duration / BENCH_ITERATIONS as u32;
	println!("[BenchMark] Sign:\t {:?}", avg_duration);
	(msgs, sigs)
}

fn bench_verify(s: &Gennaro2010, msgs: &Vec<MSG>, sigs: &Vec<Sig>, vk: &VK) {
	let mut results: [Duration; BENCH_ITERATIONS] = [Duration::ZERO; BENCH_ITERATIONS];
	for i in 0..BENCH_ITERATIONS {
		let start = Instant::now();
		s.verify(vk, &msgs[i], &sigs[i]);
		let duration = start.elapsed();
		results[i] = duration;
	}
	let total_duration: Duration = results.iter().sum();
	let avg_duration = total_duration / BENCH_ITERATIONS as u32;
	println!("[BenchMark] Verify\t {:?}", avg_duration);
}

fn bench_combine(s: &Gennaro2010, sigs: &Vec<Sig>) -> (Vec<Sig>, Vec<u32>)  {
	let mut results: [Duration; BENCH_ITERATIONS] = [Duration::ZERO; BENCH_ITERATIONS];
	let range = Uniform::from(0..u32::MAX);
	let coefs: Vec<u32> = rand::thread_rng().sample_iter(&range).take(BENCH_ITERATIONS).collect();
	let mut c_sigs: Vec<Sig> = Vec::new();
	for i in 0..BENCH_ITERATIONS {
		let start = Instant::now();
		let csig = s.combine(&vec![&sigs[i], &sigs[(i+1)%BENCH_ITERATIONS]], &vec![&coefs[i], &coefs[(i+1)%BENCH_ITERATIONS]]);
		c_sigs.push(csig);
		let duration = start.elapsed();
		results[i] = duration;
	}
	let total_duration: Duration = results.iter().sum();
	let avg_duration = total_duration / BENCH_ITERATIONS as u32;
	println!("[BenchMark] Combine:\t {:?}", avg_duration);
	(c_sigs, coefs)
}
