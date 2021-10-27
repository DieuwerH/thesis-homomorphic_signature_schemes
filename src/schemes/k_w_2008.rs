use curv::arithmetic::Converter;
use curv::elliptic::curves::Bls12_381_2;
use curv::elliptic::curves::{bls12_381, Bls12_381_1, ECPoint, Generator, Point, Scalar};
use curv::BigInt;
use rand::Rng;

pub type P1 = Point<Bls12_381_1>;
pub type P2 = Point<Bls12_381_2>;
pub type S1 = Scalar<Bls12_381_1>;
pub type S2 = Scalar<Bls12_381_2>;
type SK = BigInt;
type PK = P2;
type Sig = P1;

pub struct Key {
	pk: PK,
	sk: SK,
}

pub struct KW2008 {
	g: Generator<Bls12_381_2>,
}

impl KW2008 {
	pub fn setup() -> Self {
		Self { g: P2::generator() }
	}

	pub fn key_gen(&self, rng: &mut rand::prelude::ThreadRng) -> Key {
		let sk: u32 = rng.gen();
		let sk = BigInt::from_bytes(&sk.to_be_bytes());
		let pk = P2::generator() * S2::from_bigint(&sk);
		Key { pk, sk }
	}

	pub fn sign(&self, sk: &SK, id: &u32, v: &Vec<u32>) -> Sig {
		let sigma = KW2008::prod_hash_ids(id, v);
		sigma * S1::from_bigint(sk)
	}

	fn prod_hash_ids(id: &u32, vector: &Vec<u32>) -> P1 {
		let mut res = P1::zero();
		let id_bytes = id.to_be_bytes();

		for (i, v_i) in vector.iter().enumerate() {
			let mut to_hash = id_bytes.to_vec();
			to_hash.append(&mut i.to_be_bytes().to_vec());
			let s_i = KW2008::hash_to_curve(&to_hash) * KW2008::u32_to_s1(&v_i);
			res = res + s_i;
		}

		res
	}

	pub fn combine(
		&self,
		id: &u32,
		weights: &Vec<u32>,
		vectors: &Vec<Vec<u32>>,
		signatures: &Vec<Sig>,
	) -> (Sig, Vec<u32>) {
		let mut sigma = P1::zero();
		let mut v: Vec<u32> = vec![0; vectors[0].len()];

		for i in 0..signatures.len() {
			let s_i = &signatures[i] * KW2008::u32_to_s1(&weights[i]);
			sigma = sigma + s_i;

			let vec_i: Vec<u32> = vectors[i].iter().map(|v| v * weights[i]).collect();

			v = v.iter().zip(vec_i).map(|(v_i, v_i2)| v_i + v_i2).collect();
		}

		(sigma, v)
	}

	pub fn verify(&self, pk: &PK, id: &u32, vector: &Vec<u32>, sigma: &Sig) -> bool {
		let pair1 = bls12_381::Pair::compute_pairing(sigma, &self.g);
		let prod_hash = KW2008::prod_hash_ids(id, vector);
		let pair2 = bls12_381::Pair::compute_pairing(&prod_hash, pk);
		pair1 == pair2
	}

	fn u32_to_s1(msg: &u32) -> S1 {
		S1::from_bigint(&BigInt::from_bytes(&msg.to_be_bytes()))
	}

	fn hash_to_curve(msg: &[u8]) -> P1 {
		let on_curve = bls12_381::g1::G1Point::hash_to_curve(msg);
		P1::from_coords(&on_curve.x_coord().unwrap(), &on_curve.y_coord().unwrap())
			.expect("Coord not unwrapable")
	}
}

pub fn test() {
	println!("[*] KW2008");
	let scheme = KW2008::setup();
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

	let (s_comb, m_comb) = scheme.combine(&id, &vec![2, 5, 3], &vec![m1, m2], &vec![s1, s2]);
	let v_comb = scheme.verify(&k1.pk, &id, &m_comb, &s_comb);
	println!(
		"Signature for combined message {:?} verifies: {:?}",
		&m_comb, v_comb
	);
}
