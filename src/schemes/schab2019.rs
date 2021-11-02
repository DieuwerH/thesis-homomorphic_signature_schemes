use crate::util::bls_util::*;
use curv::elliptic::curves::bls12_381;
use ed25519_dalek::{Keypair, Signature, Signer};
use hmac::{Hmac, Mac, NewMac};
use rand::rngs::OsRng;
use rand::rngs::ThreadRng;
use rand::{CryptoRng, Rng, RngCore};
use rand_old;
use sha2::Sha256;

type HMS256 = Hmac<Sha256>;

struct SK {
	k: u32,
	sig_keypair: ed25519_dalek::Keypair,
	xs: Vec<S1>,
	y: S2,
}

struct EK {}

struct VK {
	pk_sig: ed25519_dalek::PublicKey,
	hs: Vec<bls12_381::Pair>,
	Y: P2,
}

pub struct Key {
	sk: SK,
	ek: EK,
	vk: VK,
}

pub struct Label {
	id: u32,
	tag: u32,
}

pub struct Schab2019 {
	g1: G1,
	g2: G2,
	k: u32, // Defines ID space
	n: u32, // Defines tag space
	t: u32, // Defines message vector length
	Hs: Vec<P1>,
}

pub struct Lam {
	id: u32,
	sig_d: ed25519_dalek::Signature,
	Z: P2,
	A: P1,
	C: P1,
}

pub struct Sig {
	lam: Lam,
	r: P1,
	s: P2,
}

impl Schab2019 {
	fn setup() -> Self {
		let mut Hs = Vec::new();
		let mut res = Self {
			g1: P1::generator(),
			g2: P2::generator(),
			k: 100,
			n: 100,
			t: 8,
			Hs,
		};

		let mut rng = rand::thread_rng();
		for _ in 0..(res.t + 1) {
			let h: u32 = rng.gen();

			res.Hs.push(P1::generator() * u32_to_s1(&h));
		}

		res
	}

	fn key_gen(&self, rng: &mut ThreadRng) -> Key {
		let k: u32 = rng.gen();

		let mut csprng = rand_old::rngs::OsRng {};
		let kp = Keypair::generate(&mut csprng);

		let mut xs = Vec::<S1>::new();
		let mut hs = Vec::<bls12_381::Pair>::new();
		for i in 0..self.n {
			let x = S1::random();
			xs.push(x);
			hs.push(bls12_381::Pair::compute_pairing(&(self.g1 * &x), &self.g2))
		}
		let y = S2::random();
		let Y = self.g2 * &y;

		let sk = SK {
			k,
			sig_keypair: kp,
			xs,
			y,
		};
		let ek = EK {};
		let vk = VK {
			pk_sig: kp.public,
			hs,
			Y,
		};

		Key { sk, ek, vk }
	}

	fn auth(&self, sk: SK, dataset_id: u32, l: Label, m: Vec<u32>) -> Sig {
		let mut mac =
			HMS256::new_from_slice(&sk.k.to_be_bytes()).expect("HMAC can take key of any size");
		let dataset_bytes = dataset_id.to_be_bytes();
		mac.update(&dataset_bytes);
		let z = mac.finalize().into_bytes();
		let Z = self.g2 * bytes_to_s2(&z);
		let mut to_sign: Vec<u8> = (*(Z.to_bytes(true))).to_vec();
		to_sign.extend(dataset_bytes);
		let sig_d = sk.sig_keypair.sign(&to_sign);

		let r = S1::random();
		let s = S1::random();

		let R = self.g1 * (&r - &s);
		let S = self.g2 * (-S2::from_bigint(&s.to_bigint()));

		let mut A = self.g1 * ((sk.xs[l.tag as usize].clone()) + &r);
		let mut C = self.g1 * &s;
		for i in 0..(self.t as usize) {
			let H = self.Hs[i].clone() * u32_to_s1(&m[i]);
			A = A + &H;
			C = C + &H;
		}

		A = A * bytes_to_s1(&z).invert().unwrap();
		C = C * S1::from_bigint(&sk.y.to_bigint()).invert().unwrap();

		let lam = Lam {
			id: l.id,
			sig_d,
			Z,
			A,
			C,
		};

		Sig { lam, r: R, s: S }
	}
}
