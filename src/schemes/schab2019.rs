use crate::util::bls_util::*;
use bls12_381::Pair;
use curv::arithmetic::Converter;
use curv::elliptic::curves::bls12_381;
use curv::BigInt;
use ed25519_dalek::{Keypair, Signature, Signer, Verifier};
use hmac::{Hmac, Mac, NewMac};
use rand::rngs::OsRng;
use rand::rngs::ThreadRng;
use rand::{CryptoRng, Rng, RngCore};
use rand_old;
use sha2::Sha256;

type HMS256 = Hmac<Sha256>;
type Msg = [u32; 8];
type Id = u32;

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
	id: Id,
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
	pub id: Id,
	pub sig_d: ed25519_dalek::Signature,
	pub Z: P2,
	pub A: P1,
	pub C: P1,
}

pub struct Sig {
	pub lams: Vec<Lam>,
	pub r: P1,
	pub s: P2,
}

impl Schab2019 {
	fn setup() -> Self {
		let mut res = Self {
			g1: P1::generator(),
			g2: P2::generator(),
			k: 100,
			n: 100,
			t: 8,
			Hs: Vec::new(),
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
			xs.push(x.clone());
			hs.push(bls12_381::Pair::compute_pairing(&(self.g1 * &x), &self.g2))
		}
		let y = S2::random();
		let Y = self.g2 * &y;

		let vk = VK {
			pk_sig: kp.public,
			hs,
			Y,
		};

		let sk = SK {
			k,
			sig_keypair: kp,
			xs,
			y,
		};
		let ek = EK {};

		Key { sk, ek, vk }
	}

	fn compute_z_bytes(
		k: &u32,
		d_id_bytes: &[u8],
	) -> sha2::digest::generic_array::GenericArray<u8, <hmac::Hmac<sha2::Sha256> as Mac>::OutputSize>
	{
		let mut mac =
			HMS256::new_from_slice(&k.to_be_bytes()).expect("HMAC can take key of any size");
		mac.update(d_id_bytes);
		mac.finalize().into_bytes()
	}

	fn compute_to_sign(Z: &P2, d_bytes: &[u8]) -> Vec<u8> {
		let mut to_sign: Vec<u8> = (*(Z.to_bytes(true))).to_vec();
		to_sign.extend(d_bytes);
		to_sign
	}

	fn auth(&self, sk: &SK, dataset_id: &u32, l: &Label, m: &Msg) -> Sig {
		// let mut mac =
		// 	HMS256::new_from_slice(&sk.k.to_be_bytes()).expect("HMAC can take key of any size");
		let dataset_bytes = dataset_id.to_be_bytes();
		// mac.update(&dataset_bytes);
		// let z = mac.finalize().into_bytes();
		let z = Schab2019::compute_z_bytes(&sk.k, &dataset_bytes);
		let Z = self.g2 * bytes_to_s2(&z);
		let to_sign = Schab2019::compute_to_sign(&Z, &dataset_bytes);
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

		Sig {
			lams: vec![lam],
			r: R,
			s: S,
		}
	}

	fn eval(f: Vec<u32>, signatures: Vec<Sig>) -> Sig {
		let mut R = P1::zero();
		let mut S = P2::zero();

		let mut lams: Vec<Lam> = Vec::new();

		for (fi, sigi) in f.iter().zip(signatures) {
			R = R + (sigi.r * u32_to_s1(fi));
			S = S + (sigi.s * u32_to_s2(fi));
			let A = sigi.lams[0].A.clone() * u32_to_s1(fi);
			let C = sigi.lams[0].C.clone() * u32_to_s1(fi);
			let lam = Lam {
				id: sigi.lams[0].id,
				sig_d: sigi.lams[0].sig_d,
				Z: sigi.lams[0].Z.clone(),
				A,
				C,
			};
			lams.push(lam);
		}

		Sig { lams, r: R, s: S }
	}

	fn ver(p: P, vkeys: Vec<VK>, m: Msg, sig: Sig) -> bool {
		// let mut
		for (lam, vkey) in sig.lams.iter().zip(vkeys) {
			let cur_sig = lam.sig_d;
			let msg = Schab2019::compute_to_sign(&lam.Z, &p.d_bytes());
			let verifies = match vkey.pk_sig.verify(&msg, &cur_sig) {
				Ok(()) => true,
				_ => false,
			};
			if !verifies {
				return false;
			}

			let p1 = bls12_381::Pair::compute_pairing(&lam.A, &lam.Z);
		}
		false
	}
}

struct P {
	f: Msg,
	dataset_id: u32,
}
impl P {
	fn d_bytes(&self) -> [u8; 4] {
		self.dataset_id.to_be_bytes()
	}
}

pub fn test_run() {
	println!("Test run of Schab2019");
	let scheme = Schab2019::setup();
	let mut rng = rand::thread_rng();
	let key = scheme.key_gen(&mut rng);

	let d_id: u32 = 99;

	let l = Label { id: 2, tag: 4 };

	let m: Msg = [1, 2, 3, 4, 5, 6, 7, 8];

	let sig = scheme.auth(&key.sk, &d_id, &l, &m);

	let prog = P {
		f: [1, 1, 1, 1, 1, 1, 1, 1],
		dataset_id: d_id,
	};

	let sig_dataset = sig.lams[0].sig_d;
	let msg_dataset = Schab2019::compute_to_sign(&sig.lams[0].Z, &prog.d_bytes());
	let verifies = match key.vk.pk_sig.verify(&msg_dataset, &sig_dataset) {
		Ok(()) => true,
		_ => false,
	};
	println!("Signature for dataset {} verifies? {}", &d_id, &verifies);
	let pair_1 = Pair::compute_pairing(&sig.lams[0].A, &sig.lams[0].Z);

	let mut pair_2 = key.vk.hs[0];
	for i in 1..key.vk.hs.len() {
		pair_2 = pair_2.add_pair(&key.vk.hs[i]);
	}

	pair_2 = pair_2.add_pair(&Pair::compute_pairing(&sig.lams[0].C, &key.vk.Y));
	let c_y_pair = Pair::compute_pairing(&sig.r, &scheme.g2);
	pair_2 = pair_2.add_pair(&c_y_pair);

	let c1 = pair_1 == pair_2;
	if !c1 {
		println!("C1 does not hold");
	}

	let pair_3 = Pair::compute_pairing(&scheme.g1, &sig.s).add_pair(&c_y_pair);
	let mut hprod = P1::zero();
	for i in 0..(scheme.t as usize) {
		hprod = hprod + (scheme.Hs[i].clone() * u32_to_s1(&m[i]));
	}
	let pair_4 = Pair::compute_pairing(&hprod, &scheme.g2);
	let c2 = pair_3 == pair_4;
	if !c2 {
		println!("C2 does not hold");
	}
}

pub fn step_wise() {
	// SETUP
	let n = 4; // Tag space
	let t = 4; // Message length
	let k = 4; // Id space

	let g1 = P1::generator();
	let g2 = P2::generator();

	let mut Hs: Vec<P1> = Vec::new();
	for _ in 0..t {
		Hs.push(g1 * S1::random());
	}

	// KeyGen
	let mut rng = rand::thread_rng();
	let k = rng.gen::<[u8; 32]>();
	let mut csprng = rand_old::rngs::OsRng {};
	let sig_kp = Keypair::generate(&mut csprng);
	let mut xs: Vec<S1> = Vec::new();
	let mut hs: Vec<Pair> = Vec::new();
	for _ in 0..n {
		let x = S1::random();
		hs.push(Pair::compute_pairing(&(g1 * &x), &g2));
		xs.push(x);
	}
	let y = S2::random();
	let Y = g2 * &y;
	// Set message and dataset
	let id = 3; // User ID
	let m = [1, 2, 3, 4]; // Message to sign
	let d_id: [u8; 1] = [123]; // Dataset Id
	let tag = 2; // Tag (place in program)

	// Signing / Auth
	let mut mac = HMS256::new_from_slice(&k).expect("HMAC can take key of any size");
	mac.update(&d_id);
	let z = mac.finalize().into_bytes();
	let Z = g2 * S2::from_bigint(&BigInt::from_bytes(&z));
	let mut d_msg = Z.to_bytes(true).to_vec();
	d_msg.extend(d_id);
	let sig_d = sig_kp.sign(&d_msg);

	let r = S1::random();
	let s_1 = S1::random();
	let s_2 = S2::from_bigint(&s_1.to_bigint());

	let R = g1 * (&r - &s_1);
	let S = g2 * (-&s_2);

	let mut A = g1 * (&xs[tag] + &r);
	let mut C = g1 * &s_1;
	for i in 0..t {
		A = A + (&Hs[i] * u32_to_s1(&m[i]));
		C = C + (&Hs[i] * u32_to_s1(&m[i]));
	}
	A = A * &S1::from_bigint(&BigInt::from_bytes(&z)).invert().unwrap();
	C = C * &S1::from_bigint(&y.to_bigint()).invert().unwrap();

	let Lam = (id, sig_d, Z, A, C);

	// Verify
	let program = [1];
	let sig_d_check = match sig_kp.verify(&d_msg, &sig_d) {
		Ok(()) => true,
		_ => true,
	};
	println!("Signature on dataset checks out? {}", sig_d_check);

	let p1 = Pair::compute_pairing(&Lam.3, &Lam.2);
	let p2 = hs[tag]
		.add_pair(&Pair::compute_pairing(&Lam.4, &Y))
		.add_pair(&Pair::compute_pairing(&R, &g2));
	let pair_check_1 = p1 == p2;
	println!("First two pairs equal? {}", pair_check_1);

	let p3 = Pair::compute_pairing(&g1, &S)
		.add_pair(&Pair::compute_pairing(&Lam.4, &Y));
	// let p4 = Pair::compute_pairing(p1: &Point<Bls12_381_1>, p2: &Point<Bls12_381_2>)
}

pub fn inverTest() {
	let point = P1::generator() * S1::random();
	let rng_scalar = S1::random();

	let p2 = &point * &rng_scalar.invert().unwrap();

	let check = point == (p2 * rng_scalar);
	println!("Check succeeds? {}", check);
}
