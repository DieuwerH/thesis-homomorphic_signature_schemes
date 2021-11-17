use bincode;
use bincode::rustc_serialize::{encode};
use bn::{pairing, Fr, Group, Gt, G1, G2};
use bn_rand;
use bn_rand::Rng;
use ed25519_dalek as sig;
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use sig::{Signature, Signer, Verifier};

type HMS256 = Hmac<Sha256>;

struct SK {
	k: [u8; 32],
	sig_keypair: sig::Keypair,
	xs: Vec<Fr>,
	y: Fr,
}
struct VK {
	pk_sig: sig::PublicKey,
	hs: Vec<Gt>,
	y: G2,
}

struct Key {
	sk: SK,
	vk: VK,
}

struct Schab2019 {
	g1: G1,
	g2: G2,
	gt: Gt,
	k: usize, // ID space
	n: usize, // Tag space
	t: usize, // Message length
	hhs: Vec<G1>,
}
impl Schab2019 {
	fn setup(k: usize, n: usize, t: usize, rng: &mut bn_rand::ThreadRng) -> Self {
		let mut hhs: Vec<G1> = Vec::new();
		for _ in 0..t {
			hhs.push(G1::random(rng))
		}
		let gt = pairing(G1::one(), G2::one());
		Self {
			g1: G1::one(),
			g2: G2::one(),
			gt,
			k,
			n,
			t,
			hhs,
		}
	}
	fn key_gen(&self, rng: &mut bn_rand::ThreadRng) -> Key {
		let k = rng.gen::<[u8; 32]>();
		let csprng = &mut ed_rand::rngs::OsRng {};
		let sig_kp = ed25519_dalek::Keypair::generate(csprng);
		let mut xs: Vec<Fr> = Vec::new();
		let mut hs: Vec<Gt> = Vec::new();
		for _ in 0..self.n {
			let x = Fr::random(rng);
			let h = self.gt.pow(x);
			xs.push(x);
			hs.push(h);
		}
		let y = Fr::random(rng);
		let yy = self.g2 * y;
		let vk = VK {
			pk_sig: sig_kp.public,
			hs,
			y: yy,
		};
		let sk = SK {
			k,
			sig_keypair: sig_kp,
			xs,
			y,
		};
		Key { sk, vk }
	}
	fn auth(
		&self,
		sk: &SK,
		d_id: &[u8],
		l: &(u32, usize),
		msg: &[u32],
		rng: &mut bn_rand::ThreadRng,
	) -> Sig {
		// println!("---MACing");
		let mut mac = HMS256::new_from_slice(&sk.k).expect("HMAC can take key of any size");
		mac.update(&d_id);
		let z = mac.finalize().into_bytes();
		let z_fr = Fr::from_slice(&z).unwrap();
		let zz = self.g2 * z_fr;
		// println!("---Encoding Z");
		let mut zz_bytes = encode(&zz, bincode::SizeLimit::Infinite).ok().unwrap();
		zz_bytes.push(d_id[0]);
		let sig_d = sk.sig_keypair.sign(&zz_bytes);
		let r = Fr::random(rng);
		let s = Fr::random(rng);
		let rr = self.g1 * (r - s);
		let ss = self.g2 * (-s);
		let mut a = self.g1 * (sk.xs[l.1] + r);
		let mut c = self.g1 * s;
		let mut h_factor = G1::zero();
		for i in 0..self.t {
			h_factor = h_factor + (self.hhs[i] * Fr::from_str(&msg[i].to_string()).unwrap());
		}
		a = a + h_factor;
		c = c + h_factor;
		a = a * (z_fr.inverse().unwrap());
		c = c * (sk.y.inverse().unwrap());
		let lam = Lam {
			id: l.0,
			sig_d,
			z: zz,
			a,
			c,
		};
		Sig {
			lam: lam.clone(),
			r: rr,
			s: ss,
		}
	}
	fn verify(&self, d_id: &[u8], vk: &VK, msg: &[u32], sig: &Sig) -> bool {
		// println!("--Verify");
		let mut zz_bytes_ = encode(&sig.lam.z, bincode::SizeLimit::Infinite)
			.ok()
			.unwrap();
		zz_bytes_.extend(d_id);
		let sig_v = match vk.pk_sig.verify(&zz_bytes_, &sig.lam.sig_d) {
			Ok(_) => true,
			_ => false,
		};
		if !sig_v {
			return false;
		}
		// println!("---Signature on dataset verifies? {}", sig_v);
		let pair1 = pairing(sig.lam.a, sig.lam.z);
		let pair_c_y = pairing(sig.lam.c, vk.y);
		let mut pair2 = Gt::one();
		for i in 0..vk.hs.len() {
			pair2 = pair2 * vk.hs[i];
		}
		pair2 = pair2 * pair_c_y;
		pair2 = pair2 * pairing(sig.r, self.g2);
		let v_1_2 = pair1 == pair2;
		// println!("---Pair1 == Pair2? {}", v_1_2);
		let pair3 = pairing(self.g1, sig.s) * pair_c_y;
		let mut pair4 = Gt::one();
		for i in 0..self.t {
			pair4 = pair4
				* pairing(
					self.hhs[i] * Fr::from_str(&msg[i].to_string()).unwrap(),
					self.g2,
				);
		}
		let v_3_4 = pair3 == pair4;
		// println!("---Pair3 == Pair4? {}", v_3_4);
		return v_1_2 && v_3_4;
	}
}

pub fn test_struct() {
	let rng = &mut bn_rand::thread_rng();
	let scheme = Schab2019::setup(10, 1, 1, rng);
	let key = scheme.key_gen(rng);

	let d_id = [123];
	let msg = [255];
	let l = (123, 0);
	let sig = scheme.auth(&key.sk, &d_id, &l, &msg, rng);
	let v1 = scheme.verify(&d_id, &key.vk, &msg, &sig);
	println!("V(delta1, vk1, msg1, S(sk1, delta1, (1,0), msg1)) ? {}", v1);
}

pub fn test() {
	println!("--Setup");
	let bn_rng = &mut bn_rand::thread_rng();
	let g1 = G1::one();
	let g2 = G2::one();
	let gt = pairing(g1, g2);
	const K: usize = 1000;
	const N: usize = 1;
	const T: usize = 1;
	let mut hhs: Vec<G1> = Vec::new();
	for _ in 0..T {
		hhs.push(G1::random(bn_rng))
	}

	// KeyGen
	println!("--KeyGen");
	// let rng = &mut rand::thread_rng();
	let k = bn_rng.gen::<[u8; 32]>();
	let csprng = &mut ed_rand::rngs::OsRng {};
	let sig_kp = ed25519_dalek::Keypair::generate(csprng);
	let mut xs: Vec<Fr> = Vec::new();
	let mut hs: Vec<Gt> = Vec::new();
	for _ in 0..N {
		let x = Fr::random(bn_rng);
		let h = gt.pow(x);
		xs.push(x);
		hs.push(h);
	}
	let y = Fr::random(bn_rng);
	let yy = g2 * y;
	let vk = VK {
		pk_sig: sig_kp.public,
		hs,
		y: yy,
	};
	let sk = SK {
		k,
		sig_keypair: sig_kp,
		xs,
		y,
	};
	// Auth
	let d_id: [u8; 1] = [255];
	let l: (u32, usize) = (123, 0);
	let msg = [12u32; T];

	println!("---MACing");
	let mut mac = HMS256::new_from_slice(&sk.k).expect("HMAC can take key of any size");
	mac.update(&d_id);
	let z = mac.finalize().into_bytes();
	let z_fr = Fr::from_slice(&z).unwrap();
	let zz = g2 * z_fr;
	println!("---Encoding Z");
	let mut zz_bytes = encode(&zz, bincode::SizeLimit::Infinite).ok().unwrap();
	zz_bytes.push(d_id[0]);

	let sig_d = sk.sig_keypair.sign(&zz_bytes);

	let r = Fr::random(bn_rng);
	let s = Fr::random(bn_rng);
	let rr = g1 * (r - s);
	let ss = g2 * (-s);
	let mut a = g1 * (sk.xs[l.1] + r);
	let mut c = g1 * s;
	let mut h_factor = G1::zero();
	for i in 0..T {
		h_factor = h_factor + (hhs[i] * Fr::from_str(&msg[i].to_string()).unwrap());
	}
	a = a + h_factor;
	c = c + h_factor;
	a = a * (z_fr.inverse().unwrap());
	c = c * (sk.y.inverse().unwrap());

	let lam = Lam {
		id: l.0,
		sig_d,
		z: zz,
		a,
		c,
	};
	let sig = Sig {
		lam: lam.clone(),
		r: rr,
		s: ss,
	};

	// Verify
	println!("--Verify");
	let mut zz_bytes_ = encode(&lam.z, bincode::SizeLimit::Infinite).ok().unwrap();
	zz_bytes_.push(255);
	let sig_v = match vk.pk_sig.verify(&zz_bytes_, &lam.sig_d) {
		Ok(_) => true,
		_ => false,
	};
	println!("---Signature on dataset verifies? {}", sig_v);
	let pair1 = pairing(lam.a, lam.z);
	let pair_c_y = pairing(lam.c, vk.y);
	let mut pair2 = Gt::one();
	for h_tag in vk.hs {
		pair2 = pair2 * h_tag;
	}
	pair2 = pair2 * pair_c_y;
	pair2 = pair2 * pairing(sig.r, g2);
	let v_1_2 = pair1 == pair2;
	println!("---Pair1 == Pair2? {}", v_1_2);

	let pair3 = pairing(g1, sig.s) * pair_c_y;
	let mut pair4 = Gt::one();
	for i in 0..T {
		pair4 = pair4 * pairing(hhs[i] * Fr::from_str(&msg[i].to_string()).unwrap(), g2);
	}
	let v_3_4 = pair3 == pair4;
	println!("---Pair3 == Pair4? {}", v_3_4);
}

struct Sig {
	lam: Lam,
	r: G1,
	s: G2,
}

#[derive(Clone)]
struct Lam {
	id: u32,
	sig_d: Signature,
	z: G2,
	a: G1,
	c: G1,
}

pub fn gt_test() {
	let bn_rng = &mut bn_rand::thread_rng();
	let x = Fr::random(bn_rng);
	let h = Gt::one().pow(x);
	let g = Gt::one();
	println!("h == g? {}", h == g);
	let i = pairing(G1::one(), G2::one());
	println!("i == h? {}", i == h);
}

pub fn hash_test() {
	let mut mac =
		HMS256::new_from_slice(&[123, 244, 63, 12]).expect("HMAC can take key of any size");
	mac.update(&[2, 5, 3, 1, 53, 12, 57, 84]);
	let res = mac.finalize().into_bytes();
	println!("MAC lenght: {}", res.len());
	println!("MAC: {:?}", res);
}
