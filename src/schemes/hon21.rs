use crate::util::bls_util::*;
use bls12_381::Pair;
use curv::elliptic::curves::bls12_381;
use curv::BigInt;

const DBG: bool = false;

type PK = P2;
type SK = BigInt;
type MSG = u32;

trait ToScalar {
	fn to_s1(&self) -> S1;
	fn to_s2(&self) -> S2;
}

impl ToScalar for MSG {
	fn to_s1(&self) -> S1 {
		u32_to_s1(self)
	}
	fn to_s2(&self) -> S2 {
		u32_to_s2(self)
	}
}

struct Key {
	pk: PK,
	sk: SK,
}

#[derive(Clone)]
struct Sig {
	gam: P1,
	mus: Vec<MSG>,
}

impl Sig {
	fn sum_mus(&self) -> MSG {
		self.mus.iter().sum()
	}
}

struct VK {
	h: Pair,
	pkc: PK,
}

#[derive(Clone)]
struct Label {
	id: u16,
	tg: u16,
}

struct CombineInput {
	s: Sig,
	pk: PK,
	h: Option<Pair>,
	l: Option<Label>,
}
impl CombineInput {
	fn new(s: &Sig, pk: &PK, h: &Option<Pair>, l: &Option<Label>) -> Self {
		Self { s: s.clone(), pk: pk.clone(), h: h.clone(), l: l.clone() }
	}
	fn compute_h(&self) -> Pair {
		if let Some(p) = self.h {
			return p;
		} else {
			// If we are here self.h was none, and thus l should contain a value;
			let l = (self.l).as_ref().unwrap();
			Pair::compute_pairing(&l.hash(), &self.pk)
		}
	}
}

impl Label {
	fn to_u32(&self) -> u32 {
		let res: u32 = (self.id as u32) + (self.tg as u32);
		res
	}
	fn hash(&self) -> P1 {
		hash_to_curve(self.to_u32())
	}
}

struct Hon21 {
	g1: G1,
	g2: G2,
}

impl Hon21 {
	fn setup() -> Self {
		Self {
			g1: P1::generator(),
			g2: P2::generator(),
		}
	}
	fn key_gen(&self) -> Key {
		let sk_scalar2 = S2::random();
		let sk = sk_scalar2.to_bigint();
		let pk = self.g2 * sk_scalar2;
		Key { pk, sk }
	}
	fn sign(&self, m: &MSG, sk: &SK, l: &Label) -> Sig {
		let h = l.hash();
		let gam = (h + (self.g1 * m.to_s1())) * bi_to_s1(sk);
		let mus = vec![*m];
		Sig { gam, mus }
	}
	fn verify(&self, sig: &Sig, m: &MSG, pks: &Vec<&PK>, ls: &Vec<&Label>) -> bool {
		let sum_mus: MSG = sig.mus.iter().sum();
		let v1 = *m == sum_mus;
		if DBG {
			println!("v1? {}", v1)
		};

		let g1_in = (self.g1 * sig.mus[0].to_s1()) + ls[0].hash();
		let mut c = Pair::compute_pairing(&g1_in, &pks[0]);

		for i in 1..ls.len() {
			let g1_in = (self.g1 * sig.mus[i].to_s1()) + ls[i].hash();
			let pair = Pair::compute_pairing(&g1_in, &pks[i]);
			c = c.add_pair(&pair);
		}
		let c_ = Pair::compute_pairing(&sig.gam, &self.g2);
		let v2 = c == c_;
		if DBG {
			println!("v2? {}", v2)
		};
		return v1 && v2;
	}
	fn combine(&self, signatures: &Vec<&Sig>, pks: &Vec<&PK>, ls: &Vec<&Label>) -> (Sig, VK) {
		let mut sig_c = Sig {
			gam: P1::zero(),
			mus: Vec::new(),
		};
		for sig in signatures {
			sig_c.gam = sig_c.gam + &sig.gam;
			sig_c.mus.extend(sig.mus.clone());
		}
		let mut h = Pair::compute_pairing(&ls[0].hash(), &pks[0]);
		let mut pkc = pks[0].clone() * &signatures[0].sum_mus().to_s2();
		for i in 1..ls.len() {
			h = h.add_pair(&Pair::compute_pairing(&ls[i].hash(), &pks[i]));
			pkc = pkc + (pks[i].clone() * &signatures[i].sum_mus().to_s2())
		}
		let sum_inv = sig_c.sum_mus().to_s2().invert().unwrap();
		pkc = pkc * &sum_inv;

		(sig_c, VK { h, pkc })
	}
	fn verify_identity_hiding(&self, sig: &Sig, m: &MSG, vk: &VK) -> bool {
		let c = Pair::compute_pairing(&sig.gam, &self.g2);
		let c_ =
			vk.h.add_pair(&Pair::compute_pairing(&(self.g1 * &m.to_s1()), &vk.pkc));
		c == c_
	}
	fn combine2(&self, inputs: &Vec<CombineInput>) -> (Sig, VK) {
		let mut sig_c = Sig {
			gam: inputs[0].s.gam.clone(),
			mus: inputs[0].s.mus.clone(),
		};
		let mut h = inputs[0].compute_h();
		let mut pkc = inputs[0].pk.clone() * inputs[0].s.sum_mus().to_s2();
		for i in 1..inputs.len() {
			let inp = &inputs[i];
			sig_c.gam = sig_c.gam + &inp.s.gam;
			sig_c.mus.extend(inp.s.mus.clone());
			h = h.add_pair(&inp.compute_h());
			pkc = pkc + (inp.pk.clone() * &inp.s.sum_mus().to_s2());
		}
		let sum_inv = sig_c.sum_mus().to_s2().invert().unwrap();
		pkc = pkc * &sum_inv;
		(sig_c, VK { h, pkc })
	}
}

fn zero_test() {
	let zero = P1::zero();
	let one = P1::generator() * u32_to_s1(&1);
	let check = one == zero + &one;
	println!("Check? {}", check);

	let z1 = P1::zero();
	let z2 = P2::zero();
	let pair = Pair::compute_pairing(&z1, &z2);
	let pair2 = Pair::compute_pairing(&one, &P2::generator());
	let check2 = pair == pair2;
	println!("Check? {}", check2);
}

pub fn test() {
	zero_test();
	let scheme = Hon21::setup();
	let id1: u16 = 12;
	let key1 = scheme.key_gen();
	let msg1 = 123;
	let tag1: u16 = 5;
	let lab1 = Label { id: id1, tg: tag1 };
	let sig1 = scheme.sign(&msg1, &key1.sk, &lab1);
	let ver1 = scheme.verify(&sig1, &msg1, &vec![&key1.pk], &vec![&lab1]);
	println!("V(S(123, sk1, lab1), 123, [pk1], [lab1])? {}", ver1);

	let id2: u16 = 92;
	let key2 = scheme.key_gen();
	let msg2 = 321;
	let tag2: u16 = 53;
	let lab2 = Label { id: id2, tg: tag2 };
	let sig2 = scheme.sign(&msg2, &key2.sk, &lab2);
	let ver2 = scheme.verify(&sig2, &msg2, &vec![&key2.pk], &vec![&lab2]);
	println!("V(S(321, sk2, lab2), 321, [pk2], [lab2])? {}", ver2);

	let (sig_combined, vk) = scheme.combine(
		&vec![&sig1, &sig2],
		&vec![&key1.pk, &key2.pk],
		&vec![&lab1, &lab2],
	);
	let ver_combined = scheme.verify(
		&sig_combined,
		&(msg1 + msg2),
		&vec![&key1.pk, &key2.pk],
		&vec![&lab1, &lab2],
	);

	println!(
		"V(C([s1,s2],[pk1,pk2],[l1,l2]),444, [pk1,pk2], [l1,l2])? {}",
		ver_combined
	);
	let ver_identity_hiding = scheme.verify_identity_hiding(&sig_combined, &(msg1 + msg2), &vk);
	println!(
		"V(C([s1,s2],[pk1,pk2],[l1,l2]),msg1+msg2,vk)? {}",
		ver_identity_hiding
	);

	let id3: u16 = 76;
	let key3 = scheme.key_gen();
	let msg3 = 222;
	let tag3: u16 = 2;
	let lab3 = Label {id: id3, tg: tag3 };
	let sig3 = scheme.sign(&msg3, &key3.sk, &lab3);

	let c123_input_1 = CombineInput::new(&sig_combined, &vk.pkc, &Some(vk.h), &None);
	let c123_input_2 = CombineInput::new(&sig3, &key3.pk, &None, &Some(lab3.clone()));

	let (sig_123, vk_123) = scheme.combine2(&vec![c123_input_1, c123_input_2]);
	let v_123_1 = scheme.verify(&sig_123, &666, &vec![&key1.pk, &key2.pk, &key3.pk], &vec![&lab1, &lab2, &lab3]);
	println!("v_123_1? {}", v_123_1);
	let v_123_2 = scheme.verify_identity_hiding(&sig_123, &666, &vk_123);
	println!("v_123_2? {}", v_123_2);

	let cc_input_1 = CombineInput::new(&sig_combined, &vk.pkc, &Some(vk.h), &None);
	let cc_input_2 = CombineInput::new(&sig_123, &vk_123.pkc, &Some(vk_123.h), &None);
	let (sig_c_c, vk_cc) = scheme.combine2(&vec![cc_input_1, cc_input_2]);
	let v_cc = scheme.verify_identity_hiding(&sig_c_c, &((msg1 + msg2) + (msg1 + msg2 + msg3)), &vk_cc);
	println!("VCC {}", v_cc);
}
