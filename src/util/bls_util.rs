use curv::arithmetic::Converter;
use curv::elliptic::curves::bls12_381;
use curv::elliptic::curves::Bls12_381_1;
use curv::elliptic::curves::Bls12_381_2;
use curv::elliptic::curves::ECPoint;
use curv::elliptic::curves::Point;
use curv::elliptic::curves::Scalar;
use curv::BigInt;

pub type P1 = Point<Bls12_381_1>;
pub type P2 = Point<Bls12_381_2>;
pub type S1 = Scalar<Bls12_381_1>;
pub type S2 = Scalar<Bls12_381_2>;

pub fn bi_to_s1(bi: &BigInt) -> S1 {
	return S1::from_bigint(bi);
}

pub fn bi_to_s2(bi: &BigInt) -> S2 {
	return S2::from_bigint(bi);
}

pub fn u32_to_bi(u: &u32) -> BigInt {
	BigInt::from_bytes(&u.to_be_bytes())
}

pub fn u32_to_s1(u: &u32) -> S1 {
	bi_to_s1(&u32_to_bi(u))
}

pub fn u32_to_s2(u: &u32) -> S2 {
	bi_to_s2(&u32_to_bi(u))
}

fn hash_to_curve(msg: &[u8]) -> P1 {
	let on_curve = bls12_381::g1::G1Point::hash_to_curve(msg);
	P1::from_coords(&on_curve.x_coord().unwrap(), &on_curve.y_coord().unwrap())
		.expect("Coord not unwrapable")
}

pub fn prod_hash_ids(id: &u32, vector: &Vec<u32>) -> P1 {
	let mut res = P1::zero();
	let id_bytes = id.to_be_bytes();

	for (i, v_i) in vector.iter().enumerate() {
		let mut to_hash = id_bytes.to_vec();
		to_hash.append(&mut i.to_be_bytes().to_vec());
		let s_i = hash_to_curve(&to_hash) * u32_to_s1(&v_i);
		res = res + s_i;
	}

	res
}
