use bls12_381::Pair;
use curv::arithmetic::*;
use curv::elliptic::curves::{
    bls12_381, Bls12_381_1, Bls12_381_2, ECPoint, Generator, Point, Scalar,
};
use rand::Rng;

pub type S1 = Scalar<Bls12_381_1>;
pub type S2 = Scalar<Bls12_381_2>;
pub type P1 = Point<Bls12_381_1>;
pub type P2 = Point<Bls12_381_2>;

pub struct Key {
    pub sk: BigInt,
    pub pk: P2,
    pub id: u32,
}

pub struct Program {
    pub coefficients: Vec<u32>,
    pub labels: Vec<Label>,
}

#[derive(Debug, Clone)]
pub struct Label {
    pub id: u32,
    pub tag: u32,
}

#[derive(Debug, Clone)]
pub struct Sig {
    pub ids: Vec<u32>,
    pub gam: P1,
    pub mus: Vec<u32>,
}

// #[derive(Debug)]
pub struct MkTwo {
    g1: Generator<Bls12_381_1>,
    g2: Generator<Bls12_381_2>,
}

impl MkTwo {
    fn bi_to_s1(bi: &BigInt) -> S1 {
        return S1::from_bigint(bi);
    }

    fn bi_to_s2(bi: &BigInt) -> S2 {
        return S2::from_bigint(bi);
    }

    fn u32_to_bi(u: &u32) -> BigInt {
        BigInt::from_bytes(&u.to_be_bytes())
    }

    fn u32_to_s1(u: &u32) -> S1 {
        MkTwo::bi_to_s1(&MkTwo::u32_to_bi(u))
    }

    fn u32_to_s2(u: &u32) -> S2 {
        MkTwo::bi_to_s2(&MkTwo::u32_to_bi(u))
    }

    pub fn setup() -> Self {
        Self {
            g1: P1::generator(),
            g2: P2::generator(),
        }
    }

    pub fn key_gen(&self, rng: &mut rand::prelude::ThreadRng) -> Key {
        let id: u32 = rng.gen();
        let sk = BigInt::from_bytes(&[1, 2, 3]);
        let pk = self.g2 * MkTwo::bi_to_s2(&sk);

        Key { sk, pk, id }
    }

    fn hash_label_to_curve(label: &Label) -> P1 {
        let label_on_curve = bls12_381::g1::G1Point::hash_to_curve(&label.tag.to_be_bytes());

        let res = P1::from_coords(
            &label_on_curve.x_coord().unwrap(),
            &label_on_curve.y_coord().unwrap(),
        )
        .expect("Coords not unwrapable");
        res
    }

    pub fn sign(&self, sk: &BigInt, l: &Label, m: &u32) -> Sig {
        let loc = MkTwo::hash_label_to_curve(l);
        let mut gam1 = self.g1 * MkTwo::u32_to_s1(m);
        gam1 = loc + gam1;
        gam1 = gam1 * MkTwo::bi_to_s1(sk);
        Sig {
            ids: vec![l.id],
            gam: gam1,
            mus: vec![*m],
        }
    }

    fn compute_partial_c(
        &self,
        mus: &Vec<u32>,
        labels: &Vec<Label>,
        coefficients: &Vec<u32>,
        pks: &Vec<P2>,
        i: usize,
    ) -> Pair {
        let mut p1 = self.g1 * MkTwo::u32_to_s1(&mus[i]);
        let loc = MkTwo::hash_label_to_curve(&labels[i]) * MkTwo::u32_to_s1(&coefficients[i]);
        p1 = p1 + loc;
        Pair::compute_pairing(&p1, &pks[i])
    }

    pub fn verify(&self, program: &Program, pks: &Vec<P2>, m: &u32, s: &Sig) -> bool {
        let sum_mus: u32 = s.mus.iter().sum();
        let ver1 = m == &sum_mus;
        if !ver1 {
            println!("{} != {}", m, sum_mus);
            return false;
        }

        let mut c = self.compute_partial_c(&s.mus, &program.labels, &program.coefficients, pks, 0);
        for i in 1..s.mus.len() {
            c = c.add_pair(&self.compute_partial_c(
                &s.mus,
                &program.labels,
                &program.coefficients,
                pks,
                i,
            ));
        }

        c == Pair::compute_pairing(&s.gam, &self.g2)
    }

    fn eval(&self, coefficients: &Vec<u32>, signatures: &Vec<Sig>) -> Sig {
        let mut gam = signatures[0].gam.clone() * MkTwo::u32_to_s1(&coefficients[0]);
        let mut mus: Vec<u32> = signatures.iter().flat_map(|s| s.mus.clone()).collect();
        mus[0] = mus[0] * coefficients[0];
        for i in 1..signatures.len() {
            gam = gam + signatures[i].gam.clone() * MkTwo::u32_to_s1(&coefficients[i]);
            mus[i] = mus[i] * coefficients[i];
        }

        let ids = signatures.iter().flat_map(|s| s.ids.clone()).collect();

        Sig { gam, ids, mus }
    }
}

pub fn test() {
    let mut rng = rand::thread_rng();
    let scheme = MkTwo::setup();

    let k1 = scheme.key_gen(&mut rng);

    let m1 = 2;

    let l1 = Label {
        id: k1.id,
        tag: 123,
    };

    println!("[#] Signing {} by {}", &m1, &k1.id);
    let s1 = scheme.sign(&k1.sk, &l1, &m1);

    // println!("S1: {:?}", s1);

    let k2 = scheme.key_gen(&mut rng);
    let m2: u32 = 5;
    let l2 = Label {
        id: k2.id,
        tag: 345,
    };

    println!("[#] Signing {} by {}", &m2, &k2.id);
    let s2 = scheme.sign(&k2.sk, &l2, &m2);
    // println!("S2: {:?}", s2);
    println!("==================");

    let p1 = Program {
        coefficients: vec![1],
        labels: vec![l1.clone()],
    };

    let p2 = Program {
        coefficients: vec![1],
        labels: vec![l2.clone()],
    };

    let v1 = scheme.verify(&p1, &vec![k1.pk.clone()], &m1, &s1);
    println!("Identity program verifies for s1? {}", &v1);
    let v2 = scheme.verify(&p2, &vec![k2.pk.clone()], &m2, &s2);
    println!("Identity program verifies for s2? {}", &v2);

    let p_comb = Program {
        coefficients: vec![2, 3],
        labels: vec![l1.clone(), l2.clone()],
    };

    let m_comb = vec![m1, m2]
        .iter()
        .zip(&p_comb.coefficients)
        .map(|(m, c)| m * c)
        .sum();

    println!("[#] Signing {} by {:?}", &m_comb, vec![k1.id, k2.id]);
    let s_comb = scheme.eval(&p_comb.coefficients, &vec![s1, s2]);
    let v_comb = scheme.verify(&p_comb, &vec![k1.pk, k2.pk], &(m_comb), &s_comb);
    println!("s_comb verifies? {}", v_comb);
}
