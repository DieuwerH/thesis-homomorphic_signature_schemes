use bn::{Fr, Group, Gt, G1, G2, pairing};
use bn_rand;

pub fn main() {
    let rng = &mut bn_rand::thread_rng();
    let sk1 = Fr::random(rng);
    let pk1 = G2::one() * sk1.clone();

    let m = "123";
    let m_encoded = Fr::from_str(&m).unwrap();

    let sig1 = G1::one() * m_encoded * sk1.clone();
    let ver1 = pairing(sig1, G2::one()) == pairing(G1::one() * m_encoded.clone(), pk1.clone());
    println!("Signature for {} verifies? {}", m, ver1);

    let m2 = "3";
    let m_enc2 = Fr::from_str(&m2).unwrap();
    let sig2 = G1::one() * m_enc2 * sk1.clone();
    
    let sig_comb = sig1 + sig2;
    let m_comb = "126";
    let m_comb_enc = Fr::from_str(&m_comb).unwrap();
    let v_comb = pairing(sig_comb, G2::one()) == pairing(G1::one() * m_comb_enc, pk1.clone());
    println!("Signature for {} verifies? {}", m_comb, v_comb);

    let sk2 = Fr::random(rng);
    let pk2 = G2::one() * sk2.clone();

    let m3 = "10";
    let m3_enc = Fr::from_str(&m3).unwrap();
    let sig3 = G1::one() * m3_enc.clone() * sk2.clone();

    let sig_comb13 = sig1 + sig3;
    let m_1_3 = Fr::from_str("133").unwrap();
    let v_comb = pairing(sig_comb13, G2::one()) == pairing(p: G1, q: G2)


}
