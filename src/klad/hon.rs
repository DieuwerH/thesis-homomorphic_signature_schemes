use bn::{G1, G2, Gt, Group, Fr};
use bn_rand;


pub fn run() {
    println!("Running");


    let g1 = G1::one();
    let g2 = G2::one();
    let gt = Gt::one();

    let rng = &mut bn_rand::thread_rng();
    let sk = Fr::random(rng);
    let pk = g2 * sk;

    let mut msg: [u8;32] = [0u8; 32];
    msg[31] = 123;

    let fr_msg = Fr::from_slice(&msg).unwrap();

    let sig = g1 * fr_msg * sk;

    let ver1 = verify(&sig, &msg, &pk);

    println!("Verifies? {}", ver1);

    let mut msg2 = [0u8; 32];
    msg2[31] = 2;
    let fr_msg2 = Fr::from_slice(&msg2).unwrap();
    let sig2 = g1 * fr_msg2;

    let comb = sig + sig2;
    let mut comb_msg = [0u8; 32];
    comb_msg[31] = 125;

    let ver_comb = verify(&comb, &comb_msg, &pk);
    println!("Vcomb? {}", ver_comb);

}

fn verify(sig: &G1, msg: &[u8;32], pk: &G2) -> bool {
    let fr_msg = compute_fr_msg(msg);
    let p1 = bn::pairing(sig.clone(), G2::one());
    let p2 = bn::pairing(G1::one() * fr_msg, pk.clone());
    p1 == p2
}

fn compute_fr_msg(msg: &[u8;32]) -> Fr {
    Fr::from_slice(msg).unwrap()
}