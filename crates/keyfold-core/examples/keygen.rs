//! Generate the Ed25519 licence keypair.
//!   cargo run -p keyfold-core --example keygen          # fresh random keypair
//!   cargo run -p keyfold-core --example keygen -- --dev # the fixed dev keypair
//! Keep the SEED only in the licence server's secrets. Embed the PUBLIC key in
//! the app via the KEYFOLD_LICENCE_PUBKEY build-time environment variable.
fn main() {
    let dev = std::env::args().any(|a| a == "--dev");
    let seed: [u8; 32] = if dev {
        [42u8; 32]
    } else {
        let mut s = [0u8; 32];
        getrandom::fill(&mut s).expect("os rng");
        s
    };
    let pk = keyfold_core::licence::public_key_for(&seed);
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!("SEED   (secret, licence server only): {}", hex(&seed));
    println!("PUBKEY (embed in app):                {}", hex(&pk));
    if dev {
        let lic = keyfold_core::Licence {
            product: "keyfold".into(),
            email: "dev@keyfold.local".into(),
            plan: keyfold_core::LicencePlan::Lifetime,
            issued_at: keyfold_core::time::now_ms(),
            expires_at: None,
        };
        println!(
            "DEV LICENCE TOKEN: {}",
            keyfold_core::licence::sign(&lic, &seed).unwrap()
        );
    }
}
