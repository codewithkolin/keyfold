//! Issue a licence token by hand (support, comps, re-sends).
//!   KEYFOLD_LICENCE_SEED=<64 hex> cargo run -p keyfold-core --example issue -- \
//!       --email someone@example.com --plan lifetime|yearly [--days 380] [--issued-at <unix ms>] \
//!       [--device XXXX-XXXX-XXXX-XXXX --purchase <purchase key fingerprint>]
//! Without --device it prints a purchase key; with it, a licence for that one computer.
//! Purchases are issued automatically by the licence server; the seed must match its
//! KEYFOLD_LICENCE_{TEST,LIVE}_SEED.
use keyfold_core::{Licence, LicencePlan};

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn main() {
    let seed_hex = std::env::var("KEYFOLD_LICENCE_SEED")
        .or_else(|_| std::env::var("KEYFOLD_LICENCE_LIVE_SEED"))
        .expect("set KEYFOLD_LICENCE_SEED or KEYFOLD_LICENCE_LIVE_SEED");
    let seed: [u8; 32] = (0..32)
        .map(|i| u8::from_str_radix(&seed_hex.trim()[i * 2..i * 2 + 2], 16).expect("seed hex"))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let email = arg("--email").expect("--email required");
    let issued_at = arg("--issued-at")
        .map(|s| s.parse().expect("--issued-at unix ms"))
        .unwrap_or_else(keyfold_core::time::now_ms);
    let (plan, expires_at) = match arg("--plan").as_deref() {
        Some("lifetime") => (LicencePlan::Lifetime, None),
        Some("yearly") => {
            let days: i64 = arg("--days").map_or(380, |d| d.parse().expect("--days"));
            (LicencePlan::Yearly, Some(issued_at + days * 86_400_000))
        }
        _ => panic!("--plan lifetime|yearly required"),
    };
    let lic = Licence {
        product: keyfold_core::licence::PRODUCT.into(),
        email,
        plan,
        issued_at,
        expires_at,
        device: arg("--device").map(|d| {
            keyfold_core::device::normalise_code(&d).expect("--device is not a computer code")
        }),
        purchase: arg("--purchase"),
    };
    println!("{}", keyfold_core::licence::sign(&lic, &seed).unwrap());
}
