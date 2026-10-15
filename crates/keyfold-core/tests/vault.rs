use keyfold_core::{
    licence, vault::backup_path, Error, KdfSettings, Licence, LicencePlan, Limit, PasswordInput,
    Plan, SecretInput, Vault,
};

fn fast() -> KdfSettings {
    KdfSettings {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

fn pw(title: &str, username: &str, password: &str) -> PasswordInput {
    PasswordInput {
        title: title.into(),
        username: username.into(),
        password: password.into(),
        url: String::new(),
        notes: String::new(),
        totp_secret: None,
        tags: vec![],
    }
}

fn sample_secret(key: &str) -> SecretInput {
    SecretInput {
        key: key.into(),
        value: format!("value-of-{key}"),
        notes: "n".into(),
        tags: vec!["t".into()],
        url: "https://x".into(),
        expires_at: None,
    }
}

fn seeded_vault(dir: &std::path::Path) -> (Vault, String) {
    let path = dir.join("test.keyfold");
    let mut v = Vault::create(&path, b"correct horse battery staple", fast()).unwrap();
    let pid = v.body.add_project("Acme", "violet", Plan::Free).unwrap();
    let eid = v.body.add_environment(&pid, "production").unwrap();
    let sid = v
        .body
        .add_secret(&eid, sample_secret("STRIPE_KEY"), Plan::Free)
        .unwrap();
    v.body
        .add_password(pw("GitHub", "suman", "hunter2"), Plan::Free)
        .unwrap();
    v.save().unwrap();
    (v, sid)
}

#[test]
fn create_save_open_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let (v, sid) = seeded_vault(dir.path());
    let path = v.path().to_path_buf();
    drop(v);
    let v2 = Vault::open(&path, b"correct horse battery staple").unwrap();
    let (p, e, s) = v2.body.find_secret(&sid).unwrap();
    assert_eq!(p.name, "Acme");
    assert_eq!(e.name, "production");
    assert_eq!(s.value, "value-of-STRIPE_KEY");
    assert_eq!(v2.body.passwords[0].password, "hunter2");
    assert_eq!(v2.body.item_count(), 2);
}

#[test]
fn wrong_password_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (v, _) = seeded_vault(dir.path());
    let err = Vault::open(v.path(), b"wrong").unwrap_err();
    assert!(matches!(err, Error::WrongPassword), "{err:?}");
}

#[test]
fn create_refuses_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let (v, _) = seeded_vault(dir.path());
    let err = Vault::create(v.path(), b"pw", fast()).unwrap_err();
    assert!(matches!(err, Error::AlreadyExists));
}

#[test]
fn flipping_any_byte_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let (v, _) = seeded_vault(dir.path());
    let bytes = v.to_bytes().unwrap();
    let path = v.path().to_path_buf();
    // Every byte of the file, not a sample: header, lengths, nonce, ciphertext, tag.
    for i in 0..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        let r = Vault::from_bytes(&path, &b, b"correct horse battery staple");
        assert!(r.is_err(), "flip at byte {i} was not detected");
    }
}

#[test]
fn truncated_and_padded_files_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (v, _) = seeded_vault(dir.path());
    let bytes = v.to_bytes().unwrap();
    for cut in [0, 5, 13, 40, bytes.len() - 1] {
        assert!(
            Vault::from_bytes(v.path(), &bytes[..cut], b"correct horse battery staple").is_err(),
            "cut {cut}"
        );
    }
    let mut padded = bytes.clone();
    padded.push(0);
    assert!(Vault::from_bytes(v.path(), &padded, b"correct horse battery staple").is_err());
}

#[test]
fn backups_rotate_and_cap_at_five() {
    let dir = tempfile::tempdir().unwrap();
    let (mut v, _) = seeded_vault(dir.path());
    for _ in 0..7 {
        v.save().unwrap();
    }
    let path = v.path();
    for n in 1..=5 {
        assert!(backup_path(path, n).exists(), "bak{n} missing");
    }
    assert!(!backup_path(path, 6).exists());
    assert!(!path.with_extension("keyfold.tmp").exists());
    // A backup is a valid vault with the same password.
    assert!(Vault::open(backup_path(path, 1), b"correct horse battery staple").is_ok());
}

#[test]
fn change_password_rewraps_without_touching_data() {
    let dir = tempfile::tempdir().unwrap();
    let (mut v, sid) = seeded_vault(dir.path());
    assert!(matches!(
        v.change_password(b"nope", b"new pass", fast()).unwrap_err(),
        Error::WrongPassword
    ));
    v.change_password(b"correct horse battery staple", b"new pass", fast())
        .unwrap();
    let path = v.path().to_path_buf();
    drop(v);
    assert!(matches!(
        Vault::open(&path, b"correct horse battery staple").unwrap_err(),
        Error::WrongPassword
    ));
    let v2 = Vault::open(&path, b"new pass").unwrap();
    assert!(v2.body.find_secret(&sid).is_some());
}

#[test]
fn dek_reopen_matches_password_path() {
    let dir = tempfile::tempdir().unwrap();
    let (v, sid) = seeded_vault(dir.path());
    let dek = v.dek();
    let v2 = Vault::open_with_dek(v.path(), dek).unwrap();
    assert!(v2.body.find_secret(&sid).is_some());
}

#[test]
fn free_plan_limits_projects_and_items() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("free.keyfold");
    let mut v = Vault::create(&path, b"pw", fast()).unwrap();
    let pid = v.body.add_project("one", "", Plan::Free).unwrap();
    let err = v.body.add_project("two", "", Plan::Free).unwrap_err();
    assert!(matches!(err, Error::LimitReached(Limit::Projects(1))));
    v.body.add_project("two", "", Plan::Pro).unwrap();

    let eid = v.body.add_environment(&pid, "dev").unwrap();
    for i in 0..25 {
        v.body
            .add_secret(&eid, sample_secret(&format!("K{i}")), Plan::Free)
            .unwrap();
    }
    let err = v
        .body
        .add_secret(&eid, sample_secret("K25"), Plan::Free)
        .unwrap_err();
    assert!(matches!(err, Error::LimitReached(Limit::Items(25))));
    let err = v
        .body
        .add_password(pw("x", "", "y"), Plan::Free)
        .unwrap_err();
    assert!(matches!(err, Error::LimitReached(Limit::Items(25))));
    v.body
        .add_secret(&eid, sample_secret("K25"), Plan::Pro)
        .unwrap();
}

#[test]
fn crud_paths() {
    let dir = tempfile::tempdir().unwrap();
    let (mut v, sid) = seeded_vault(dir.path());
    let mut upd = sample_secret("RENAMED");
    upd.value = "new".into();
    v.body.update_secret(&sid, upd).unwrap();
    assert_eq!(v.body.find_secret(&sid).unwrap().2.value, "new");
    assert!(matches!(
        v.body
            .update_secret("missing", sample_secret("x"))
            .unwrap_err(),
        Error::NotFound
    ));
    v.body.delete_secret(&sid).unwrap();
    assert!(v.body.find_secret(&sid).is_none());
    let pid = v.body.projects[0].id.clone();
    v.body.update_project(&pid, "Acme 2", "teal").unwrap();
    assert_eq!(v.body.projects[0].name, "Acme 2");
    let eid = v.body.projects[0].environments[0].id.clone();
    v.body.rename_environment(&eid, "prod").unwrap();
    v.body.delete_environment(&eid).unwrap();
    assert!(v.body.projects[0].environments.is_empty());
    v.body.delete_project(&pid).unwrap();
    assert!(v.body.projects.is_empty());
    let pwid = v.body.passwords[0].id.clone();
    v.body.update_password(&pwid, pw("GH", "", "z")).unwrap();
    assert_eq!(v.body.find_password(&pwid).unwrap().title, "GH");
    v.body.delete_password(&pwid).unwrap();
    assert_eq!(v.body.item_count(), 0);
}

#[test]
fn licence_tokens_verify_offline() {
    let seed = [7u8; 32];
    let pk = licence::public_key_for(&seed);
    let lic = Licence {
        product: "keyfold".into(),
        email: "a@b.c".into(),
        plan: LicencePlan::Yearly,
        issued_at: 1_000,
        expires_at: Some(2_000),
        device: None,
        purchase: None,
    };
    let token = licence::sign(&lic, &seed).unwrap();
    assert_eq!(licence::verify(&token, &pk, 1_500).unwrap(), lic);
    assert!(matches!(
        licence::verify(&token, &pk, 2_000).unwrap_err(),
        Error::Licence("licence has expired")
    ));
    let other_pk = licence::public_key_for(&[9u8; 32]);
    assert!(licence::verify(&token, &other_pk, 1_500).is_err());
    let mut tampered = token.clone();
    tampered.replace_range(2..3, if &token[2..3] == "A" { "B" } else { "A" });
    assert!(licence::verify(&tampered, &pk, 1_500).is_err());
    assert!(licence::verify("garbage", &pk, 0).is_err());
    let lifetime = Licence {
        plan: LicencePlan::Lifetime,
        expires_at: None,
        device: None,
        purchase: None,
        ..lic
    };
    let t = licence::sign(&lifetime, &seed).unwrap();
    assert!(licence::verify(&t, &pk, i64::MAX - 1).is_ok());
}

#[test]
fn recovery_kit_opens_vault_and_rotates() {
    let dir = tempfile::tempdir().unwrap();
    let (mut v, sid) = seeded_vault(dir.path());
    let path = v.path().to_path_buf();
    assert!(!v.has_recovery());
    assert!(matches!(
        keyfold_core::Vault::open_with_recovery(
            &path,
            &keyfold_core::RecoveryCode::from_bytes([0; 20])
        )
        .unwrap_err(),
        Error::NoRecovery
    ));

    let code = v.enable_recovery().unwrap();
    assert!(v.has_recovery());
    assert!(Vault::read_has_recovery(&path).unwrap());
    let shown = code.display();
    drop(v);

    // Typed sloppily: lowercase, no dashes, O for 0.
    let typed = shown.to_lowercase().replace('-', "").replace('0', "o");
    let parsed = keyfold_core::RecoveryCode::parse(&typed).unwrap();
    let mut v2 = Vault::open_with_recovery(&path, &parsed).unwrap();
    assert!(v2.body.find_secret(&sid).is_some());

    // Wrong code is rejected.
    let wrong = keyfold_core::RecoveryCode::from_bytes([9; 20]);
    assert!(matches!(
        Vault::open_with_recovery(&path, &wrong).unwrap_err(),
        Error::WrongRecoveryCode
    ));

    // New passphrase without the old one, then a fresh code retires the old one.
    v2.set_password(b"brand new passphrase", fast()).unwrap();
    let code2 = v2.enable_recovery().unwrap();
    drop(v2);
    assert!(matches!(
        Vault::open(&path, b"correct horse battery staple").unwrap_err(),
        Error::WrongPassword
    ));
    assert!(Vault::open(&path, b"brand new passphrase").is_ok());
    assert!(matches!(
        Vault::open_with_recovery(&path, &parsed).unwrap_err(),
        Error::WrongRecoveryCode
    ));
    assert!(Vault::open_with_recovery(&path, &code2).is_ok());

    // Turning it off removes the path entirely.
    let mut v3 = Vault::open(&path, b"brand new passphrase").unwrap();
    v3.disable_recovery().unwrap();
    drop(v3);
    assert!(matches!(
        Vault::open_with_recovery(&path, &code2).unwrap_err(),
        Error::NoRecovery
    ));
}

#[test]
fn hint_is_readable_while_locked_and_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let (mut v, _) = seeded_vault(dir.path());
    let path = v.path().to_path_buf();
    assert_eq!(Vault::read_hint(&path).unwrap(), None);
    v.set_hint(Some("  the usual four words  ")).unwrap();
    assert_eq!(v.hint(), Some("the usual four words"));
    assert!(v.set_hint(Some(&"x".repeat(81))).is_err());
    v.set_hint(Some(&"y".repeat(80))).unwrap();
    drop(v);
    assert_eq!(Vault::read_hint(&path).unwrap().unwrap().len(), 80);
    let mut v = Vault::open(&path, b"correct horse battery staple").unwrap();
    v.set_hint(Some("   ")).unwrap();
    assert_eq!(v.hint(), None);
}

#[test]
fn recovery_header_tamper_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let (mut v, _) = seeded_vault(dir.path());
    let code = v.enable_recovery().unwrap();
    let bytes = v.to_bytes().unwrap();
    // Flip bytes inside the header region only (after the 14-byte prefix).
    for i in (14..bytes.len().min(700)).step_by(7) {
        let mut b = bytes.clone();
        b[i] ^= 0x40;
        std::fs::write(v.path(), &b).unwrap();
        assert!(
            Vault::open_with_recovery(v.path(), &code).is_err(),
            "flip at {i}"
        );
    }
}

#[test]
fn export_backup_opens_with_the_same_passphrase_and_refuses_the_vault_itself() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.keyfold");
    let mut v = Vault::create(&path, b"pw", fast()).unwrap();
    let pid = v.body.add_project("Acme", "", Plan::Free).unwrap();
    let eid = v.body.add_environment(&pid, "dev").unwrap();
    v.body
        .add_secret(&eid, sample_secret("ONE"), Plan::Free)
        .unwrap();
    v.save().unwrap();
    v.save().unwrap(); // creates main.keyfold.bak1

    let dest = dir.path().join("copy.keyfold");
    v.export_backup(&dest).unwrap();
    let copy = Vault::open(&dest, b"pw").unwrap();
    assert_eq!(copy.body.item_count(), 1);
    assert!(Vault::open(&dest, b"wrong").is_err());

    for bad in [path.clone(), keyfold_core::vault::backup_path(&path, 1)] {
        assert!(
            matches!(v.export_backup(&bad), Err(Error::Backup(_))),
            "{bad:?}"
        );
    }
}

#[test]
fn restore_replaces_the_vault_and_keeps_the_old_one_as_bak1() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.keyfold");
    let mut v = Vault::create(&path, b"pw", fast()).unwrap();
    let pid = v.body.add_project("Acme", "", Plan::Free).unwrap();
    let eid = v.body.add_environment(&pid, "dev").unwrap();
    v.body
        .add_secret(&eid, sample_secret("ONE"), Plan::Free)
        .unwrap();
    v.save().unwrap();
    let code = v.enable_recovery().unwrap();
    v.save().unwrap();

    let backup = dir.path().join("backup.keyfold");
    v.export_backup(&backup).unwrap();
    v.body
        .add_secret(&eid, sample_secret("TWO"), Plan::Free)
        .unwrap();
    v.save().unwrap();
    drop(v);

    // Restore with the backup's recovery code: the vault goes back to one item.
    let opened = Vault::open_with_recovery(&backup, &code).unwrap();
    let restored = opened.restore_into(&path).unwrap();
    assert_eq!(restored.path(), path.as_path());
    assert_eq!(restored.body.item_count(), 1);
    assert_eq!(Vault::open(&path, b"pw").unwrap().body.item_count(), 1);

    // The pre-restore state (two items) is the newest rolling backup.
    let previous = Vault::open(keyfold_core::vault::backup_path(&path, 1), b"pw").unwrap();
    assert_eq!(previous.body.item_count(), 2);

    // Restoring the open vault onto itself is refused.
    let same = Vault::open(&path, b"pw").unwrap();
    assert!(matches!(same.restore_into(&path), Err(Error::Backup(_))));
}
