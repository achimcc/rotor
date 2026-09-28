//! Audit 3 of the homeserver (2026-09-27), CD-7 / B92: readers rotor could
//! not see, and a run that ended with exit 0 all the same. The probe from the
//! audit, turned around: it now has to be a finding.

mod fixture;
use fixture::*;

fn run(args: &[&str]) -> (i32, String) {
    rotor::run(args.iter().map(|s| s.to_string()).collect())
}

fn blind(f: &Fix) -> (String, std::path::PathBuf) {
    let s = f.store();
    f.file(
        "store/aa-split",
        "#!/bin/sh\nd=/run/secrets\ncat \"$d/k\"\n",
    );
    f.file("store/bb-var", "#!/bin/sh\ncat /run/secrets/$NAME\n");
    let t = f.host(
        &manifest_json(
            &[
                ("k", "/run/secrets/k", &["gedeckt.service"]),
                ("niemand", "/run/secrets/niemand", &[]),
            ],
            &[],
        ),
        &[
            (
                "gedeckt.service",
                "[Service]\nEnvironmentFile=/run/secrets/k\nExecStart=/bin/g\n",
            ),
            (
                "split.service",
                &format!("[Service]\nExecStart={s}aa-split\n"),
            ),
            (
                "var.service",
                &format!("[Service]\nEnvironment=NAME=k\nExecStart={s}bb-var\n"),
            ),
            (
                "etc.service",
                "[Service]\nExecStart=/bin/x --config /etc/x.conf\n",
            ),
        ],
        &[],
    );
    f.file("top/etc/x.conf", "password_file = /run/secrets/k\n");
    let act = std::fs::read_to_string(t.join("activate")).unwrap();
    std::fs::write(
        t.join("activate"),
        format!("{act}cp /run/secrets/k /var/lib/kopie\n"),
    )
    .unwrap();
    (s, t)
}

#[test]
fn the_four_blind_readers_are_named_and_the_run_is_red() {
    let f = Fix::new("a3-blind");
    let (s, t) = blind(&f);
    let top = format!("server={}", t.display());
    let (code, out) = run(&["check", "--store-prefix", &s, &top]);
    assert_eq!(code, 1, "{out}");
    // (1) a path built from a variable: named as unklar, not dropped
    assert!(out.contains("unklar     server:split.service"), "{out}");
    assert!(out.contains("unklar     server:var.service"), "{out}");
    // a secret nobody reads is a finding, not a hint
    assert!(out.contains("ohne-leser server: niemand"), "{out}");
    let (_, show) = run(&["show", "k", "--store-prefix", &s, &top]);
    // (2) a config file in /etc that names the path
    assert!(show.contains("server:etc.service"), "{show}");
    // (3) the activation script
    assert!(show.contains("aktivierung  server:activation"), "{show}");
}

/// The manifest names EVERY secret path. Reached from `activate`, it must
/// not make an unread secret look read by the activation.
#[test]
fn the_manifest_is_no_reader() {
    let f = Fix::new("a3-manifest");
    let (s, t) = blind(&f);
    let (_, show) = run(&[
        "show",
        "niemand",
        "--store-prefix",
        &s,
        &format!("server={}", t.display()),
    ]);
    assert!(!show.contains("activation"), "{show}");
}

/// (4) A reader outside the built systems is declared `extern` and then
/// counts; an `extern` for a secret no host knows is stale.
#[test]
fn an_extern_reader_is_declared_and_checked() {
    let f = Fix::new("a3-extern");
    let (s, t) = blind(&f);
    let d = f.file(
        "d.json",
        r#"[{"secret":"niemand","leser":"workstation:octodns","klasse":"extern","grund":"liest den Wert aus homeserver-secrets","wo":"just dns-apply auf der Workstation"},
            {"secret":"gibt-es-nicht","leser":"workstation:x","klasse":"extern","grund":"g","wo":"w"}]"#,
    );
    let top = format!("server={}", t.display());
    let dp = d.display().to_string();
    let (_, out) = run(&["check", "--declarations", &dp, "--store-prefix", &s, &top]);
    assert!(!out.contains("ohne-leser server: niemand"), "{out}");
    assert!(
        out.contains("tot        Deklaration gibt-es-nicht -> workstation:x"),
        "{out}"
    );
    let (_, show) = run(&[
        "show",
        "niemand",
        "--declarations",
        &dp,
        "--store-prefix",
        &s,
        &top,
    ]);
    assert!(show.contains("extern       workstation:octodns"), "{show}");
    assert!(
        show.contains("ausserhalb: just dns-apply auf der Workstation"),
        "{show}"
    );
}

/// K9 (2026-09-12): qBittorrent's password was rotated and taken by the
/// service, but tofu on the workstation and bindery on the host kept writing
/// the old one — seven hours of banned addresses. Both readers must show up:
/// the host one as uncovered, the workstation one as declared.
#[test]
fn k9_tofu_und_bindery() {
    let f = Fix::new("a3-k9");
    let s = f.store();
    f.file(
        "store/cc-bindery",
        "#!/bin/sh\ncurl -K /run/secrets/qbt-pass http://torrent\n",
    );
    let t = f.host(
        &manifest_json(
            &[(
                "qbt-pass",
                "/run/secrets/qbt-pass",
                &["qbittorrent.service"],
            )],
            &[],
        ),
        &[
            (
                "qbittorrent.service",
                "[Service]\nLoadCredential=p:/run/secrets/qbt-pass\nExecStart=/bin/q\n",
            ),
            (
                "bindery.service",
                &format!("[Service]\nExecStart={s}cc-bindery\n"),
            ),
        ],
        &[],
    );
    let d = f.file(
        "d.json",
        r#"[{"secret":"qbt-pass","leser":"workstation:tofu","klasse":"extern","grund":"K9","wo":"tofu apply"}]"#,
    );
    let (code, out) = run(&[
        "check",
        "--declarations",
        &d.display().to_string(),
        "--store-prefix",
        &s,
        &format!("server={}", t.display()),
    ]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("ungedeckt  qbt-pass  server:bindery.service"),
        "{out}"
    );
    let (_, show) = run(&[
        "show",
        "qbt-pass",
        "--declarations",
        &d.display().to_string(),
        "--store-prefix",
        &s,
        &format!("server={}", t.display()),
    ]);
    assert!(show.contains("extern       workstation:tofu"), "{show}");
    assert!(
        show.contains("neustart     server:qbittorrent.service"),
        "{show}"
    );
}
