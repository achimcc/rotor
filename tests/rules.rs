//! Every rule has to be able to fire. Each test builds a small built system
//! with a broken reader and a healthy twin, and expects exactly the broken one.

mod fixture;
use fixture::*;
use rotor::manifest;

#[test]
fn manifest_is_found_through_activate_and_merged() {
    let f = Fix::new("manifest");
    let m1 = f.file(
        "store/aaa-manifest.json",
        &manifest_json(&[("a", "/run/secrets/a", &[])], &[]),
    );
    let m2 = f.file(
        "store/bbb-manifest-for-users.json",
        &manifest_json(&[("b", "/run/secrets/b", &[])], &[]),
    );
    f.file(
        "top/activate",
        &format!(
            "#!/bin/sh\nsops-install-secrets {} \nx {}\n",
            m1.display(),
            m2.display()
        ),
    );
    let m = manifest::load_for(&f.path("top")).unwrap();
    let names: Vec<_> = m.secrets.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["a", "b"]);
    assert!(m.placeholders.contains_key("b"));
}

#[test]
fn a_toplevel_without_manifest_is_an_error() {
    let f = Fix::new("nomanifest");
    f.file("top/activate", "#!/bin/sh\ntrue\n");
    let e = manifest::load_for(&f.path("top")).unwrap_err();
    assert!(e.contains("no sops-nix manifest"), "{e}");
}

use rotor::scan;
use unit_lint::unit;

fn unit_with(f: &Fix, name: &str, text: &str) -> unit::Unit {
    f.file(&format!("sys/{name}"), text);
    let sys = unit::load("t", &f.path("sys"), false).unwrap();
    sys.units.into_values().find(|u| u.name == name).unwrap()
}

#[test]
fn a_path_three_levels_deep_is_found_four_levels_deep_is_not() {
    let f = Fix::new("depth");
    let s = f.store();
    f.file("store/d4-x", "cat /run/secrets/deep4\n");
    f.file("store/d3-x", &format!("{s}d4-x\ncat /run/secrets/deep3\n"));
    f.file("store/d2-x", &format!("exec {s}d3-x\n"));
    f.file(
        "store/d1-x",
        &format!("#!/bin/sh\n. {s}d2-x\ncat /run/secrets/shallow\n"),
    );
    let u = unit_with(&f, "a.service", &format!("[Service]\nExecStart={s}d1-x\n"));
    let mut sc = scan::Scanner::new(&s);
    let lines = sc.lines(&u).join("\n");
    assert!(lines.contains("/run/secrets/shallow"));
    assert!(lines.contains("/run/secrets/deep3"));
    assert!(
        !lines.contains("/run/secrets/deep4"),
        "depth 4 is past the limit on purpose"
    );
}

#[test]
fn binaries_are_skipped_and_counted() {
    let f = Fix::new("binary");
    let s = f.store();
    let p = f.path("store/bin-x");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, b"\x7fELF\0\0/run/secrets/x").unwrap();
    let u = unit_with(&f, "b.service", &format!("[Service]\nExecStart={s}bin-x\n"));
    let mut sc = scan::Scanner::new(&s);
    let lines = sc.lines(&u).join("\n");
    assert!(!lines.contains("/run/secrets/x"));
    assert_eq!(sc.binaries_skipped, 1);
}

#[test]
fn mentions_needs_a_boundary() {
    assert!(scan::mentions("cat /run/secrets/foo;", "/run/secrets/foo"));
    assert!(!scan::mentions(
        "cat /run/secrets/foo-bar",
        "/run/secrets/foo"
    ));
    assert!(!scan::mentions(
        "cat /run/secrets/foo/x",
        "/run/secrets/foo"
    ));
    assert!(scan::mentions("x=/run/secrets/foo", "/run/secrets/foo"));
}

use rotor::converge;

#[test]
fn converge_names_its_handed_over_credentials() {
    let f = Fix::new("converge");
    let s = f.store();
    f.file(
        "store/h1-converge-download-clients-radarr.json",
        r#"{"api_key_credential":"radarr-api-key","task":"download-clients",
      "desired":{"providers":{"qBittorrent":{"secret_fields":{"password":"qbittorrent-webui-password"}}}}}"#,
    );
    f.file(
        "store/h2-converge-plugins-jellyfin.json",
        r#"{"desired":{"x":{"secrets":{"OmdbApiKey":"jellyfin-omdb-key"}}}}"#,
    );
    let u = unit_with(
        &f,
        "arr-anbieter.service",
        &format!(
            "[Service]\nExecStart={s}c-converge-0.24.0/bin/converge apply {s}h1-converge-download-clients-radarr.json {s}h2-converge-plugins-jellyfin.json\n"
        ),
    );
    let got = converge::handed_over(&u, &s).unwrap();
    let v: Vec<_> = got.iter().map(String::as_str).collect();
    assert_eq!(
        v,
        ["jellyfin-omdb-key", "qbittorrent-webui-password"],
        "api_key_credential is converge's own login, not a hand-over"
    );
}

#[test]
fn a_broken_spec_is_an_error_naming_the_path() {
    let f = Fix::new("converge-broken");
    let s = f.store();
    f.file("store/h3-converge-x-y.json", "{");
    let u = unit_with(
        &f,
        "c.service",
        &format!("[Service]\nExecStart=/bin/converge apply {s}h3-converge-x-y.json\n"),
    );
    let e = converge::handed_over(&u, &s).unwrap_err();
    assert!(e.contains("h3-converge-x-y.json"), "{e}");
}

use rotor::graph::{self, Class};

fn class_of(h: &graph::Host, machine: &str, unit: &str) -> &'static str {
    h.readers
        .iter()
        .find(|r| r.machine == machine && r.unit == unit)
        .map(|r| r.class.name())
        .unwrap_or("absent")
}

#[test]
fn a_template_without_restart_on_its_container_is_uncovered() {
    let f = Fix::new("tpl-restart");
    let t = f.host(
        &manifest_json(
            &[("k", "/run/secrets/k", &[])],
            &[
                (
                    "gut",
                    "/run/secrets/rendered/gut",
                    &ph("k"),
                    &["container@g1.service"],
                ),
                ("schlecht", "/run/secrets/rendered/schlecht", &ph("k"), &[]),
            ],
        ),
        &[],
        &[
            (
                "g1",
                "--load-credential=gut:/run/secrets/rendered/gut",
                &[(
                    "a.service",
                    "[Service]\nLoadCredential=gut\nExecStart=/bin/a\n",
                )],
            ),
            (
                "g2",
                "--load-credential=schlecht:/run/secrets/rendered/schlecht",
                &[(
                    "b.service",
                    "[Service]\nLoadCredential=schlecht\nExecStart=/bin/b\n",
                )],
            ),
        ],
    );
    let h = graph::analyse("server", &t, &mut scan::Scanner::new(&f.store())).unwrap();
    assert_eq!(class_of(&h, "server", "container@g1.service"), "neustart");
    assert_eq!(class_of(&h, "g1", "a.service"), "neustart");
    assert_eq!(class_of(&h, "server", "container@g2.service"), "ungedeckt");
    assert_eq!(class_of(&h, "g2", "b.service"), "ungedeckt");
}

#[test]
fn restart_on_another_unit_does_not_cover_the_reader() {
    let f = Fix::new("other-unit");
    let t = f.host(
        &manifest_json(&[("k", "/run/secrets/k", &["nginx.service"])], &[]),
        &[
            (
                "nginx.service",
                "[Service]\nLoadCredential=k:/run/secrets/k\nExecStart=/bin/nginx\n",
            ),
            (
                "dritter.service",
                "[Service]\nEnvironmentFile=/run/secrets/k\nExecStart=/bin/x\n",
            ),
        ],
        &[],
    );
    let h = graph::analyse("vps", &t, &mut scan::Scanner::new(&f.store())).unwrap();
    assert_eq!(class_of(&h, "vps", "nginx.service"), "neustart");
    assert_eq!(class_of(&h, "vps", "dritter.service"), "ungedeckt");
}

#[test]
fn a_reader_in_a_guest_script_two_levels_deep_is_found() {
    let f = Fix::new("script-reader");
    let s = f.store();
    f.file("store/s2-inner", "cat /run/host/credentials/tok\n");
    f.file("store/s1-outer", &format!("exec {s}s2-inner\n"));
    let t = f.host(
        &manifest_json(
            &[("tok", "/run/secrets/tok", &["container@g.service"])],
            &[],
        ),
        &[],
        &[(
            "g",
            "--load-credential=tok:/run/secrets/tok",
            &[(
                "leser.service",
                &format!("[Service]\nExecStart={s}s1-outer\n"),
            )],
        )],
    );
    let h = graph::analyse("server", &t, &mut scan::Scanner::new(&s)).unwrap();
    assert_eq!(class_of(&h, "g", "leser.service"), "neustart");
}

#[test]
fn a_guest_unit_that_does_not_read_the_credential_is_no_reader() {
    let f = Fix::new("non-reader");
    let t = f.host(
        &manifest_json(
            &[("tok", "/run/secrets/tok", &["container@g.service"])],
            &[],
        ),
        &[],
        &[(
            "g",
            "--load-credential=tok:/run/secrets/tok",
            &[
                (
                    "leser.service",
                    "[Service]\nLoadCredential=lokal:tok\nExecStart=/bin/a\n",
                ),
                (
                    "fremd.service",
                    "[Service]\nLoadCredential=tokx\nExecStart=/bin/b\n",
                ),
            ],
        )],
    );
    let h = graph::analyse("server", &t, &mut scan::Scanner::new(&f.store())).unwrap();
    assert_eq!(class_of(&h, "g", "leser.service"), "neustart");
    assert_eq!(class_of(&h, "g", "fremd.service"), "absent");
}

#[test]
fn converge_with_a_timer_hands_over_without_a_timer_it_inherits() {
    let f = Fix::new("converge-timer");
    let s = f.store();
    f.file(
        "store/h-converge-dc-radarr.json",
        r#"{"desired":{"p":{"secret_fields":{"password":"qb"}}}}"#,
    );
    let unit = format!(
        "[Service]\nLoadCredential=qb\nExecStart={s}c-converge/bin/converge apply {s}h-converge-dc-radarr.json\n"
    );
    let t = f.host(
        &manifest_json(&[("qb", "/run/secrets/qb", &[])], &[]),
        &[],
        &[
            (
                "mit",
                "--load-credential=qb:/run/secrets/qb",
                &[
                    ("anb.service", &unit),
                    ("anb.timer", "[Timer]\nOnUnitActiveSec=1d\n"),
                ],
            ),
            (
                "ohne",
                "--load-credential=qb:/run/secrets/qb",
                &[("anb.service", &unit)],
            ),
        ],
    );
    let h = graph::analyse("server", &t, &mut scan::Scanner::new(&s)).unwrap();
    assert_eq!(class_of(&h, "mit", "anb.service"), "uebergabe");
    assert_eq!(
        class_of(&h, "ohne", "anb.service"),
        "ungedeckt",
        "no timer: the container's class, and it has no restart"
    );
    let r = h
        .readers
        .iter()
        .find(|r| r.machine == "mit" && r.unit == "anb.service")
        .unwrap();
    assert!(matches!(&r.class, Class::Uebergabe { takt } if takt == "OnUnitActiveSec=1d"));
}
