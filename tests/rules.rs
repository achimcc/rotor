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
