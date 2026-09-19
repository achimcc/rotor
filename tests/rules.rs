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
