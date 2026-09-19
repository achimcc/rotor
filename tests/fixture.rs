#![allow(dead_code)]
use std::fs;
use std::path::PathBuf;

pub struct Fix(pub PathBuf);

/// (name, path, restartUnits)
pub type SecretSpec<'a> = (&'a str, &'a str, &'a [&'a str]);
/// (name, path, content, restartUnits)
pub type TemplateSpec<'a> = (&'a str, &'a str, &'a str, &'a [&'a str]);
/// (container, load-credential flags, guest units as (name, text))
pub type ContainerSpec<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)]);

impl Fix {
    pub fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!("rotor-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Fix(p)
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }

    pub fn file(&self, rel: &str, text: &str) -> PathBuf {
        let p = self.0.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, text).unwrap();
        p
    }

    /// A store prefix inside the fixture, standing in for `/nix/store/`.
    pub fn store(&self) -> String {
        format!("{}/store/", self.0.display())
    }

    /// A toplevel `top` with a manifest and the given host units, plus
    /// containers: (name, load-credential flags, guest units).
    pub fn host(
        &self,
        manifest: &str,
        units: &[(&str, &str)],
        containers: &[ContainerSpec],
    ) -> PathBuf {
        let m = self.file("store/mmm-manifest.json", manifest);
        self.file(
            "top/activate",
            &format!("#!/bin/sh\nsops-install-secrets {}\n", m.display()),
        );
        fs::create_dir_all(self.path("top/etc/systemd/system")).unwrap();
        for (n, t) in units {
            self.file(&format!("top/etc/systemd/system/{n}"), t);
        }
        for (c, flags, gunits) in containers {
            let gt = self.path(&format!("guest-{c}"));
            fs::create_dir_all(gt.join("etc/systemd/system")).unwrap();
            for (n, t) in gunits.iter() {
                self.file(&format!("guest-{c}/etc/systemd/system/{n}"), t);
            }
            self.file(
                &format!("top/etc/nixos-containers/{c}.conf"),
                &format!(
                    "SYSTEM_PATH={}\nEXTRA_NSPAWN_FLAGS=\"{flags}\"\n",
                    gt.display()
                ),
            );
        }
        self.path("top")
    }
}

/// `secrets`: (name, path, restartUnits); `templates`: (name, path, content, restartUnits).
pub fn manifest_json(secrets: &[SecretSpec], templates: &[TemplateSpec]) -> String {
    let s: Vec<_> = secrets
        .iter()
        .map(|(n, p, r)| {
            serde_json::json!({"name": n, "path": p, "restartUnits": r, "reloadUnits": []})
        })
        .collect();
    let t: Vec<_> = templates
        .iter()
        .map(|(n, p, c, r)| {
            serde_json::json!({"name": n, "path": p, "content": c, "restartUnits": r, "reloadUnits": []})
        })
        .collect();
    let ph: serde_json::Map<_, _> = secrets
        .iter()
        .map(|(n, _, _)| (n.to_string(), serde_json::json!(ph(n))))
        .collect();
    serde_json::json!({"secrets": s, "templates": t, "placeholderBySecretName": ph}).to_string()
}

pub fn ph(name: &str) -> String {
    format!("<SOPS:{name}:PLACEHOLDER>")
}
