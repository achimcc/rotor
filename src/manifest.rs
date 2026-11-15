//! The sops-nix manifest: which secrets and templates a toplevel installs,
//! where, and which units a changed value restarts. It holds no values —
//! template `content` carries placeholders only — and rotor prints none of it.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Secret {
    pub name: String,
    pub path: String,
    #[serde(default, rename = "restartUnits")]
    pub restart_units: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Template {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub content: String,
    #[serde(default, rename = "restartUnits")]
    pub restart_units: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub secrets: Vec<Secret>,
    #[serde(default)]
    pub templates: Vec<Template>,
    #[serde(default, rename = "placeholderBySecretName")]
    pub placeholders: BTreeMap<String, String>,
}

/// Every token in `activate` that names a `…-manifest*.json` file.
pub fn manifest_paths(activate: &str) -> Vec<String> {
    let mut out: Vec<String> = activate
        .split(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .filter(|t| t.starts_with('/') && t.ends_with(".json"))
        .filter(|t| t.rsplit('/').next().unwrap_or("").contains("-manifest"))
        .map(str::to_owned)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The units sops-nix installs secrets with when `sops.useSystemdActivation`
/// is set (or sysusers/userborn are on). Their manifest then no longer
/// appears in `activate`, only in the unit's `ExecStart`.
pub const INSTALL_UNITS: [&str; 2] = [
    "sops-install-secrets.service",
    "sops-install-secrets-for-users.service",
];

/// Everything that can name a manifest: `activate` and the install units, if
/// the toplevel has them.
pub fn manifest_sources(top: &Path) -> Result<String, String> {
    let act = top.join("activate");
    let mut text = fs::read_to_string(&act).map_err(|e| format!("{}: {e}", act.display()))?;
    for u in INSTALL_UNITS {
        let p = top.join("etc/systemd/system").join(u);
        if let Ok(t) = fs::read_to_string(&p) {
            text.push('\n');
            text.push_str(&t);
        }
    }
    Ok(text)
}

/// The merged manifests a toplevel names, in `activate` or in an install
/// unit. A toplevel without one is an error, not "no secrets": a missing
/// manifest must not read as green.
pub fn load_for(top: &Path) -> Result<Manifest, String> {
    let text = manifest_sources(top)?;
    let paths = manifest_paths(&text);
    if paths.is_empty() {
        return Err(format!(
            "{}: no sops-nix manifest named in activate or in {}",
            top.display(),
            INSTALL_UNITS.join(", ")
        ));
    }
    let mut all = Manifest::default();
    for p in paths {
        let raw = fs::read_to_string(&p).map_err(|e| format!("{p}: {e}"))?;
        // serde_json names line and column, never the content.
        let m: Manifest =
            serde_json::from_str(&raw).map_err(|e| format!("{p}: not a sops-nix manifest: {e}"))?;
        all.secrets.extend(m.secrets);
        all.templates.extend(m.templates);
        all.placeholders.extend(m.placeholders);
    }
    Ok(all)
}
