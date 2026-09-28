//! What cannot be recognised has to be declared: a service that takes a value
//! into its database on first start (`einmalig`), or a value whose other half
//! lives elsewhere (`gegenstelle`). A declaration that matches no reader is a
//! finding too — a list that goes stale silently is worse than none.

use crate::graph::{Class, Reader};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decl {
    pub secret: String,
    /// `<machine>:<unit>`, the machine being a host label or a container.
    pub leser: String,
    pub klasse: String,
    pub grund: String,
    pub handgriff: Option<String>,
    pub gegenseite: Option<String>,
    /// `extern`: where the reader lives (a workstation tool, a service
    /// outside both hosts). It cannot be found, only declared.
    pub wo: Option<String>,
}

fn filled(o: &Option<String>) -> bool {
    o.as_deref().is_some_and(|s| !s.trim().is_empty())
}

pub fn load(path: &Path) -> Result<Vec<Decl>, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let ds: Vec<Decl> =
        serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
    for d in &ds {
        let at = format!("{}: declaration {} / {}", path.display(), d.secret, d.leser);
        if !d.leser.contains(':') {
            return Err(format!("{at}: leser must be <machine>:<unit>"));
        }
        if d.grund.trim().is_empty() {
            return Err(format!("{at}: grund is empty"));
        }
        match d.klasse.as_str() {
            "einmalig" if !filled(&d.handgriff) => {
                return Err(format!("{at}: einmalig needs handgriff"));
            }
            "gegenstelle" if !filled(&d.gegenseite) => {
                return Err(format!("{at}: gegenstelle needs gegenseite"));
            }
            "extern" if !filled(&d.wo) => {
                return Err(format!("{at}: extern needs wo"));
            }
            "einmalig" | "gegenstelle" | "extern" => {}
            k => {
                return Err(format!(
                    "{at}: klasse {k} cannot be declared (only einmalig, gegenstelle, extern)"
                ));
            }
        }
    }
    Ok(ds)
}

/// Sets the class of every reader a declaration names; returns the
/// declarations that named none.
pub fn apply(readers: &mut [Reader], decls: &[Decl]) -> Vec<Decl> {
    let mut stale = Vec::new();
    for d in decls.iter().filter(|d| d.klasse != "extern") {
        let mut hit = false;
        for r in readers
            .iter_mut()
            .filter(|r| r.secret == d.secret && format!("{}:{}", r.machine, r.unit) == d.leser)
        {
            hit = true;
            r.class = if d.klasse == "einmalig" {
                Class::Einmalig {
                    handgriff: d.handgriff.clone().unwrap_or_default(),
                }
            } else {
                Class::Gegenstelle {
                    gegenseite: d.gegenseite.clone().unwrap_or_default(),
                }
            };
        }
        if !hit {
            stale.push(d.clone());
        }
    }
    stale
}

/// Readers outside the built systems (audit 3, CD-7: K9 — tofu on the
/// workstation kept writing the old qBittorrent password for seven hours).
/// They cannot be found, so each `extern` declaration IS the reader. It is
/// stale when no host knows the secret.
pub fn externals(decls: &[Decl]) -> Vec<Reader> {
    decls
        .iter()
        .filter(|d| d.klasse == "extern")
        .map(|d| {
            let (machine, unit) = d.leser.split_once(':').unwrap_or(("extern", &d.leser));
            Reader {
                secret: d.secret.clone(),
                machine: machine.to_owned(),
                unit: unit.to_owned(),
                via: "deklariert".into(),
                class: Class::Extern {
                    wo: d.wo.clone().unwrap_or_default(),
                },
            }
        })
        .collect()
}
