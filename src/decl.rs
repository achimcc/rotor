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
            "einmalig" | "gegenstelle" => {}
            k => {
                return Err(format!(
                    "{at}: klasse {k} cannot be declared (only einmalig, gegenstelle)"
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
    for d in decls {
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
