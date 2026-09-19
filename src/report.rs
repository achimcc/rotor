//! Names and paths only. No line of a file and no template content is ever
//! printed — rotor reads them to find readers, never to show them.

use crate::decl::Decl;
use crate::graph::{Class, Host, Reader};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

pub struct Outcome {
    pub hosts: Vec<Host>,
    pub stale: Vec<Decl>,
    pub files_read: usize,
    pub binaries_skipped: usize,
}

impl Outcome {
    pub fn readers(&self) -> impl Iterator<Item = &Reader> {
        self.hosts.iter().flat_map(|h| h.readers.iter())
    }

    fn secret_count(&self) -> usize {
        self.hosts.iter().map(|h| h.stats.secrets).sum()
    }

    pub fn knows(&self, secret: &str) -> bool {
        self.hosts
            .iter()
            .any(|h| h.secrets.iter().any(|s| s == secret))
    }
}

/// 2 when the search found nothing although there are secrets — a scan that
/// sees nothing is a broken scan, not a clean host. 1 for a finding.
pub fn exit_code(o: &Outcome) -> i32 {
    if o.secret_count() > 0 && o.readers().next().is_none() {
        return 2;
    }
    if o.readers().any(|r| r.class == Class::Ungedeckt) || !o.stale.is_empty() {
        1
    } else {
        0
    }
}

fn todo(c: &Class) -> String {
    match c {
        Class::Neustart => "Deploy genuegt (restartUnits)".into(),
        Class::Uebergabe { takt } => format!("converge-Lauf abwarten ({takt})"),
        Class::Einmalig { handgriff } => format!("Handgriff: {handgriff}"),
        Class::Gegenstelle { gegenseite } => format!("Gegenseite: {gegenseite}"),
        Class::Ungedeckt => "kommt NICHT an".into(),
    }
}

fn head(o: &Outcome, out: &mut String) {
    for h in &o.hosts {
        let s = &h.stats;
        let _ = writeln!(
            out,
            "{}: {} secrets, {} templates, {} units, {} containers",
            h.label, s.secrets, s.templates, s.units, s.containers
        );
    }
    let _ = writeln!(
        out,
        "files read: {}, binaries skipped: {}",
        o.files_read, o.binaries_skipped
    );
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for r in o.readers() {
        *counts.entry(r.class.name()).or_default() += 1;
    }
    let parts: Vec<String> = counts.iter().map(|(k, v)| format!("{k} {v}")).collect();
    let _ = writeln!(
        out,
        "readers: {} ({})",
        o.readers().count(),
        parts.join(", ")
    );
}

pub fn text_check(o: &Outcome) -> String {
    let mut out = String::new();
    head(o, &mut out);
    for r in o.readers().filter(|r| r.class == Class::Ungedeckt) {
        let _ = writeln!(
            out,
            "ungedeckt  {}  {}:{}  via {}",
            r.secret, r.machine, r.unit, r.via
        );
    }
    for d in &o.stale {
        let _ = writeln!(
            out,
            "tot        Deklaration {} -> {}: kein solcher Leser",
            d.secret, d.leser
        );
    }
    let read: BTreeSet<&str> = o.readers().map(|r| r.secret.as_str()).collect();
    for h in &o.hosts {
        for s in h.secrets.iter().filter(|s| !read.contains(s.as_str())) {
            let _ = writeln!(
                out,
                "hinweis    {}: {s} hat keinen gefundenen Leser",
                h.label
            );
        }
    }
    out
}

pub fn text_show(o: &Outcome, secret: &str) -> String {
    let mut out = String::new();
    head(o, &mut out);
    for r in o.readers().filter(|r| r.secret == secret) {
        let _ = writeln!(
            out,
            "{:<12} {}:{}  via {}  -> {}",
            r.class.name(),
            r.machine,
            r.unit,
            r.via,
            todo(&r.class)
        );
    }
    out
}

pub fn json(o: &Outcome, secret: Option<&str>) -> String {
    let readers: Vec<_> = o
        .readers()
        .filter(|r| secret.is_none_or(|s| r.secret == s))
        .map(|r| {
            json!({"secret": r.secret, "machine": r.machine, "unit": r.unit,
                   "via": r.via, "class": r.class.name(), "todo": todo(&r.class)})
        })
        .collect();
    let stale: Vec<_> = o
        .stale
        .iter()
        .map(|d| json!({"secret": d.secret, "leser": d.leser}))
        .collect();
    let hosts: Vec<_> = o
        .hosts
        .iter()
        .map(|h| {
            json!({"label": h.label, "secrets": h.stats.secrets, "templates": h.stats.templates,
                   "units": h.stats.units, "containers": h.stats.containers})
        })
        .collect();
    json!({"hosts": hosts, "files_read": o.files_read, "binaries_skipped": o.binaries_skipped,
           "readers": readers, "stale": stale})
    .to_string()
}
