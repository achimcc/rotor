//! From secret to reader. A secret reaches a unit on the host through its
//! own path or a template's; it reaches a guest through `--load-credential`
//! on the container. Each reader gets a class: does a rotation reach it?

use crate::converge::handed_over;
use crate::manifest;
use crate::scan::{Scanner, mentions};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use unit_lint::unit::{System, Unit, load_toplevel};

#[derive(Debug, Clone, PartialEq)]
pub enum Class {
    /// `restartUnits` names this unit (or its container): a deploy restarts it.
    Neustart,
    /// converge hands the value over on a timer.
    Uebergabe { takt: String },
    /// A oneshot on the host that reads the secret afresh at every run.
    Lauf { takt: String },
    /// Declared: the service took the value once; a hand is needed.
    Einmalig { handgriff: String },
    /// Declared: the value's other half lives elsewhere.
    Gegenstelle { gegenseite: String },
    /// Found, and none of the above: a rotation does not reach it.
    Ungedeckt,
}

impl Class {
    pub fn name(&self) -> &'static str {
        match self {
            Class::Neustart => "neustart",
            Class::Uebergabe { .. } => "uebergabe",
            Class::Lauf { .. } => "lauf",
            Class::Einmalig { .. } => "einmalig",
            Class::Gegenstelle { .. } => "gegenstelle",
            Class::Ungedeckt => "ungedeckt",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Reader {
    pub secret: String,
    /// The host label, or the container's name for a unit inside it.
    pub machine: String,
    pub unit: String,
    pub via: String,
    pub class: Class,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub secrets: usize,
    pub templates: usize,
    pub units: usize,
    pub containers: usize,
}

#[derive(Debug)]
pub struct Host {
    pub label: String,
    pub stats: Stats,
    pub readers: Vec<Reader>,
    pub secrets: Vec<String>,
}

struct Source {
    secret: String,
    path: String,
    restart: BTreeSet<String>,
    via: String,
}

fn sources(m: &manifest::Manifest) -> Vec<Source> {
    let mut out = Vec::new();
    for s in &m.secrets {
        out.push(Source {
            secret: s.name.clone(),
            path: s.path.clone(),
            restart: s.restart_units.iter().cloned().collect(),
            via: "secret".into(),
        });
    }
    for t in &m.templates {
        for (name, ph) in &m.placeholders {
            if t.content.contains(ph.as_str()) {
                out.push(Source {
                    secret: name.clone(),
                    path: t.path.clone(),
                    restart: t.restart_units.iter().cloned().collect(),
                    via: format!("template {}", t.name),
                });
            }
        }
    }
    out
}

fn class_for(restart: &BTreeSet<String>, unit: &str) -> Class {
    if restart.contains(unit) {
        Class::Neustart
    } else {
        Class::Ungedeckt
    }
}

/// `--load-credential=<id>:<path>` pairs of one container.
fn container_credentials(conf: &str) -> Vec<(String, String)> {
    conf.split(|c: char| c.is_whitespace() || c == '"')
        .filter_map(|t| t.strip_prefix("--load-credential="))
        .filter_map(|t| t.split_once(':'))
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
        .collect()
}

/// The local name under which `unit` reads credential `id` of its container,
/// if it reads it at all.
fn local_name(unit: &Unit, lines: &[String], id: &str) -> Option<String> {
    let host_path = format!("/run/host/credentials/{id}");
    for v in unit.list("Service", "LoadCredential") {
        match v.split_once(':') {
            None if v == id => return Some(id.to_owned()),
            Some((l, src)) if src == id || src == host_path => return Some(l.to_owned()),
            _ => {}
        }
    }
    lines
        .iter()
        .any(|l| mentions(l, &host_path))
        .then(|| id.to_owned())
}

/// The schedule of the timer that starts `unit`, if one does.
fn timer_for(sys: &System, unit: &str) -> Option<String> {
    let stem = unit.strip_suffix(".service")?;
    let own = format!("{stem}.timer");
    let t = sys.units.values().find(|t| {
        t.kind() == "timer" && (t.name == own || t.last("Timer", "Unit") == Some(unit))
    })?;
    let keys = ["OnCalendar", "OnUnitActiveSec", "OnActiveSec", "OnBootSec"];
    let parts: Vec<String> = keys
        .iter()
        .flat_map(|k| {
            t.list("Timer", k)
                .into_iter()
                .map(move |v| format!("{k}={v}"))
        })
        .collect();
    Some(parts.join(", "))
}

/// A oneshot without `RemainAfterExit` that a timer starts, or a template
/// started per instance, runs anew — and reads `/run/secrets` anew — every
/// time. Only on the host: a guest reads its container's frozen copy.
fn runs_afresh(sys: &System, u: &Unit) -> Option<String> {
    let oneshot = u.last("Service", "Type") == Some("oneshot");
    let remains = u
        .last("Service", "RemainAfterExit")
        .and_then(unit_lint::unit::parse_bool)
        .unwrap_or(false);
    if !oneshot || remains {
        return None;
    }
    if u.name.contains("@.") {
        return Some("bei jedem Start der Vorlage".into());
    }
    timer_for(sys, &u.name)
}

pub fn analyse(label: &str, top: &Path, scanner: &mut Scanner) -> Result<Host, String> {
    let m = manifest::load_for(top)?;
    let systems = load_toplevel(label, top).map_err(|e| format!("{}: {e}", top.display()))?;
    let srcs = sources(&m);
    let prefix = scanner.prefix().to_owned();
    let mut readers = Vec::new();
    let mut stats = Stats {
        secrets: m.secrets.len(),
        templates: m.templates.len(),
        ..Stats::default()
    };

    let host = &systems[0];
    stats.units += host.units.len();
    for u in host.units.values() {
        let lines = scanner.lines(u);
        for s in &srcs {
            if lines.iter().any(|l| mentions(l, &s.path)) {
                readers.push(Reader {
                    secret: s.secret.clone(),
                    machine: label.to_owned(),
                    unit: u.name.clone(),
                    via: s.via.clone(),
                    class: match class_for(&s.restart, &u.name) {
                        Class::Ungedeckt => runs_afresh(host, u)
                            .map_or(Class::Ungedeckt, |takt| Class::Lauf { takt }),
                        c => c,
                    },
                });
            }
        }
    }

    for guest in systems.iter().skip(1) {
        stats.containers += 1;
        stats.units += guest.units.len();
        let conf_path = top.join(format!("etc/nixos-containers/{}.conf", guest.name));
        let conf =
            fs::read_to_string(&conf_path).map_err(|e| format!("{}: {e}", conf_path.display()))?;
        let container_unit = format!("container@{}.service", guest.name);
        let guest_lines: Vec<(&Unit, Vec<String>)> = guest
            .units
            .values()
            .map(|u| (u, scanner.lines(u)))
            .collect();
        for (id, path) in container_credentials(&conf) {
            for s in srcs.iter().filter(|s| s.path == path) {
                let cclass = class_for(&s.restart, &container_unit);
                let via = format!("{} -> credential {id}", s.via);
                readers.push(Reader {
                    secret: s.secret.clone(),
                    machine: label.to_owned(),
                    unit: container_unit.clone(),
                    via: via.clone(),
                    class: cclass.clone(),
                });
                for (u, lines) in &guest_lines {
                    let Some(local) = local_name(u, lines, &id) else {
                        continue;
                    };
                    let mut class = cclass.clone();
                    // Only a restarted container brings the new value in; a
                    // hand-over from its frozen copy hands over the old one.
                    if cclass == Class::Neustart
                        && handed_over(u, &prefix)?.contains(&local)
                        && let Some(takt) = timer_for(guest, &u.name)
                    {
                        class = Class::Uebergabe { takt };
                    }
                    readers.push(Reader {
                        secret: s.secret.clone(),
                        machine: guest.name.clone(),
                        unit: u.name.clone(),
                        via: format!("{via} -> container {}", guest.name),
                        class,
                    });
                }
            }
        }
    }
    let secrets = m.secrets.iter().map(|s| s.name.clone()).collect();
    Ok(Host {
        label: label.to_owned(),
        stats,
        readers,
        secrets,
    })
}
