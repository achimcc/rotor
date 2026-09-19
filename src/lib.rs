//! rotor — who reads a secret on a NixOS host, and does a rotation reach them?
//!
//! It reads a *built* system: the sops-nix manifest, the units of the host
//! and its containers, the files those units run, and the converge specs they
//! hand over. It never opens a secret; it knows names and paths only.

pub mod converge;
pub mod decl;
pub mod graph;
pub mod manifest;
pub mod report;
pub mod scan;

use std::path::PathBuf;

const USAGE: &str = "usage: rotor check [--declarations FILE] [--json] LABEL=TOPLEVEL...\n       rotor show SECRET [--declarations FILE] [--json] LABEL=TOPLEVEL...";

/// The whole program without `std::process::exit`, for the tests.
pub fn run(args: Vec<String>) -> (i32, String) {
    match run_inner(args) {
        Ok(r) => r,
        Err(e) => (2, format!("rotor: {e}\n")),
    }
}

fn run_inner(args: Vec<String>) -> Result<(i32, String), String> {
    use lexopt::prelude::*;
    let mut p = lexopt::Parser::from_args(args);
    let mut cmd: Option<String> = None;
    let mut secret: Option<String> = None;
    let mut decls: Option<PathBuf> = None;
    let mut as_json = false;
    let mut prefix = "/nix/store/".to_string();
    let mut tops: Vec<(String, PathBuf)> = Vec::new();
    while let Some(a) = p.next().map_err(|e| e.to_string())? {
        match a {
            Long("declarations") => decls = Some(p.value().map_err(|e| e.to_string())?.into()),
            Long("json") => as_json = true,
            // Only for the tests: fixtures cannot live in /nix/store.
            Long("store-prefix") => {
                prefix = p
                    .value()
                    .map_err(|e| e.to_string())?
                    .string()
                    .map_err(|e| format!("{e:?}"))?
            }
            Long("help") | Short('h') => return Ok((0, format!("{USAGE}\n"))),
            Value(v) => {
                let v = v.string().map_err(|e| format!("{e:?}"))?;
                if cmd.is_none() {
                    cmd = Some(v);
                } else if cmd.as_deref() == Some("show") && secret.is_none() && !v.contains('=') {
                    secret = Some(v);
                } else if let Some((l, t)) = v.split_once('=') {
                    tops.push((l.to_owned(), PathBuf::from(t)));
                } else {
                    return Err(format!("expected LABEL=TOPLEVEL, got {v}"));
                }
            }
            _ => return Err(a.unexpected().to_string()),
        }
    }
    let cmd = cmd.ok_or(USAGE)?;
    if tops.is_empty() {
        return Err(format!("no LABEL=TOPLEVEL given\n{USAGE}"));
    }
    let mut scanner = scan::Scanner::new(&prefix);
    let mut hosts = Vec::new();
    for (l, t) in &tops {
        hosts.push(graph::analyse(l, t, &mut scanner)?);
    }
    let ds = match &decls {
        Some(p) => decl::load(p)?,
        None => Vec::new(),
    };
    // A declaration is stale only if it matched in NO host: guest readers
    // carry the guest's name as `machine`, so they stay in their host.
    let mut hit = vec![false; ds.len()];
    for h in hosts.iter_mut() {
        let stale_here = decl::apply(&mut h.readers, &ds);
        for (i, d) in ds.iter().enumerate() {
            if !stale_here
                .iter()
                .any(|s| s.secret == d.secret && s.leser == d.leser)
            {
                hit[i] = true;
            }
        }
    }
    let stale: Vec<_> = ds
        .iter()
        .zip(&hit)
        .filter(|(_, h)| !**h)
        .map(|(d, _)| d.clone())
        .collect();
    let o = report::Outcome {
        hosts,
        stale,
        files_read: scanner.files_read,
        binaries_skipped: scanner.binaries_skipped,
    };
    match cmd.as_str() {
        "check" => {
            let text = if as_json {
                report::json(&o, None)
            } else {
                report::text_check(&o)
            };
            Ok((report::exit_code(&o), text))
        }
        "show" => {
            let s = secret.ok_or("show needs a SECRET")?;
            if !o.knows(&s) {
                return Err(format!("no manifest knows a secret named {s}"));
            }
            let text = if as_json {
                report::json(&o, Some(&s))
            } else {
                report::text_show(&o, &s)
            };
            let uncovered = o
                .readers()
                .any(|r| r.secret == s && r.class == graph::Class::Ungedeckt);
            Ok((i32::from(uncovered), text))
        }
        c => Err(format!("unknown command {c}\n{USAGE}")),
    }
}
