//! What a unit runs, read line by line. A unit names store files in its
//! settings; those files name more store files. rotor follows the references
//! to MAX_DEPTH and keeps only the lines that mention `/run/` — the only
//! lines that can name a secret's path. Binaries are skipped: a service that
//! reads a credential in its own code is found through `LoadCredential=`.
//!
//! Always line by line: one pattern over a whole large file is the size trap
//! this tool's host has already fallen into more than once.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::rc::Rc;
use unit_lint::unit::Unit;

/// A unit's own settings are depth 0; the files they name are depth 1.
pub const MAX_DEPTH: usize = 3;
const PEEK: usize = 8192;
const MAX_TEXT: u64 = 16 * 1024 * 1024;

struct FileInfo {
    lines: Vec<String>,
    refs: Vec<String>,
}

pub struct Scanner {
    prefix: String,
    /// Files never followed: the sops-nix manifest names EVERY secret path,
    /// and reached from `activate` it would make every secret look read.
    pub skip: HashSet<String>,
    /// Where `/etc/…` resolves for the system being scanned (`<toplevel>/etc`).
    pub etc_root: Option<std::path::PathBuf>,
    cache: HashMap<String, Option<Rc<FileInfo>>>,
    pub files_read: usize,
    pub binaries_skipped: usize,
}

fn path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "+._?=/-".contains(c)
}

/// Every `<prefix>…` path in a line, cut at the first character a store path
/// cannot hold.
pub fn store_refs(line: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(i) = rest.find(prefix) {
        let tail = &rest[i..];
        let end = tail[prefix.len()..]
            .find(|c: char| !path_char(c))
            .map_or(tail.len(), |e| e + prefix.len());
        let p = tail[..end].trim_end_matches(['.', '/']);
        if p.len() > prefix.len() {
            out.push(p.to_owned());
        }
        rest = &tail[end..];
    }
    out
}

/// `needle` occurs in `line` and is not the start of a longer name or path.
pub fn mentions(line: &str, needle: &str) -> bool {
    line.match_indices(needle).any(|(i, _)| {
        line[i + needle.len()..]
            .chars()
            .next()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || "_.-/".contains(c)))
    })
}

impl Scanner {
    pub fn new(prefix: &str) -> Self {
        Scanner {
            prefix: prefix.to_owned(),
            skip: HashSet::new(),
            etc_root: None,
            cache: HashMap::new(),
            files_read: 0,
            binaries_skipped: 0,
        }
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    fn info(&mut self, path: &str) -> Option<Rc<FileInfo>> {
        if self.skip.contains(path) {
            return None;
        }
        if let Some(c) = self.cache.get(path) {
            return c.clone();
        }
        let info = match fs::metadata(path) {
            Ok(m) if m.is_file() && m.len() <= MAX_TEXT => match fs::read(path) {
                Ok(bytes) if !bytes[..bytes.len().min(PEEK)].contains(&0) => {
                    self.files_read += 1;
                    let text = String::from_utf8_lossy(&bytes);
                    let mut lines = Vec::new();
                    let mut refs = Vec::new();
                    for l in text.lines() {
                        refs.extend(store_refs(l, &self.prefix));
                        refs.extend(self.etc_files(l));
                        if l.contains("/run/") {
                            lines.push(l.to_owned());
                        }
                    }
                    Some(Rc::new(FileInfo { lines, refs }))
                }
                Ok(_) => {
                    self.binaries_skipped += 1;
                    None
                }
                Err(_) => None,
            },
            Ok(m) if m.is_file() => {
                self.binaries_skipped += 1;
                None
            }
            // Directories (a package) and missing paths hold no script.
            _ => None,
        };
        self.cache.insert(path.to_owned(), info.clone());
        info
    }

    /// The unit's own settings as `Key=Value`, and every `/run/` line of the
    /// files it runs, to MAX_DEPTH.
    pub fn lines(&mut self, unit: &Unit) -> Vec<String> {
        self.walk(unit).0
    }

    /// Every store path reached from the unit, to MAX_DEPTH — files and
    /// directories alike, read or not.
    pub fn reachable(&mut self, unit: &Unit) -> Vec<String> {
        self.walk(unit).1
    }

    /// `/etc/<p>` in a line, as the file under `etc_root` (audit 3, CD-7: a
    /// config file in /etc that names a secret path was a reader rotor could
    /// not see). The file there is a link into the store; reading follows it.
    fn etc_files(&self, line: &str) -> Vec<String> {
        let Some(root) = &self.etc_root else {
            return Vec::new();
        };
        store_refs(line, "/etc/")
            .into_iter()
            .map(|p| {
                root.join(&p["/etc/".len()..])
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    /// Every `/run/` line of a FILE and what it runs, to MAX_DEPTH — for the
    /// activation script, which is no unit.
    pub fn file_lines(&mut self, path: &str) -> Vec<String> {
        self.walk_from(Vec::new(), vec![path.to_owned()]).0
    }

    fn walk(&mut self, unit: &Unit) -> (Vec<String>, Vec<String>) {
        let own: Vec<String> = unit
            .entries
            .iter()
            .map(|e| format!("{}={}", e.key, e.value))
            .collect();
        let level: Vec<String> = unit
            .entries
            .iter()
            .flat_map(|e| {
                let mut r = store_refs(&e.value, &self.prefix);
                r.extend(self.etc_files(&e.value));
                r
            })
            .collect();
        self.walk_from(own, level)
    }

    fn walk_from(
        &mut self,
        mut out: Vec<String>,
        mut level: Vec<String>,
    ) -> (Vec<String>, Vec<String>) {
        let mut seen = HashSet::new();
        let mut reached = Vec::new();
        for _ in 0..MAX_DEPTH {
            let mut next = Vec::new();
            for r in level {
                if !seen.insert(r.clone()) {
                    continue;
                }
                reached.push(r.clone());
                if let Some(i) = self.info(&r) {
                    out.extend(i.lines.iter().cloned());
                    next.extend(i.refs.iter().cloned());
                }
            }
            level = next;
        }
        (out, reached)
    }
}
