//! converge hands credentials over into a service's database on every apply
//! (converge design §12). A unit that runs converge with a spec naming a
//! credential in `secret_fields` or `secrets` is therefore a hand-over, not
//! only a reader. `*_credential` keys are converge's own login to the
//! service; that credential is read, not handed over.

use crate::scan::store_refs;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use unit_lint::unit::Unit;

fn is_spec(path: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or("");
    let after_hash = file.split_once('-').map(|(_, r)| r).unwrap_or("");
    after_hash.starts_with("converge-") && file.ends_with(".json")
}

fn collect(v: &Value, under_secret: bool, out: &mut BTreeSet<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                collect(
                    x,
                    under_secret || k == "secret_fields" || k == "secrets",
                    out,
                );
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect(x, under_secret, out)),
        Value::String(s) if under_secret => {
            out.insert(s.clone());
        }
        _ => {}
    }
}

/// The credential names the converge specs of `unit` hand over.
pub fn handed_over(unit: &Unit, prefix: &str) -> Result<BTreeSet<String>, String> {
    let mut out = BTreeSet::new();
    for e in unit
        .entries
        .iter()
        .filter(|e| e.section == "Service" && e.key.starts_with("Exec"))
    {
        for p in store_refs(&e.value, prefix)
            .into_iter()
            .filter(|p| is_spec(p))
        {
            let raw = fs::read_to_string(&p).map_err(|er| format!("{p}: {er}"))?;
            let v: Value = serde_json::from_str(&raw)
                .map_err(|er| format!("{p}: not a converge spec: {er}"))?;
            collect(&v, false, &mut out);
        }
    }
    Ok(out)
}
