// SPDX-License-Identifier: GPL-3.0-or-later
//! Render flattened records and evaluation trees.

use serde::Serialize;

use crate::config::Config;
use crate::eval::{Live, Node, Problem};
use crate::flatten::Plan;

/// Longest DNS character-string (RFC 1035 §3.3).
const MAX_STRING: usize = 255;

/// Split a TXT value into character-strings of at most 255 bytes, breaking
/// before a space so the receiver's concatenation restores it exactly.
pub fn split_strings(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for (i, token) in value.split(' ').enumerate() {
        let piece = if i == 0 {
            token.to_string()
        } else {
            format!(" {token}")
        };
        if !cur.is_empty() && cur.len() + piece.len() > MAX_STRING {
            out.push(std::mem::take(&mut cur));
        }
        cur.push_str(&piece);
        // A single token over the limit (only possible with long macros) is cut anywhere.
        while cur.len() > MAX_STRING {
            let rest = cur.split_off(MAX_STRING);
            out.push(std::mem::replace(&mut cur, rest));
        }
    }
    out.push(cur);
    out
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// BIND zone-file lines.
pub fn zone(cfg: &Config, plan: &Plan) -> String {
    let width = plan
        .records
        .iter()
        .map(|r| r.name.len() + 1)
        .max()
        .unwrap_or(0);
    let mut out = format!(
        "; SPF for {} flattened by spf-flatten {}: {} prefixes, {} of {} lookups\n",
        cfg.domain,
        env!("CARGO_PKG_VERSION"),
        plan.prefixes,
        plan.lookups,
        cfg.max_lookups
    );
    for r in &plan.records {
        let strings: Vec<String> = split_strings(&r.value).iter().map(|s| quote(s)).collect();
        out.push_str(&format!(
            "{:<width$} {} IN TXT {}\n",
            format!("{}.", r.name),
            cfg.ttl,
            strings.join(" ")
        ));
    }
    out
}

/// One `name<TAB>value` line per record.
pub fn plain(plan: &Plan) -> String {
    plan.records
        .iter()
        .map(|r| format!("{}\t{}\n", r.name, r.value))
        .collect()
}

#[derive(Serialize)]
struct JsonRecord<'a> {
    name: &'a str,
    ttl: u32,
    value: &'a str,
    strings: Vec<String>,
    bytes: usize,
}

#[derive(Serialize)]
struct JsonPlan<'a> {
    domain: &'a str,
    policy: String,
    lookups: usize,
    max_lookups: usize,
    prefixes: usize,
    records: Vec<JsonRecord<'a>>,
    kept: &'a [Live],
    warnings: Vec<String>,
}

pub fn json(cfg: &Config, plan: &Plan, warnings: &[Problem]) -> String {
    let doc = JsonPlan {
        domain: &cfg.domain,
        policy: cfg.policy_term(),
        lookups: plan.lookups,
        max_lookups: cfg.max_lookups,
        prefixes: plan.prefixes,
        records: plan
            .records
            .iter()
            .map(|r| JsonRecord {
                name: &r.name,
                ttl: cfg.ttl,
                value: &r.value,
                strings: split_strings(&r.value),
                bytes: r.value.len(),
            })
            .collect(),
        kept: &plan.live,
        warnings: cfg
            .warnings
            .iter()
            .cloned()
            .chain(warnings.iter().map(|p| p.to_string()))
            .collect(),
    };
    serde_json::to_string_pretty(&doc).expect("serializable") + "\n"
}

/// An indented tree of evaluated terms with their lookup cost.
pub fn tree(nodes: &[Node]) -> String {
    fn walk(nodes: &[Node], depth: usize, out: &mut String) {
        for n in nodes {
            let mut detail = Vec::new();
            match n.lookups {
                0 => {}
                1 => detail.push("1 lookup".to_string()),
                k => detail.push(format!("{k} lookups")),
            }
            if n.void {
                detail.push("VOID".into());
            }
            if n.ranges > 0 && n.lookups > 0 && n.children.is_empty() {
                detail.push(match n.ranges {
                    1 => "1 range".into(),
                    k => format!("{k} ranges"),
                });
            }
            if let Some(note) = &n.note {
                detail.push(note.clone());
            }
            let label = format!("{}{}", "  ".repeat(depth + 1), n.term);
            if detail.is_empty() {
                out.push_str(&format!("{label}\n"));
            } else {
                out.push_str(&format!("{label:<56} {}\n", detail.join(", ")));
            }
            walk(&n.children, depth + 1, out);
        }
    }
    let mut out = String::new();
    walk(nodes, 0, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_at_spaces_and_rejoins() {
        let value = format!(
            "v=spf1 {} -all",
            (0..40)
                .map(|i| format!("ip4:10.0.{i}.0/24"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let parts = split_strings(&value);
        assert!(parts.len() > 1);
        assert!(parts.iter().all(|p| p.len() <= MAX_STRING));
        assert!(parts[1].starts_with(' '));
        assert_eq!(parts.concat(), value);
    }

    #[test]
    fn short_value_is_one_string() {
        assert_eq!(split_strings("v=spf1 -all"), ["v=spf1 -all"]);
    }
}
