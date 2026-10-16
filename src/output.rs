// SPDX-License-Identifier: GPL-3.0-or-later
//! Render flattened records, evaluation trees and risk reports.

use serde::Serialize;

use crate::config::Config;
use crate::eval::Node;
use crate::flatten::Plan;
use crate::risk::{SourceRisk, Suggestion};

/// Bumped when a JSON document changes incompatibly (see docs/json.md).
pub const SCHEMA_VERSION: u32 = 1;

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
    if let Some(w) = &plan.widening {
        out.push_str(&format!(
            "; widened {} prefixes: {} extra IPv4 addresses authorized\n",
            w.widened, w.extra_ipv4_addresses
        ));
    }
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

/// A record as it appears in JSON documents.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRecord {
    pub name: String,
    pub ttl: u32,
    pub value: String,
    /// The value split into the character-strings a zone needs.
    pub strings: Vec<String>,
    pub bytes: usize,
}

pub fn json_records(cfg: &Config, plan: &Plan) -> Vec<JsonRecord> {
    plan.records
        .iter()
        .map(|r| JsonRecord {
            name: r.name.clone(),
            ttl: cfg.ttl,
            value: r.value.clone(),
            strings: split_strings(&r.value),
            bytes: r.value.len(),
        })
        .collect()
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
            if let Some(ttl) = n.ttl {
                detail.push(format!("ttl {ttl}"));
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

/// The risk table and suggestions, for people.
pub fn risk(risks: &[SourceRisk], suggestions: &[Suggestion]) -> String {
    let width = risks.iter().map(|r| r.source.len()).max().unwrap_or(0);
    let mut out = String::new();
    for r in risks {
        let ttl = r
            .min_ttl
            .map_or("ttl ?".to_string(), |t| format!("ttl {t}"));
        out.push_str(&format!(
            "  {:<6}  {:<width$}  {} lookups, {} prefixes ({} hosts), {}\n",
            r.level.to_string(),
            r.source,
            r.lookups,
            r.prefixes,
            r.hosts,
            ttl
        ));
        for reason in &r.reasons {
            out.push_str(&format!("          - {reason}\n"));
        }
        if let Some(h) = &r.history {
            for p in &h.added {
                out.push_str(&format!("          + {p} (new since last run)\n"));
            }
            for p in &h.removed {
                out.push_str(&format!("          - {p} (gone since last run)\n"));
            }
        }
    }
    if !suggestions.is_empty() {
        out.push_str("\nsuggestions:\n");
        for s in suggestions {
            out.push_str(&format!("  {}: {}\n", s.source, s.advice));
        }
    }
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
