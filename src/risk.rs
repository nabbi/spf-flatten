// SPDX-License-Identifier: GPL-3.0-or-later
//! Drift risk: how likely each source's addresses are to change after they've
//! been flattened, so a stale record starts rejecting real mail.
//!
//! Two kinds of evidence feed the score. Heuristics need only one run: short
//! TTLs, many single-host addresses (cloud instances come and go), and deep
//! nesting the provider can rearrange. History needs a state file kept between
//! runs: each source's resolved prefixes are recorded, and every observed
//! change counts against it.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::dns::Dns;
use crate::eval::{Evaluator, Flat, Node};
use crate::flatten::{ip_term, summarize};
use crate::spf::{Mechanism, Term};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Low,
    Medium,
    High,
}

impl Level {
    fn from_score(score: u32) -> Self {
        match score {
            0..=1 => Level::Low,
            2..=3 => Level::Medium,
            _ => Level::High,
        }
    }
}

impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
        })
    }
}

/// History kept between runs, keyed by source term.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub schema_version: u32,
    pub domain: String,
    pub sources: BTreeMap<String, SourceState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceState {
    pub prefixes: Vec<String>,
    /// Unix seconds.
    pub first_seen: u64,
    pub last_checked: u64,
    pub last_changed: Option<u64>,
    pub checks: u32,
    pub changes: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct History {
    pub checks: u32,
    pub changes: u32,
    pub first_seen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_changed: Option<String>,
    /// Prefixes that appeared or disappeared since the previous run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub added: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceRisk {
    pub source: String,
    pub level: Level,
    pub score: u32,
    pub reasons: Vec<String>,
    /// Nothing from it is flattened (kept, or only per-message terms), so it can't go stale.
    pub live: bool,
    pub kept: bool,
    pub lookups: usize,
    pub prefixes: usize,
    pub hosts: usize,
    pub nested: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<History>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Suggestion {
    pub source: String,
    pub lookups: usize,
    pub advice: String,
}

/// Recent changes weigh more than old ones.
const RECENT_SECS: u64 = 30 * 86_400;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Unix seconds as an RFC 3339 UTC timestamp.
pub fn rfc3339(secs: u64) -> String {
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

struct Stats {
    min_ttl: Option<u32>,
    nested: usize,
}

fn stats(node: &Node) -> Stats {
    fn walk(n: &Node, s: &mut Stats, depth: usize) {
        if let Some(t) = n.ttl {
            s.min_ttl = Some(s.min_ttl.map_or(t, |m| m.min(t)));
        }
        let nests = n.term.contains("include:") || n.term.starts_with("redirect=");
        if depth > 0 && nests {
            s.nested += 1;
        }
        n.children.iter().for_each(|c| walk(c, s, depth + 1));
    }
    let mut s = Stats {
        min_ttl: None,
        nested: 0,
    };
    walk(node, &mut s, 0);
    s
}

/// Score each non-static source of `cfg`. `expected` is the config evaluated
/// with `keep` ignored. With `state`, each source's prefixes are recorded and
/// compared with the previous run.
pub fn assess(
    cfg: &Config,
    expected: &Flat,
    dns: &dyn Dns,
    mut state: Option<&mut State>,
    now: u64,
) -> Vec<SourceRisk> {
    let mut out = Vec::new();
    for (i, (term, node)) in cfg.terms.iter().zip(&expected.tree).enumerate() {
        if matches!(term, Term::Directive(_, Mechanism::Ip(..))) {
            continue;
        }
        let source = term.to_string();
        let kept = cfg.keep.get(i).copied().unwrap_or(false);
        // Nothing flattened from it (kept, not flattenable, or only lifted
        // per-message terms) means nothing to go stale.
        let live = kept || node.ranges == 0 || expected.live.iter().any(|l| l.term == source);
        let s = stats(node);
        let mut score = 0;
        let mut reasons = Vec::new();

        match s.min_ttl {
            Some(t) if t <= 300 => {
                score += 2;
                reasons.push(format!(
                    "TTL {t}s: the publisher expects to change it quickly"
                ));
            }
            Some(t) if t < 3600 => {
                score += 1;
                reasons.push(format!("TTL {t}s"));
            }
            _ => {}
        }
        if node.hosts >= 5 && node.hosts * 2 >= node.ranges {
            score += 2;
            reasons.push(format!(
                "{} of {} prefixes are single addresses, typical of cloud hosts that get replaced",
                node.hosts, node.ranges
            ));
        } else if node.hosts >= 3 {
            score += 1;
            reasons.push(format!("{} single-address prefixes", node.hosts));
        }
        if s.nested >= 2 {
            score += 1;
            reasons.push(format!(
                "built from {} nested records the provider can rearrange",
                s.nested
            ));
        }
        if matches!(term, Term::Directive(_, Mechanism::A(_) | Mechanism::Mx(_))) {
            score += 1;
            reasons.push("follows your own A/MX records, which change when hosts move".into());
        }

        let history = state.as_deref_mut().and_then(|st| {
            let h = record(st, cfg, term, &source, dns, now)?;
            match h.last_changed_secs {
                Some(t) if now.saturating_sub(t) <= RECENT_SECS => {
                    score += 3;
                    reasons.push(format!(
                        "changed {} times in {} checks, most recently {}",
                        h.history.changes,
                        h.history.checks,
                        rfc3339(t)
                    ));
                }
                Some(_) => {
                    score += 1;
                    reasons.push(format!(
                        "changed {} times, none recently",
                        h.history.changes
                    ));
                }
                None => {}
            }
            Some(h.history)
        });

        let level = if live {
            reasons.insert(
                0,
                "nothing from it is flattened, so it can't go stale".into(),
            );
            Level::Low
        } else {
            Level::from_score(score)
        };
        out.push(SourceRisk {
            source,
            level,
            score,
            reasons,
            live,
            kept,
            lookups: node.lookups,
            prefixes: node.ranges,
            hosts: node.hosts,
            nested: s.nested,
            min_ttl: s.min_ttl,
            history,
        });
    }
    out
}

struct Recorded {
    history: History,
    last_changed_secs: Option<u64>,
}

/// Resolve one source alone, compare with the state, and update it. Returns
/// None (leaving the state alone) if the source couldn't be resolved cleanly,
/// so a DNS failure is never mistaken for a change.
fn record(
    st: &mut State,
    cfg: &Config,
    term: &Term,
    source: &str,
    dns: &dyn Dns,
    now: u64,
) -> Option<Recorded> {
    let mut ev = Evaluator::new(dns);
    let flat = ev.evaluate_terms(&cfg.domain, std::slice::from_ref(term), &[]);
    if ev.has_errors() {
        return None;
    }
    let prefixes: Vec<String> = summarize(&flat.pass, &[]).iter().map(ip_term).collect();
    let entry = st
        .sources
        .entry(source.to_string())
        .or_insert_with(|| SourceState {
            prefixes: prefixes.clone(),
            first_seen: now,
            last_checked: now,
            last_changed: None,
            checks: 0,
            changes: 0,
        });
    let added: Vec<String> = prefixes
        .iter()
        .filter(|p| !entry.prefixes.contains(p))
        .cloned()
        .collect();
    let removed: Vec<String> = entry
        .prefixes
        .iter()
        .filter(|p| !prefixes.contains(p))
        .cloned()
        .collect();
    if !added.is_empty() || !removed.is_empty() {
        entry.changes += 1;
        entry.last_changed = Some(now);
        entry.prefixes = prefixes;
    }
    entry.checks += 1;
    entry.last_checked = now;
    Some(Recorded {
        history: History {
            checks: entry.checks,
            changes: entry.changes,
            first_seen: rfc3339(entry.first_seen),
            last_changed: entry.last_changed.map(rfc3339),
            added,
            removed,
        },
        last_changed_secs: entry.last_changed,
    })
}

/// Which risky sources to keep live, within the lookups left after flattening.
pub fn suggest(risks: &[SourceRisk], mut headroom: usize) -> Vec<Suggestion> {
    let mut risky: Vec<&SourceRisk> = risks
        .iter()
        .filter(|r| !r.live && r.level >= Level::Medium)
        .collect();
    risky.sort_by(|a, b| b.score.cmp(&a.score).then(a.lookups.cmp(&b.lookups)));
    let mut out = Vec::new();
    for r in risky {
        let advice = if r.lookups <= headroom {
            headroom -= r.lookups;
            format!(
                "set keep = true ({} lookup{}, fits the budget)",
                r.lookups,
                if r.lookups == 1 { "" } else { "s" }
            )
        } else if r.hosts > 0 {
            "no lookup budget left to keep it; consider widening (--aggressive) and run diff often"
                .into()
        } else {
            "no lookup budget left to keep it; run diff often".into()
        };
        out.push(Suggestion {
            source: r.source.clone(),
            lookups: r.lookups,
            advice,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::StaticDns;

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_792_108_800), "2026-10-16T00:00:00Z");
    }

    fn setup(zone: &str) -> (Config, StaticDns) {
        let cfg = Config::parse(
            "domain = \"example.com\"\npolicy = \"-all\"\n\
             [[source]]\ninclude = \"cloud.test\"\n\
             [[source]]\ninclude = \"stable.test\"\n\
             [[source]]\ninclude = \"macro.test\"\n",
        )
        .unwrap();
        (cfg, StaticDns::parse(zone).unwrap())
    }

    const ZONE: &str = r#"
        cloud.test 300 TXT "v=spf1 ip4:192.0.2.1 ip4:192.0.2.7 ip4:192.0.2.9 ip4:192.0.2.20 ip4:192.0.2.33 -all"
        stable.test 86400 TXT "v=spf1 ip4:198.51.100.0/24 -all"
        macro.test TXT "v=spf1 exists:%{i}.x.macro.test -all"
    "#;

    fn run(cfg: &Config, dns: &StaticDns, state: Option<&mut State>, now: u64) -> Vec<SourceRisk> {
        let mut ev = Evaluator::new(dns);
        let expected = ev.evaluate_terms(&cfg.domain, &cfg.terms, &[]);
        assess(cfg, &expected, dns, state, now)
    }

    #[test]
    fn heuristics() {
        let (cfg, dns) = setup(ZONE);
        let r = run(&cfg, &dns, None, 0);
        assert_eq!(r[0].level, Level::High, "{:?}", r[0]);
        assert_eq!(r[0].min_ttl, Some(300));
        assert_eq!(r[1].level, Level::Low);
        assert!(r[2].live);
        let s = suggest(&r, 1);
        assert_eq!(s.len(), 1);
        assert!(s[0].advice.starts_with("set keep = true"));
    }

    #[test]
    fn history_tracks_changes() {
        let (cfg, dns) = setup(ZONE);
        let mut state = State::default();
        run(&cfg, &dns, Some(&mut state), 1000);
        let r = run(&cfg, &dns, Some(&mut state), 2000);
        let h = r[1].history.as_ref().unwrap();
        assert_eq!((h.checks, h.changes), (2, 0));

        let changed = ZONE.replace("198.51.100.0/24", "198.51.100.0/23");
        let (cfg, dns) = setup(&changed);
        let r = run(&cfg, &dns, Some(&mut state), 3000);
        let h = r[1].history.as_ref().unwrap();
        assert_eq!((h.checks, h.changes), (3, 1));
        assert_eq!(h.added, ["ip4:198.51.100.0/23"]);
        assert_eq!(h.removed, ["ip4:198.51.100.0/24"]);
        assert_eq!(r[1].level, Level::Medium);
    }

    #[test]
    fn dns_failure_is_not_a_change() {
        let (cfg, dns) = setup(ZONE);
        let mut state = State::default();
        run(&cfg, &dns, Some(&mut state), 1000);
        let mut broken = StaticDns::parse(ZONE).unwrap();
        broken.add_failure("stable.test");
        let r = run(&cfg, &broken, Some(&mut state), 2000);
        assert!(r[1].history.is_none());
        assert_eq!(state.sources["include:stable.test"].changes, 0);
    }
}
