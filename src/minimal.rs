// SPDX-License-Identifier: GPL-3.0-or-later
//! Minimal flattening: keep as much of the record live as the lookup budget
//! allows, flattening the sources least likely to drift.
//!
//! Every source starts live, which is the record as published. Sources are
//! flattened one at a time, lowest drift risk and largest lookup saving
//! first, until the packed result fits `max_lookups - headroom`. A second
//! pass then tries to return each flattened source to live, riskiest first,
//! and keeps any that still fit.

use serde::Serialize;

use crate::config::Config;
use crate::dns::Dns;
use crate::eval::Evaluator;
use crate::flatten::pack_records;
use crate::risk::{Level, SourceRisk};
use crate::spf::{Mechanism, Term};

#[derive(Debug, Clone, Serialize)]
pub struct Choice {
    pub source: String,
    pub flattened: bool,
    pub level: Level,
    pub score: u32,
    /// Lookups the source costs when live.
    pub lookups: usize,
    pub reason: String,
}

/// The `keep` vector to flatten with, and why each source landed where it did.
#[derive(Debug, Clone, Serialize)]
pub struct Minimal {
    #[serde(skip)]
    pub keep: Vec<bool>,
    pub target: usize,
    pub lookups: usize,
    pub choices: Vec<Choice>,
}

/// Lookups the packed result needs with this `keep`, or None if it can't be
/// packed (the live terms alone overflow the apex record).
fn cost(cfg: &Config, dns: &dyn Dns, keep: &[bool]) -> Option<usize> {
    let flat = Evaluator::new(dns).evaluate_terms(&cfg.domain, &cfg.terms, keep);
    pack_records(cfg, &flat).ok().map(|p| p.lookups)
}

pub fn choose(cfg: &Config, dns: &dyn Dns, risks: &[SourceRisk]) -> Result<Minimal, String> {
    let target = cfg.max_lookups - cfg.headroom;
    let risk_of = |t: &Term| risks.iter().find(|r| r.source == t.to_string());

    // Candidates: sources that cost lookups and the config doesn't pin live.
    let mut keep: Vec<bool> = cfg
        .terms
        .iter()
        .map(|t| !matches!(t, Term::Directive(_, Mechanism::Ip(..))))
        .collect();
    let mut candidates: Vec<usize> = (0..cfg.terms.len())
        .filter(|&i| {
            keep[i] && !cfg.keep[i] && risk_of(&cfg.terms[i]).is_some_and(|r| r.lookups > 0)
        })
        .collect();
    candidates.sort_by_key(|&i| {
        let r = risk_of(&cfg.terms[i]).expect("filtered");
        (r.level, r.score, std::cmp::Reverse(r.lookups))
    });

    let mut lookups = cost(cfg, dns, &keep);
    let mut flattened = Vec::new();
    for &i in &candidates {
        if lookups.is_some_and(|n| n <= target) {
            break;
        }
        keep[i] = false;
        flattened.push(i);
        lookups = cost(cfg, dns, &keep);
    }
    let Some(mut lookups) = lookups.filter(|&n| n <= target) else {
        return Err(format!(
            "even flattening every source needs {} lookups, over the target of {target} \
             (max_lookups {} minus headroom {})",
            lookups.map_or("too many".into(), |n| n.to_string()),
            cfg.max_lookups,
            cfg.headroom
        ));
    };

    // Return sources to live where the budget still allows, riskiest first.
    for &i in flattened.iter().rev() {
        keep[i] = true;
        match cost(cfg, dns, &keep) {
            Some(n) if n <= target => lookups = n,
            _ => keep[i] = false,
        }
    }

    let choices = (0..cfg.terms.len())
        .filter_map(|i| {
            let r = risk_of(&cfg.terms[i])?;
            let reason = if cfg.keep[i] {
                "pinned live with keep = true".to_string()
            } else if !keep[i] {
                format!("flattened: {} drift risk, saves lookups", r.level)
            } else if r.lookups == 0 {
                "live: costs no lookups".to_string()
            } else {
                "live: not needed to meet the budget".to_string()
            };
            Some(Choice {
                source: r.source.clone(),
                flattened: !keep[i],
                level: r.level,
                score: r.score,
                lookups: r.lookups,
                reason,
            })
        })
        .collect();
    Ok(Minimal {
        keep,
        target,
        lookups,
        choices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::StaticDns;
    use crate::risk::assess;

    fn run(cfg_extra: &str) -> Minimal {
        // Three providers: stable (long TTL), volatile (short TTL, hosts), and
        // a deep one; the original record needs 11 lookups.
        let dns = StaticDns::parse(
            r#"
            stable.test 86400 TXT "v=spf1 include:s1.stable.test include:s2.stable.test -all"
            s1.stable.test 86400 TXT "v=spf1 ip4:198.51.100.0/24 -all"
            s2.stable.test 86400 TXT "v=spf1 ip4:203.0.113.0/24 -all"
            cloud.test 60 TXT "v=spf1 ip4:192.0.2.1 ip4:192.0.2.7 ip4:192.0.2.9 ip4:192.0.2.20 ip4:192.0.2.33 -all"
            deep.test 3600 TXT "v=spf1 include:d1.deep.test include:d2.deep.test include:d3.deep.test include:d4.deep.test -all"
            d1.deep.test 3600 TXT "v=spf1 ip4:10.1.0.0/16 -all"
            d2.deep.test 3600 TXT "v=spf1 ip4:10.2.0.0/16 -all"
            d3.deep.test 3600 TXT "v=spf1 ip4:10.3.0.0/16 -all"
            d4.deep.test 3600 TXT "v=spf1 ip4:10.4.0.0/16 -all"
            other.test 3600 TXT "v=spf1 ip4:172.16.0.0/16 -all"
            "#,
        )
        .unwrap();
        let cfg = Config::parse(&format!(
            "domain = \"example.com\"\npolicy = \"-all\"\nstrategy = \"minimal\"\n{cfg_extra}\n\
             [[source]]\ninclude = \"stable.test\"\n\
             [[source]]\ninclude = \"cloud.test\"\n\
             [[source]]\ninclude = \"deep.test\"\n\
             [[source]]\ninclude = \"other.test\"\n"
        ))
        .unwrap();
        let expected = Evaluator::new(&dns).evaluate_terms(&cfg.domain, &cfg.terms, &[]);
        assert_eq!(expected.lookups, 10);
        let risks = assess(&cfg, &expected, &dns, None, 0);
        choose(&cfg, &dns, &risks).unwrap()
    }

    fn flattened(m: &Minimal) -> Vec<&str> {
        m.choices
            .iter()
            .filter(|c| c.flattened)
            .map(|c| c.source.as_str())
            .collect()
    }

    #[test]
    fn within_budget_flattens_nothing() {
        let m = run("headroom = 0");
        assert!(flattened(&m).is_empty());
        assert_eq!(m.lookups, 10);
    }

    #[test]
    fn flattens_stable_sources_and_keeps_volatile_live() {
        let m = run("headroom = 3");
        assert!(m.lookups <= 7, "{m:?}");
        let f = flattened(&m);
        assert!(!f.contains(&"include:cloud.test"), "{f:?}");
        assert!(
            f.contains(&"include:deep.test") || f.contains(&"include:stable.test"),
            "{f:?}"
        );
    }

    #[test]
    fn pruning_returns_unneeded_sources_to_live() {
        let m = run("headroom = 4");
        // Flattening deep.test alone (5 -> 1 chain record or apex) reaches 6.
        assert!(m.lookups <= 6);
        assert!(flattened(&m).len() <= 2, "{m:?}");
    }
}
