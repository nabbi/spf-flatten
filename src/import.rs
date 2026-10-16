// SPDX-License-Identifier: GPL-3.0-or-later
//! Build a config file from the SPF record a domain publishes now.

use std::collections::HashMap;

use route_summarization::Family;

use crate::config::{DEFAULT_CHAIN_PREFIX, Entry, render};
use crate::dns::Dns;
use crate::eval::{Evaluator, MAX_LOOKUPS, MAX_VOIDS, Problem};
use crate::spf::{HostSpec, Mechanism, Qualifier, Record, Term};

pub struct Imported {
    pub config: String,
    pub problems: Vec<Problem>,
}

/// Value for an `a`/`mx`/`ptr` source: "@" for the current domain, plus CIDR lengths.
fn host_value(domain: Option<&str>, h: &HostSpec) -> String {
    let mut s = domain.unwrap_or("@").to_string();
    if let Some(n) = h.v4 {
        s.push_str(&format!("/{n}"));
    }
    if let Some(n) = h.v6 {
        s.push_str(&format!("//{n}"));
    }
    s
}

/// True for names like `_spf3.example.com`, which a previous flatten wrote.
fn looks_flattened(target: &str, domain: &str) -> bool {
    target
        .strip_suffix(domain)
        .and_then(|t| t.strip_suffix('.'))
        .and_then(|t| t.strip_prefix(DEFAULT_CHAIN_PREFIX))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The `all` qualifier that applies to `record`, following redirects.
fn policy(record: &Record, dns: &dyn Dns) -> Option<Qualifier> {
    let mut record = record.clone();
    for _ in 0..MAX_LOOKUPS {
        if let Some(q) = record.all() {
            return Some(q);
        }
        let target = record.redirect()?.to_string();
        let (next, _) = Evaluator::new(dns).fetch(&target);
        record = next?;
    }
    None
}

pub fn import(domain: &str, dns: &dyn Dns) -> Result<Imported, Vec<Problem>> {
    let mut fetcher = Evaluator::new(dns);
    let (Some(record), _) = fetcher.fetch(domain) else {
        return Err(fetcher.problems);
    };
    let mut ev = Evaluator::new(dns);
    let flat = ev.evaluate_domain(domain).unwrap_or_default();
    let cost: HashMap<&str, usize> = flat
        .tree
        .iter()
        .map(|n| (n.term.as_str(), n.lookups))
        .collect();
    let note = |term: &str| match cost.get(term) {
        Some(1) => Some("1 lookup".to_string()),
        Some(&n) if n > 1 => Some(format!("{n} lookups")),
        _ => None,
    };

    let mut comments = vec![
        format!("Imported from the SPF record at {domain}:"),
        format!("  {record}"),
        format!(
            "It costs {} of {MAX_LOOKUPS} lookups and {} of {MAX_VOIDS} void lookups.",
            flat.lookups, flat.voids
        ),
    ];
    let mut entries: Vec<Entry> = Vec::new();
    let mut ip_index: HashMap<Family, usize> = HashMap::new();
    let has_all = record.all().is_some();

    for term in &record.terms {
        let text = term.to_string();
        let (key, value) = match term {
            Term::Directive(_, Mechanism::All) => continue,
            Term::Directive(q, _) if *q != Qualifier::Pass => {
                comments.push(format!("Dropped {text}: sources must be pass (+) terms."));
                continue;
            }
            Term::Directive(_, Mechanism::Ip(family, addr, _)) => {
                let key = match family {
                    Family::V4 => "ip4",
                    Family::V6 => "ip6",
                };
                match ip_index.get(family) {
                    Some(&i) => entries[i].values.push(addr.clone()),
                    None => {
                        ip_index.insert(*family, entries.len());
                        entries.push(Entry {
                            key,
                            values: vec![addr.clone()],
                            keep: false,
                            note: Some("listed directly in the record".into()),
                        });
                    }
                }
                continue;
            }
            Term::Directive(_, Mechanism::Include(d)) => {
                if looks_flattened(d, domain) {
                    comments.push(format!(
                        "{d} looks like the output of an earlier flatten; replace it with the original sources."
                    ));
                }
                ("include", d.clone())
            }
            Term::Directive(_, Mechanism::A(h)) => ("a", host_value(h.domain.as_deref(), h)),
            Term::Directive(_, Mechanism::Mx(h)) => ("mx", host_value(h.domain.as_deref(), h)),
            Term::Directive(_, Mechanism::Ptr(d)) => {
                ("ptr", d.clone().unwrap_or_else(|| "@".into()))
            }
            Term::Directive(_, Mechanism::Exists(d)) => ("exists", d.clone()),
            Term::Redirect(d) if !has_all => {
                let cost = cost.get(text.as_str()).copied().unwrap_or(1);
                entries.push(Entry {
                    key: "include",
                    values: vec![d.clone()],
                    keep: false,
                    note: Some(format!("was redirect=, {cost} lookups")),
                });
                continue;
            }
            Term::Redirect(_) | Term::Exp(_) | Term::Unknown(..) => {
                comments.push(format!("Dropped {text}."));
                continue;
            }
        };
        entries.push(Entry {
            key,
            values: vec![value],
            keep: false,
            note: note(&text),
        });
    }

    let policy = match policy(&record, dns) {
        Some(Qualifier::Pass) => {
            comments.push("The record ends in +all, which authorizes everyone; using ~all.".into());
            "~all".to_string()
        }
        Some(q) => format!("{}all", q.prefix()),
        None => {
            comments.push("The record has no \"all\"; its default is ?all (neutral).".into());
            "?all".to_string()
        }
    };

    Ok(Imported {
        config: render(domain, &policy, &entries, &comments),
        problems: ev.problems,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::dns::StaticDns;

    #[test]
    fn imports_and_reparses() {
        let dns = StaticDns::parse(
            r#"
            example.com TXT "v=spf1 ip4:192.0.2.1 mx include:p.example ip4:192.0.2.9 a:web.example.com/28 -ip4:10.0.0.1 redirect=r.example"
            p.example TXT "v=spf1 include:q.example ~all"
            q.example TXT "v=spf1 ip6:2001:db8::/32 ~all"
            r.example TXT "v=spf1 ip4:198.51.100.0/24 -all"
            example.com MX mx.example.com
            mx.example.com A 192.0.2.25
            web.example.com A 192.0.2.80
            "#,
        )
        .unwrap();
        let out = import("example.com", &dns).unwrap();
        let cfg = Config::parse(&out.config).unwrap();
        let terms: Vec<String> = cfg.terms.iter().map(|t| t.to_string()).collect();
        assert_eq!(
            terms,
            [
                "ip4:192.0.2.1",
                "ip4:192.0.2.9",
                "mx",
                "include:p.example",
                "a:web.example.com/28",
                "include:r.example"
            ]
        );
        assert_eq!(cfg.policy, Qualifier::Fail);
        assert!(out.config.contains("note = \"2 lookups\""));
        assert!(out.config.contains("# Dropped -ip4:10.0.0.1"));
    }

    #[test]
    fn flags_previous_output() {
        assert!(looks_flattened("_spf2.example.com", "example.com"));
        assert!(!looks_flattened("_spf.example.com", "example.com"));
        assert!(!looks_flattened("_spf2.notexample.com", "example.com"));
    }
}
