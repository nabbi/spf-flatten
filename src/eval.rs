// SPDX-License-Identifier: GPL-3.0-or-later
//! Evaluate SPF the way a receiver would in the worst case: follow every
//! include and redirect, count DNS lookups and void lookups (RFC 7208 §4.6.4),
//! and collect the addresses that end in `pass`.
//!
//! Terms that can only be resolved per message (macros, `exists`, `ptr`) are
//! kept as [`Live`] terms. Inside an include they are lifted into the top-level
//! record when that keeps their meaning; otherwise the whole include stays live.

use std::net::IpAddr;

use route_summarization::{Aggregator, Range, parse_entry};
use serde::Serialize;

use crate::dns::Dns;
use crate::spf::{self, HostSpec, Mechanism, Qualifier, Record, Term};

/// RFC 7208 §4.6.4 limits.
pub const MAX_LOOKUPS: usize = 10;
pub const MAX_VOIDS: usize = 2;
/// Names an `mx` (or `ptr`) term may expand to.
const MAX_NAMES: usize = 10;
const MAX_DEPTH: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct Problem {
    pub severity: Severity,
    /// Chain of domains being evaluated when it was found.
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let level = match self.severity {
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        if self.path.is_empty() {
            write!(f, "{level}: {}", self.message)
        } else {
            write!(f, "{level}: {}: {}", self.path, self.message)
        }
    }
}

/// A term written verbatim into the top-level record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Live {
    pub term: String,
    /// Lookups it costs, including everything under it.
    pub lookups: usize,
    pub reason: String,
}

/// One evaluated term, for display.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Node {
    pub term: String,
    /// Lookups for this term and everything under it.
    pub lookups: usize,
    pub void: bool,
    /// CIDR ranges this term matched directly or through its children.
    pub ranges: usize,
    /// How many of those ranges are single addresses (/32 or /128).
    pub hosts: usize,
    /// Lowest TTL of the records this term itself looked up, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<Node>,
}

/// The result of evaluating one record, or the configured list of sources.
#[derive(Debug, Clone, Default)]
pub struct Flat {
    /// Addresses whose result is `pass`, with earlier non-pass terms taken out.
    pub pass: Vec<Range>,
    /// Terms that can't be flattened, valid in the top-level record.
    pub live: Vec<Live>,
    /// Worst-case lookups, including those under live terms.
    pub lookups: usize,
    pub voids: usize,
    /// The `all` qualifier, from this record or its redirect target.
    pub all: Option<Qualifier>,
    /// False when a live term can't be moved out of this record: it depends on
    /// the current domain (`%{d}`), or a non-pass term before it may shadow it.
    pub portable: bool,
    pub tree: Vec<Node>,
}

/// What one mechanism contributes.
#[derive(Default)]
struct Outcome {
    ranges: Vec<Range>,
    live: Vec<Live>,
    lookups: usize,
    voids: usize,
    portable: bool,
    node: Node,
}

impl Outcome {
    fn new(term: String) -> Self {
        Self {
            portable: true,
            node: Node {
                term,
                ..Node::default()
            },
            ..Self::default()
        }
    }

    fn finish(mut self) -> Self {
        self.node.lookups = self.lookups;
        self.node.ranges = self.ranges.len();
        self.node.hosts = host_count(&self.ranges);
        self
    }
}

fn host_count(ranges: &[Range]) -> usize {
    ranges.iter().filter(|r| r.start() == r.end()).count()
}

pub struct Evaluator<'a> {
    dns: &'a dyn Dns,
    pub problems: Vec<Problem>,
    stack: Vec<String>,
}

impl<'a> Evaluator<'a> {
    pub fn new(dns: &'a dyn Dns) -> Self {
        Self {
            dns,
            problems: Vec::new(),
            stack: Vec::new(),
        }
    }

    pub fn has_errors(&self) -> bool {
        self.problems.iter().any(|p| p.severity == Severity::Error)
    }

    fn report(&mut self, severity: Severity, message: impl Into<String>) {
        self.problems.push(Problem {
            severity,
            path: self.stack.join(" > "),
            message: message.into(),
        });
    }

    fn error(&mut self, message: impl Into<String>) {
        self.report(Severity::Error, message);
    }

    fn warn(&mut self, message: impl Into<String>) {
        self.report(Severity::Warning, message);
    }

    /// Fetch and parse the SPF record at `domain`. Returns the record (if
    /// exactly one valid one exists) and whether the TXT lookup was void.
    pub fn fetch(&mut self, domain: &str) -> (Option<Record>, bool) {
        let txts = match self.dns.txt(domain) {
            Ok(t) => t,
            Err(e) => {
                self.error(format!("temporary DNS failure: {e}"));
                return (None, false);
            }
        };
        let void = txts.is_empty();
        let spf: Vec<&String> = txts.iter().filter(|t| spf::is_spf(t)).collect();
        let record = match spf.as_slice() {
            [] => {
                self.error(format!("no SPF record at {domain}"));
                None
            }
            [one] => match Record::parse(one) {
                Ok(r) => Some(r),
                Err(e) => {
                    self.error(format!("invalid SPF record at {domain}: {e}"));
                    None
                }
            },
            _ => {
                self.error(format!(
                    "{} SPF records at {domain}; receivers return permerror",
                    spf.len()
                ));
                None
            }
        };
        (record, void)
    }

    /// Evaluate the record published at `domain`.
    pub fn evaluate_domain(&mut self, domain: &str) -> Option<Flat> {
        self.stack.push(domain.to_string());
        let (record, _) = self.fetch(domain);
        let flat = record.map(|r| self.evaluate(domain, &r.terms, &[]));
        self.stack.pop();
        flat
    }

    /// Evaluate `terms` as the top-level record of `domain`. Terms whose
    /// `keep` entry is true are written verbatim instead of flattened.
    pub fn evaluate_terms(&mut self, domain: &str, terms: &[Term], keep: &[bool]) -> Flat {
        self.stack.push(domain.to_string());
        let flat = self.evaluate(domain, terms, keep);
        self.stack.pop();
        flat
    }

    fn evaluate(&mut self, domain: &str, terms: &[Term], keep: &[bool]) -> Flat {
        let mut out = Flat {
            portable: true,
            ..Flat::default()
        };
        // Addresses already matched by non-pass terms; later terms never see them.
        let mut blocked: Vec<Range> = Vec::new();
        let has_all = terms
            .iter()
            .any(|t| matches!(t, Term::Directive(_, Mechanism::All)));

        for (i, term) in terms.iter().enumerate() {
            let Term::Directive(q, m) = term else {
                continue;
            };
            if *m == Mechanism::All {
                out.all = Some(*q);
                let mut o = Outcome::new(term.to_string());
                if *q == Qualifier::Pass {
                    self.warn("\"+all\" authorizes every address on the internet");
                    o.ranges = vec![
                        parse_entry("0.0.0.0/0", false).unwrap(),
                        parse_entry("::/0", false).unwrap(),
                    ];
                }
                self.merge(&mut out, &mut blocked, *q, o.finish());
                // Nothing after `all` is evaluated.
                break;
            }
            let keep = keep.get(i).copied().unwrap_or(false);
            let o = self.mechanism(domain, *q, m, keep);
            self.merge(&mut out, &mut blocked, *q, o);
        }

        let redirect = terms.iter().find_map(|t| match t {
            Term::Redirect(d) => Some(d.as_str()),
            _ => None,
        });
        if let Some(target) = redirect
            && !has_all
        {
            self.redirect(&mut out, &blocked, target);
        }
        out
    }

    /// Fold one mechanism's outcome into the record's result.
    fn merge(&mut self, out: &mut Flat, blocked: &mut Vec<Range>, q: Qualifier, o: Outcome) {
        out.lookups += o.lookups;
        out.voids += o.voids;
        out.portable &= o.portable;
        if q == Qualifier::Pass {
            out.pass.extend(subtract(&o.ranges, blocked));
            if !o.live.is_empty() && !blocked.is_empty() {
                out.portable = false;
            }
        } else {
            blocked.extend(o.ranges);
            if !o.live.is_empty() {
                out.portable = false;
            }
        }
        out.live.extend(o.live);
        out.tree.push(o.node);
    }

    fn redirect(&mut self, out: &mut Flat, blocked: &[Range], target: &str) {
        let mut node = Node {
            term: format!("redirect={target}"),
            ..Node::default()
        };
        out.lookups += 1;
        if spf::has_macro(target) {
            self.error(format!(
                "redirect={target} uses macros and cannot be flattened"
            ));
            out.portable = false;
        } else {
            let (sub, void) = self.nested(target);
            out.voids += usize::from(void);
            node.void = void;
            node.ttl = self.ttl(target, &["TXT"]);
            let Some(sub) = sub else {
                out.tree.push(node);
                return;
            };
            out.voids += sub.voids;
            out.lookups += sub.lookups;
            out.all = sub.all;
            out.pass.extend(subtract(&sub.pass, blocked));
            out.portable &= sub.portable && (sub.live.is_empty() || blocked.is_empty());
            out.live.extend(sub.live);
            node.lookups = 1 + sub.lookups;
            node.ranges = sub.pass.len();
            node.hosts = host_count(&sub.pass);
            node.children = sub.tree;
        }
        out.tree.push(node);
    }

    /// Evaluate the record at `target` one level down, guarding against loops.
    /// Returns the result, if the record could be evaluated, and whether its
    /// TXT lookup was void.
    fn nested(&mut self, target: &str) -> (Option<Flat>, bool) {
        if self.stack.iter().any(|d| d == target) {
            self.error(format!("{target} includes itself (loop)"));
            return (None, false);
        }
        if self.stack.len() >= MAX_DEPTH {
            self.error(format!("nesting deeper than {MAX_DEPTH} at {target}"));
            return (None, false);
        }
        self.stack.push(target.to_string());
        let (record, void) = self.fetch(target);
        let flat = record.map(|r| self.evaluate(target, &r.terms, &[]));
        self.stack.pop();
        (flat, void)
    }

    fn mechanism(&mut self, domain: &str, q: Qualifier, m: &Mechanism, keep: bool) -> Outcome {
        let text = format!("{}{m}", q.prefix());
        let mut o = Outcome::new(text.clone());
        if let Mechanism::Ip(_, _, range) = m {
            if keep {
                self.warn(format!("keep has no effect on {text}"));
            }
            o.ranges.push(*range);
            return o.finish();
        }

        o.lookups = 1;
        let spec = m.domain_spec();
        if let Some(spec) = spec.filter(|s| spf::has_macro(s)) {
            o.portable = !spf::uses_current_domain(spec);
            let reason = "uses macros, resolved per message";
            o.node.note = Some(reason.into());
            if matches!(m, Mechanism::Include(_)) {
                self.warn(format!(
                    "{text}: lookups under a macro include can't be counted ahead of time"
                ));
            }
            o.live.push(live(&text, 1, reason));
            return o.finish();
        }
        let target = spec.unwrap_or(domain).to_string();

        match m {
            Mechanism::Include(_) => self.include(&mut o, q, &text, &target, keep),
            Mechanism::A(h) => {
                if keep {
                    o.live.push(live(&text, 1, "kept live"));
                } else {
                    let (ranges, void) = self.addresses(&target, h);
                    o.ranges = ranges;
                    o.voids = usize::from(void);
                    o.node.void = void;
                    o.node.ttl = self.ttl(&target, &["A", "AAAA"]);
                }
            }
            Mechanism::Mx(h) => {
                if keep {
                    o.live.push(live(&text, 1, "kept live"));
                } else {
                    self.mx(&mut o, &target, h);
                }
            }
            Mechanism::Ptr(d) => {
                self.warn(format!(
                    "{text}: ptr is deprecated (RFC 7208 §5.5), slow, and ignored by some receivers"
                ));
                // Bare `ptr` means the current domain; name it so it survives being lifted.
                let term = match d {
                    None if self.stack.len() > 1 => format!("{}ptr:{domain}", q.prefix()),
                    _ => text.clone(),
                };
                o.node.note = Some("resolved per message".into());
                o.live.push(live(&term, 1, "ptr is resolved per message"));
            }
            Mechanism::Exists(_) => {
                o.node.note = Some("resolved per message".into());
                o.live
                    .push(live(&text, 1, "exists is resolved per message"));
            }
            Mechanism::All | Mechanism::Ip(..) => unreachable!(),
        }
        o.finish()
    }

    fn include(&mut self, o: &mut Outcome, q: Qualifier, text: &str, target: &str, keep: bool) {
        let (sub, void) = self.nested(target);
        o.node.ttl = self.ttl(target, &["TXT"]);
        if void {
            o.voids += 1;
            o.node.void = true;
        }
        let Some(sub) = sub else {
            return;
        };
        o.lookups += sub.lookups;
        o.voids += sub.voids;
        o.node.children = sub.tree;
        if sub.all == Some(Qualifier::Pass) {
            self.warn(format!("{text}: the included record ends in +all"));
        }
        let lifts = sub.live.is_empty() || (sub.portable && q == Qualifier::Pass);
        if keep || !lifts {
            let reason = if keep {
                "kept live"
            } else {
                "contains terms that only work inside it"
            };
            o.node.note = Some(reason.into());
            o.live.push(live(text, 1 + sub.lookups, reason));
            return;
        }
        o.ranges = sub.pass;
        o.live = sub.live;
    }

    fn mx(&mut self, o: &mut Outcome, target: &str, h: &HostSpec) {
        let names = match self.dns.mx(target) {
            Ok(n) => n,
            Err(e) => {
                self.error(format!("temporary DNS failure: {e}"));
                return;
            }
        };
        // A null MX (RFC 7505) has the root as its exchange.
        let names: Vec<String> = names.into_iter().filter(|n| !n.is_empty()).collect();
        if names.is_empty() {
            o.voids = 1;
            o.node.void = true;
            return;
        }
        if names.len() > MAX_NAMES {
            self.error(format!(
                "mx:{target} has {} MX names; over {MAX_NAMES} is a permerror",
                names.len()
            ));
        }
        o.node.ttl = self.ttl(target, &["MX"]);
        for name in names.iter().take(MAX_NAMES) {
            let (ranges, _) = self.addresses(name, h);
            o.ranges.extend(ranges);
            o.node.ttl = min_opt(o.node.ttl, self.ttl(name, &["A", "AAAA"]));
        }
        o.node.note = Some(format!("{} MX hosts", names.len()));
    }

    /// A and AAAA records of `name` as CIDR ranges; true if both were empty.
    fn addresses(&mut self, name: &str, h: &HostSpec) -> (Vec<Range>, bool) {
        let mut ips: Vec<IpAddr> = Vec::new();
        match self.dns.a(name) {
            Ok(v) => ips.extend(v.into_iter().map(IpAddr::V4)),
            Err(e) => self.error(format!("temporary DNS failure: {e}")),
        }
        match self.dns.aaaa(name) {
            Ok(v) => ips.extend(v.into_iter().map(IpAddr::V6)),
            Err(e) => self.error(format!("temporary DNS failure: {e}")),
        }
        let void = ips.is_empty();
        let ranges = ips
            .into_iter()
            .map(|ip| {
                let len = match ip {
                    IpAddr::V4(_) => h.v4.unwrap_or(32),
                    IpAddr::V6(_) => h.v6.unwrap_or(128),
                };
                parse_entry(&format!("{ip}/{len}"), false).expect("valid address and length")
            })
            .collect();
        (ranges, void)
    }
}

fn min_opt(a: Option<u32>, b: Option<u32>) -> Option<u32> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

impl Evaluator<'_> {
    /// Lowest known TTL of `name` across record types.
    fn ttl(&self, name: &str, rtypes: &[&'static str]) -> Option<u32> {
        rtypes
            .iter()
            .fold(None, |acc, t| min_opt(acc, self.dns.ttl(name, t)))
    }
}

fn live(term: &str, lookups: usize, reason: &str) -> Live {
    Live {
        term: term.to_string(),
        lookups,
        reason: reason.to_string(),
    }
}

/// `ranges` minus `blocked`, as CIDR ranges.
pub fn subtract(ranges: &[Range], blocked: &[Range]) -> Vec<Range> {
    if blocked.is_empty() {
        return ranges.to_vec();
    }
    let mut agg = Aggregator::new();
    ranges.iter().for_each(|r| agg.add(*r));
    blocked.iter().for_each(|r| agg.exclude(*r));
    agg.summarize().iter().map(|p| p.range()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::StaticDns;

    fn eval(zone: &str, domain: &str) -> (Flat, Vec<Problem>) {
        let dns = StaticDns::parse(zone).unwrap();
        let mut ev = Evaluator::new(&dns);
        let flat = ev.evaluate_domain(domain).unwrap_or_default();
        (flat, ev.problems)
    }

    fn prefixes(flat: &Flat) -> Vec<String> {
        let mut agg = Aggregator::new();
        flat.pass.iter().for_each(|r| agg.add(*r));
        agg.summarize().iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn counts_nested_lookups() {
        let (flat, problems) = eval(
            r#"
            example.com TXT "v=spf1 include:a.example mx a:host.example -all"
            a.example TXT "v=spf1 include:b.example ip4:192.0.2.0/25"
            b.example TXT "v=spf1 ip4:192.0.2.128/25 ip6:2001:db8::/32"
            example.com MX mx1.example.com
            mx1.example.com A 198.51.100.7
            host.example A 203.0.113.1
            "#,
            "example.com",
        );
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(flat.lookups, 4);
        assert_eq!(flat.voids, 0);
        assert_eq!(flat.all, Some(Qualifier::Fail));
        assert_eq!(
            prefixes(&flat),
            [
                "192.0.2.0/24",
                "198.51.100.7",
                "203.0.113.1",
                "2001:db8::/32"
            ]
        );
    }

    #[test]
    fn void_lookups_and_missing_records() {
        let (flat, problems) = eval(
            r#"
            example.com TXT "v=spf1 a:gone.example mx:nomx.example include:missing.example -all"
            "#,
            "example.com",
        );
        assert_eq!(flat.voids, 3);
        assert!(
            problems
                .iter()
                .any(|p| p.message.contains("no SPF record at missing.example"))
        );
    }

    #[test]
    fn non_pass_terms_shadow_later_ones() {
        let (flat, _) = eval(
            r#"
            example.com TXT "v=spf1 -ip4:192.0.2.0/26 ip4:192.0.2.0/24 ~all"
            "#,
            "example.com",
        );
        assert_eq!(prefixes(&flat), ["192.0.2.64/26", "192.0.2.128/25"]);
    }

    #[test]
    fn lifts_portable_macros_and_keeps_others() {
        let (flat, _) = eval(
            r#"
            example.com TXT "v=spf1 include:sf.example include:local.example -all"
            sf.example TXT "v=spf1 ip4:192.0.2.1 exists:%{i}._spf.sf.example ~all"
            local.example TXT "v=spf1 exists:%{l}.%{d} -all"
            "#,
            "example.com",
        );
        let live: Vec<&str> = flat.live.iter().map(|l| l.term.as_str()).collect();
        assert_eq!(
            live,
            ["exists:%{i}._spf.sf.example", "include:local.example"]
        );
        assert_eq!(flat.lookups, 4);
        assert_eq!(prefixes(&flat), ["192.0.2.1"]);
    }

    #[test]
    fn redirect_and_loops() {
        let (flat, problems) = eval(
            r#"
            example.com TXT "v=spf1 redirect=_spf.example.com"
            _spf.example.com TXT "v=spf1 ip4:192.0.2.1 include:loop.example ~all"
            loop.example TXT "v=spf1 include:_spf.example.com"
            "#,
            "example.com",
        );
        assert_eq!(flat.all, Some(Qualifier::SoftFail));
        assert_eq!(prefixes(&flat), ["192.0.2.1"]);
        assert!(problems.iter().any(|p| p.message.contains("loop")));
    }

    #[test]
    fn multiple_records_are_an_error() {
        let (_, problems) = eval(
            r#"
            example.com TXT "v=spf1 -all"
            example.com TXT "v=spf1 ~all"
            "#,
            "example.com",
        );
        assert!(problems[0].message.contains("2 SPF records"));
    }
}
