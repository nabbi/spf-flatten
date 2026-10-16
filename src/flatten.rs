// SPDX-License-Identifier: GPL-3.0-or-later
//! Turn an evaluated config into a chain of TXT records, then check the result
//! by evaluating it as if it were published.

use route_summarization::{Aggregator, Family, Prefix, Range};
use serde::Serialize;

use crate::config::Config;
use crate::dns::{Dns, Overlay};
use crate::eval::{Evaluator, Flat, Live, MAX_VOIDS, Problem, Severity};
use crate::spf::Qualifier;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TxtRecord {
    pub name: String,
    pub value: String,
}

/// The flattened records, apex first.
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub records: Vec<TxtRecord>,
    pub lookups: usize,
    pub prefixes: usize,
    pub live: Vec<Live>,
}

/// The minimal CIDR list for `ranges` minus `exclude`.
pub fn summarize(ranges: &[Range], exclude: &[Range]) -> Vec<Prefix> {
    let mut agg = Aggregator::new();
    ranges.iter().for_each(|r| agg.add(*r));
    exclude.iter().for_each(|r| agg.exclude(*r));
    agg.summarize()
}

pub fn ip_term(p: &Prefix) -> String {
    match p.family() {
        Family::V4 => format!("ip4:{p}"),
        Family::V6 => format!("ip6:{p}"),
    }
}

/// Bytes `tokens` add to a record, a space before each.
fn width<S: AsRef<str>>(tokens: &[S]) -> usize {
    tokens.iter().map(|t| 1 + t.as_ref().len()).sum()
}

/// The longest prefix of `tokens` that fits in `room` bytes.
fn fitting<S: AsRef<str>>(tokens: &[S], room: usize) -> usize {
    let mut used = 0;
    tokens
        .iter()
        .take_while(|t| {
            used += 1 + t.as_ref().len();
            used <= room
        })
        .count()
}

/// Pack the flattened addresses and live terms into records within the size
/// and lookup budgets.
pub fn pack(cfg: &Config, flat: &Flat) -> Result<Plan, String> {
    let prefixes = summarize(&flat.pass, &cfg.exclude);
    let ips: Vec<String> = prefixes.iter().map(ip_term).collect();

    let mut live: Vec<Live> = Vec::new();
    for l in &flat.live {
        if !live.iter().any(|x| x.term == l.term) {
            live.push(l.clone());
        }
    }
    let live_terms: Vec<&str> = live.iter().map(|l| l.term.as_str()).collect();
    let policy = cfg.policy_term();
    let max = cfg.max_record_bytes;
    let fixed = "v=spf1".len() + width(&live_terms) + 1 + policy.len();
    let chain_room = max - "v=spf1".len();

    // Try 0, 1, 2... chained records: reserve room in the apex for that many
    // includes, fill the apex, and see whether the rest fits in that many records.
    for n in 0..=ips.len() {
        let mut includes: Vec<String> = (1..=n)
            .map(|i| format!("include:{}", cfg.chain_name(i)))
            .collect();
        let Some(room) = max.checked_sub(fixed + width(&includes)) else {
            return Err(format!(
                "the apex record alone (kept terms, {n} includes and policy) is over max_record_bytes {max}"
            ));
        };
        let in_apex = if cfg.apex_ips { fitting(&ips, room) } else { 0 };
        let mut chain: Vec<&[String]> = Vec::new();
        let mut rest = &ips[in_apex..];
        while !rest.is_empty() {
            let take = fitting(rest, chain_room).max(1);
            chain.push(&rest[..take]);
            rest = &rest[take..];
        }
        if chain.len() > n {
            continue;
        }
        includes.truncate(chain.len());

        let apex: Vec<&str> = ips[..in_apex]
            .iter()
            .map(String::as_str)
            .chain(live_terms.iter().copied())
            .chain(includes.iter().map(String::as_str))
            .chain([policy.as_str()])
            .collect();
        let mut records = vec![TxtRecord {
            name: cfg.domain.clone(),
            value: format!("v=spf1 {}", apex.join(" ")),
        }];
        for (i, tokens) in chain.iter().enumerate() {
            records.push(TxtRecord {
                name: cfg.chain_name(i + 1),
                value: format!("v=spf1 {}", tokens.join(" ")),
            });
        }

        let lookups = live.iter().map(|l| l.lookups).sum::<usize>() + chain.len();
        if lookups > cfg.max_lookups {
            return Err(format!(
                "the flattened record needs {lookups} lookups ({} from kept terms, {} chained records), over max_lookups {}; \
                 keep fewer sources or raise max_record_bytes",
                lookups - chain.len(),
                chain.len(),
                cfg.max_lookups
            ));
        }
        return Ok(Plan {
            records,
            lookups,
            prefixes: prefixes.len(),
            live,
        });
    }
    unreachable!("n = ips.len() always fits: one address per record")
}

/// How two evaluated SPF policies differ.
#[derive(Debug, Default, Serialize)]
pub struct Comparison {
    /// In `want` but not `have`.
    pub missing: Vec<String>,
    /// In `have` but not `want`.
    pub extra: Vec<String>,
    pub missing_live: Vec<String>,
    pub extra_live: Vec<String>,
    pub all: Option<(String, String)>,
}

impl Comparison {
    pub fn is_empty(&self) -> bool {
        self.missing.is_empty()
            && self.extra.is_empty()
            && self.missing_live.is_empty()
            && self.extra_live.is_empty()
            && self.all.is_none()
    }
}

fn all_text(q: Option<Qualifier>) -> String {
    q.map_or("(none)".into(), |q| format!("{}all", q.prefix()))
}

/// Compare what two policies authorize, address by address.
pub fn compare(want: &Flat, want_exclude: &[Range], have: &Flat) -> Comparison {
    let want_pass: Vec<Range> = summarize(&want.pass, want_exclude)
        .iter()
        .map(Prefix::range)
        .collect();
    let have_pass: Vec<Range> = summarize(&have.pass, &[])
        .iter()
        .map(Prefix::range)
        .collect();
    let terms = |f: &Flat| -> Vec<String> { f.live.iter().map(|l| l.term.clone()).collect() };
    let (want_live, have_live) = (terms(want), terms(have));
    Comparison {
        missing: summarize(&want_pass, &have_pass)
            .iter()
            .map(ip_term)
            .collect(),
        extra: summarize(&have_pass, &want_pass)
            .iter()
            .map(ip_term)
            .collect(),
        missing_live: want_live
            .iter()
            .filter(|t| !have_live.contains(t))
            .cloned()
            .collect(),
        extra_live: have_live
            .iter()
            .filter(|t| !want_live.contains(t))
            .cloned()
            .collect(),
        all: (want.all != have.all).then(|| (all_text(want.all), all_text(have.all))),
    }
}

/// Evaluate the planned records over live DNS and check they authorize
/// exactly what `expected` (the config, fully flattened) does, within limits.
pub fn verify(cfg: &Config, plan: &Plan, expected: &Flat, dns: &dyn Dns) -> Vec<Problem> {
    let overlay = Overlay::new(
        dns,
        plan.records
            .iter()
            .map(|r| (r.name.clone(), r.value.clone())),
    );
    let mut ev = Evaluator::new(&overlay);
    let actual = ev.evaluate_domain(&cfg.domain);
    let mut problems: Vec<Problem> = ev
        .problems
        .into_iter()
        .filter(|p| p.severity == Severity::Error)
        .map(|mut p| {
            p.message = format!("in the generated records: {}", p.message);
            p
        })
        .collect();
    let mut fail = |message: String| {
        problems.push(Problem {
            severity: Severity::Error,
            path: String::new(),
            message: format!("verification: {message}"),
        })
    };
    let Some(actual) = actual else {
        fail("the generated apex record could not be evaluated".into());
        return problems;
    };

    if actual.lookups != plan.lookups {
        fail(format!(
            "expected {} lookups, evaluation counted {}",
            plan.lookups, actual.lookups
        ));
    }
    if actual.lookups > cfg.max_lookups {
        fail(format!(
            "{} lookups, over max_lookups {}",
            actual.lookups, cfg.max_lookups
        ));
    }
    if actual.voids > MAX_VOIDS {
        fail(format!("{} void lookups, over {MAX_VOIDS}", actual.voids));
    }
    for r in &plan.records {
        if r.value.len() > cfg.max_record_bytes {
            fail(format!("{} is {} bytes", r.name, r.value.len()));
        }
    }
    // The config's sources carry no `all`; the policy is added when packing.
    let expected = Flat {
        all: Some(cfg.policy),
        ..expected.clone()
    };
    let diff = compare(&expected, &cfg.exclude, &actual);
    if !diff.missing.is_empty() {
        fail(format!("does not authorize {}", diff.missing.join(" ")));
    }
    if !diff.extra.is_empty() {
        fail(format!(
            "also authorizes {} (an exclude overlapping a kept source?)",
            diff.extra.join(" ")
        ));
    }
    if !diff.missing_live.is_empty() || !diff.extra_live.is_empty() {
        fail(format!(
            "kept terms differ: missing [{}], extra [{}]",
            diff.missing_live.join(" "),
            diff.extra_live.join(" ")
        ));
    }
    if let Some((want, have)) = diff.all {
        fail(format!("policy is {have}, expected {want}"));
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::StaticDns;

    fn config(extra: &str, sources: &str) -> Config {
        Config::parse(&format!(
            "domain = \"example.com\"\npolicy = \"-all\"\n{extra}\n{sources}"
        ))
        .unwrap()
    }

    fn run(cfg: &Config, dns: &StaticDns) -> (Plan, Vec<Problem>) {
        let mut ev = Evaluator::new(dns);
        let flat = ev.evaluate_terms(&cfg.domain, &cfg.terms, &cfg.keep);
        assert!(!ev.has_errors(), "{:?}", ev.problems);
        let plan = pack(cfg, &flat).unwrap();
        let mut ev = Evaluator::new(dns);
        let expected = ev.evaluate_terms(&cfg.domain, &cfg.terms, &[]);
        let problems = verify(cfg, &plan, &expected, dns);
        (plan, problems)
    }

    /// A provider record listing `n` /24s in 10.x.y.0, none adjacent.
    fn big_provider(dns: &mut StaticDns, name: &str, base: u8, n: usize) {
        let ips: Vec<String> = (0..n)
            .map(|i| format!("ip4:10.{base}.{}.0/24", i * 2))
            .collect();
        dns.add_txt(name, &format!("v=spf1 {} ~all", ips.join(" ")));
    }

    #[test]
    fn small_set_fits_in_apex() {
        let mut dns = StaticDns::new();
        dns.add_txt(
            "p.example",
            "v=spf1 ip4:192.0.2.0/25 ip4:192.0.2.128/25 ~all",
        );
        let cfg = config("", "[[source]]\ninclude = \"p.example\"\n");
        let (plan, problems) = run(&cfg, &dns);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(plan.records.len(), 1);
        assert_eq!(plan.records[0].value, "v=spf1 ip4:192.0.2.0/24 -all");
        assert_eq!(plan.lookups, 0);
    }

    #[test]
    fn large_set_chains_within_budget() {
        let mut dns = StaticDns::new();
        big_provider(&mut dns, "a.example", 1, 60);
        big_provider(&mut dns, "b.example", 2, 60);
        dns.add_txt("kept.example", "v=spf1 ip4:203.0.113.0/24 -all");
        let cfg = config(
            "",
            "[[source]]\ninclude = \"a.example\"\n\
             [[source]]\ninclude = \"b.example\"\n\
             [[source]]\ninclude = \"kept.example\"\nkeep = true\n",
        );
        let (plan, problems) = run(&cfg, &dns);
        assert!(problems.is_empty(), "{problems:?}");
        assert!(plan.records.len() > 2);
        for r in &plan.records {
            assert!(
                r.value.len() <= 450,
                "{} is {} bytes",
                r.name,
                r.value.len()
            );
        }
        assert_eq!(plan.lookups, 1 + plan.records.len() - 1);
        let apex = &plan.records[0].value;
        assert!(apex.contains("include:kept.example"));
        assert!(apex.contains("include:_spf1.example.com"));
        assert!(apex.ends_with(" -all"));
        assert_eq!(plan.prefixes, 120);
    }

    #[test]
    fn exclude_and_no_apex_ips() {
        let mut dns = StaticDns::new();
        dns.add_txt("p.example", "v=spf1 ip4:192.0.2.0/24 ~all");
        let cfg = config(
            "apex_ips = false\nexclude = [\"192.0.2.0/25\"]",
            "[[source]]\ninclude = \"p.example\"\n",
        );
        let (plan, problems) = run(&cfg, &dns);
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(
            plan.records[0].value,
            "v=spf1 include:_spf1.example.com -all"
        );
        assert_eq!(plan.records[1].value, "v=spf1 ip4:192.0.2.128/25");
    }

    #[test]
    fn over_lookup_budget_is_an_error() {
        let mut dns = StaticDns::new();
        let mut sources = String::new();
        for i in 0..6 {
            let name = format!("p{i}.example");
            dns.add_txt(&name, "v=spf1 include:q.example ~all");
            sources.push_str(&format!("[[source]]\ninclude = \"{name}\"\nkeep = true\n"));
        }
        dns.add_txt("q.example", "v=spf1 ip4:192.0.2.1 ~all");
        let cfg = config("", &sources);
        let mut ev = Evaluator::new(&dns);
        let flat = ev.evaluate_terms(&cfg.domain, &cfg.terms, &cfg.keep);
        let err = pack(&cfg, &flat).unwrap_err();
        assert!(err.contains("needs 12 lookups"), "{err}");
    }
}
