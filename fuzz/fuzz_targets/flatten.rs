// SPDX-License-Identifier: GPL-3.0-or-later
//! The core promise, end to end: for any set of provider records and config
//! knobs, a plan that `pack` accepts passes `verify` (same senders, within the
//! lookup and size limits), and its records survive TXT string splitting.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use route_summarization::{Family, Prefix};
use spf_flatten::config::Config;
use spf_flatten::dns::StaticDns;
use spf_flatten::eval::Evaluator;
use spf_flatten::flatten::{pack, verify};
use spf_flatten::output::split_strings;
use spf_flatten::spf::Record;

#[derive(Debug, Arbitrary)]
struct Net {
    v6: bool,
    addr: u128,
    len: u8,
}

impl Net {
    fn prefix(&self) -> Prefix {
        let family = if self.v6 { Family::V6 } else { Family::V4 };
        let bits = family.bits();
        let len = self.len % (bits + 1);
        let addr = if self.v6 {
            self.addr
        } else {
            self.addr & 0xffff_ffff
        };
        let mask = if len == 0 {
            0
        } else {
            u128::MAX << (128 - u32::from(len)) >> (128 - u32::from(bits))
        };
        Prefix::new(family, addr & mask, len).expect("masked prefix")
    }

    fn term(&self) -> String {
        let p = self.prefix();
        match p.family() {
            Family::V4 => format!("ip4:{p}"),
            Family::V6 => format!("ip6:{p}"),
        }
    }
}

#[derive(Debug, Arbitrary)]
struct Provider {
    nets: Vec<Net>,
    /// One level of nesting under the provider.
    nested: Option<Vec<Net>>,
    /// Hosts behind an `a:` term in the provider record.
    hosts: Vec<u32>,
    keep: bool,
}

#[derive(Debug, Arbitrary)]
struct Input {
    providers: Vec<Provider>,
    direct: Vec<Net>,
    exclude: Vec<Net>,
    exists_live: bool,
    policy: u8,
    max_lookups: u8,
    max_record_bytes: u16,
    apex_ips: bool,
    widen_ipv4: Option<u8>,
    widen_ipv6: Option<u8>,
}

fn overlaps(a: &Prefix, b: &Prefix) -> bool {
    let (a, b) = (a.range(), b.range());
    a.family() == b.family() && a.start() <= b.end() && b.start() <= a.end()
}

fuzz_target!(|input: Input| {
    let mut dns = StaticDns::new();
    let mut sources = String::new();
    // Addresses reached only through kept sources: an exclude can't remove
    // them, and widening can't round them, so keep those apart (documented).
    let mut kept: Vec<Prefix> = Vec::new();

    for (i, p) in input.providers.iter().take(8).enumerate() {
        let name = format!("p{i}.provider.test");
        let mut terms: Vec<String> = p.nets.iter().take(80).map(Net::term).collect();
        let mut reached: Vec<Prefix> = p.nets.iter().take(80).map(Net::prefix).collect();
        if let Some(nested) = &p.nested {
            let sub = format!("n{i}.provider.test");
            let nterms: Vec<String> = nested.iter().take(40).map(Net::term).collect();
            dns.add_txt(&sub, &format!("v=spf1 {} ~all", nterms.join(" ")));
            reached.extend(nested.iter().take(40).map(Net::prefix));
            terms.push(format!("include:{sub}"));
        }
        if !p.hosts.is_empty() {
            let host = format!("h{i}.provider.test");
            for &ip in p.hosts.iter().take(5) {
                dns.add_a(&host, ip.into());
                reached.push(Prefix::new(Family::V4, ip.into(), 32).unwrap());
            }
            terms.push(format!("a:{host}"));
        }
        dns.add_txt(&name, &format!("v=spf1 {} ~all", terms.join(" ")));
        sources.push_str(&format!(
            "[[source]]\ninclude = \"{name}\"\nkeep = {}\n",
            p.keep
        ));
        if p.keep {
            kept.extend(reached);
        }
    }
    if input.exists_live {
        sources.push_str("[[source]]\nexists = \"%{i}._spf.live.test\"\n");
    }
    for (key, v6) in [("ip4", false), ("ip6", true)] {
        let list: Vec<String> = input
            .direct
            .iter()
            .take(40)
            .filter(|n| n.v6 == v6)
            .map(|n| format!("\"{}\"", n.prefix()))
            .collect();
        if !list.is_empty() {
            sources.push_str(&format!("[[source]]\n{key} = [{}]\n", list.join(", ")));
        }
    }
    if sources.is_empty() {
        return;
    }

    let widening = input.widen_ipv4.is_some() || input.widen_ipv6.is_some();
    if widening && !kept.is_empty() {
        return;
    }
    let exclude: Vec<String> = input
        .exclude
        .iter()
        .take(6)
        .map(Net::prefix)
        .filter(|e| !kept.iter().any(|k| overlaps(e, k)))
        .map(|e| format!("\"{e}\""))
        .collect();

    let mut text = format!(
        "domain = \"example.com\"\npolicy = \"{}\"\nmax_lookups = {}\nmax_record_bytes = {}\napex_ips = {}\nexclude = [{}]\n",
        ["-all", "~all", "?all"][usize::from(input.policy % 3)],
        input.max_lookups % 10 + 1,
        input.max_record_bytes % 3901 + 100,
        input.apex_ips,
        exclude.join(", "),
    );
    if let Some(n) = input.widen_ipv4 {
        text.push_str(&format!("widen_ipv4 = {}\n", n % 17 + 16));
    }
    if let Some(n) = input.widen_ipv6 {
        text.push_str(&format!("widen_ipv6 = {}\n", n % 97 + 32));
    }
    text.push_str("headroom = 0\n");
    text.push_str(&sources);

    let cfg = match Config::parse(&text) {
        Ok(cfg) => cfg,
        Err(e) => panic!("generated config rejected: {e}\n{text}"),
    };

    let mut ev = Evaluator::new(&dns);
    let flat = ev.evaluate_terms(&cfg.domain, &cfg.terms, &cfg.keep);
    assert!(!ev.has_errors(), "{:?}\n{text}", ev.problems);

    let plan = match pack(&cfg, &flat) {
        Ok(plan) => plan,
        Err(e) if e.contains("max_lookups") || e.contains("over max_record_bytes") => return,
        Err(e) => panic!("unexpected pack error: {e}\n{text}"),
    };

    let mut ev = Evaluator::new(&dns);
    let expected = ev.evaluate_terms(&cfg.domain, &cfg.terms, &[]);
    let problems = verify(&cfg, &plan, &expected, &dns);
    assert!(
        problems.is_empty(),
        "{problems:#?}\n{text}\n{:#?}",
        plan.records
    );

    assert!(plan.lookups <= cfg.max_lookups);
    for r in &plan.records {
        assert!(
            r.value.len() <= cfg.max_record_bytes,
            "{} is {} bytes",
            r.name,
            r.value.len()
        );
        Record::parse(&r.value).unwrap_or_else(|e| panic!("{}: {e}", r.value));
        assert_eq!(split_strings(&r.value).concat(), r.value);
    }
});
