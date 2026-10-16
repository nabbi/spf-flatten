// SPDX-License-Identifier: GPL-3.0-or-later
//! Property tests run by `cargo test`. The libFuzzer targets in fuzz/ check
//! the same promises over arbitrary bytes for longer runs.

use proptest::prelude::*;
use spf_flatten::config::Config;
use spf_flatten::dns::StaticDns;
use spf_flatten::eval::Evaluator;
use spf_flatten::flatten::{pack, verify};
use spf_flatten::output::split_strings;
use spf_flatten::spf::Record;

fn ip4() -> impl Strategy<Value = String> {
    (any::<[u8; 4]>(), 8u8..=32).prop_map(|(a, len)| {
        let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
        let addr = std::net::Ipv4Addr::from(u32::from_be_bytes(a) & mask);
        format!("ip4:{addr}/{len}")
    })
}

fn ip6() -> impl Strategy<Value = String> {
    (any::<u128>(), 16u8..=128).prop_map(|(a, len)| {
        let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
        format!("ip6:{}/{len}", std::net::Ipv6Addr::from(a & mask))
    })
}

fn term() -> impl Strategy<Value = String> {
    let qualifier = prop::sample::select(vec!["", "+", "-", "~", "?"]);
    let domain = prop::sample::select(vec![
        "example.com",
        "_spf.Example.COM.",
        "%{i}._spf.example.com",
        "%{ir}.%{v}._spf.%{d2}",
        "%{l1r-}.x.example",
    ]);
    let mech = prop_oneof![
        Just("all".to_string()),
        ip4(),
        ip6(),
        domain.clone().prop_map(|d| format!("include:{d}")),
        domain.clone().prop_map(|d| format!("exists:{d}")),
        (
            prop::sample::select(vec!["a", "mx"]),
            prop::option::of(domain.clone()),
            prop::option::of(0u8..=32),
            prop::option::of(0u8..=128)
        )
            .prop_map(|(m, d, v4, v6)| {
                let mut s = m.to_string();
                if let Some(d) = d {
                    s += &format!(":{d}");
                }
                if let Some(n) = v4 {
                    s += &format!("/{n}");
                }
                if let Some(n) = v6 {
                    s += &format!("//{n}");
                }
                s
            }),
        prop::option::of(domain).prop_map(|d| d.map_or("ptr".into(), |d| format!("ptr:{d}"))),
    ];
    (qualifier, mech).prop_map(|(q, m)| format!("{q}{m}"))
}

proptest! {
    /// Any record built from valid terms parses, and prints as a record that
    /// parses back to the same thing.
    #[test]
    fn record_display_round_trips(terms in prop::collection::vec(term(), 0..20)) {
        let text = format!("v=spf1 {}", terms.join(" "));
        let record = Record::parse(&text).unwrap();
        let shown = record.to_string();
        prop_assert_eq!(Record::parse(&shown).unwrap(), record);
    }

    /// Whatever the providers publish and however tight the budgets, a plan
    /// that `pack` accepts passes `verify` and fits its limits.
    #[test]
    fn packed_plans_verify(
        providers in prop::collection::vec(
            (prop::collection::vec(prop_oneof![ip4(), ip6()], 0..60), any::<bool>()),
            1..6,
        ),
        exists_live in any::<bool>(),
        max_lookups in 1usize..=10,
        max_record_bytes in 100usize..=1000,
        apex_ips in any::<bool>(),
        policy in prop::sample::select(vec!["-all", "~all", "?all"]),
        widen_ipv4 in prop::option::of(16u8..=32),
    ) {
        let mut dns = StaticDns::new();
        let mut text = format!(
            "domain = \"example.com\"\npolicy = \"{policy}\"\nmax_lookups = {max_lookups}\n\
             max_record_bytes = {max_record_bytes}\napex_ips = {apex_ips}\nheadroom = 0\n"
        );
        // Widening rounds flattened prefixes only, so it can't be checked
        // against kept sources; keep sources only without it.
        if let Some(n) = widen_ipv4 {
            text += &format!("widen_ipv4 = {n}\n");
        }
        for (i, (nets, keep)) in providers.iter().enumerate() {
            let name = format!("p{i}.provider.test");
            dns.add_txt(&name, &format!("v=spf1 {} ~all", nets.join(" ")));
            let keep = *keep && widen_ipv4.is_none();
            text += &format!("[[source]]\ninclude = \"{name}\"\nkeep = {keep}\n");
        }
        if exists_live {
            text += "[[source]]\nexists = \"%{i}._spf.live.test\"\n";
        }
        let cfg = Config::parse(&text).unwrap();

        let mut ev = Evaluator::new(&dns);
        let flat = ev.evaluate_terms(&cfg.domain, &cfg.terms, &cfg.keep);
        prop_assert!(!ev.has_errors(), "{:?}", ev.problems);
        let Ok(plan) = pack(&cfg, &flat) else {
            return Ok(());
        };
        let expected = Evaluator::new(&dns).evaluate_terms(&cfg.domain, &cfg.terms, &[]);
        let problems = verify(&cfg, &plan, &expected, &dns);
        prop_assert!(problems.is_empty(), "{:#?}\n{:#?}", problems, plan.records);
        prop_assert!(plan.lookups <= cfg.max_lookups);
        for r in &plan.records {
            prop_assert!(r.value.len() <= cfg.max_record_bytes);
            prop_assert_eq!(split_strings(&r.value).concat(), r.value.clone());
        }
    }
}
