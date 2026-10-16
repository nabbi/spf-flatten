// SPDX-License-Identifier: GPL-3.0-or-later
//! Any zone fixture: parsing never panics, and evaluating every name in it
//! terminates without panicking, whatever loops or garbage the records hold.
#![no_main]

use libfuzzer_sys::fuzz_target;
use spf_flatten::advice;
use spf_flatten::dns::StaticDns;
use spf_flatten::eval::{Evaluator, MAX_LOOKUPS};
use spf_flatten::import;
use spf_flatten::spf::Record;

fuzz_target!(|text: &str| {
    let Ok(dns) = StaticDns::parse(text) else {
        return;
    };
    let mut names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| !n.starts_with([';', '#']))
        .collect();
    names.dedup();
    for name in names.into_iter().take(8) {
        let mut ev = Evaluator::new(&dns);
        if let Some(flat) = ev.evaluate_domain(name) {
            // Evaluation goes past the limit to report it, but is capped (eval::MAX_RECORDS).
            assert!(
                flat.lookups <= 2000 * MAX_LOOKUPS,
                "{} lookups",
                flat.lookups
            );
        }
        let _ = import::import(name, &dns);
        if let (Some(record), _) = Evaluator::new(&dns).fetch(name) {
            let _ = advice::own_hosts(name, &record, &dns);
            let _ = Record::parse(&record.to_string()).unwrap();
        }
    }
});
