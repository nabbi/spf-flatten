// SPDX-License-Identifier: GPL-3.0-or-later
//! Any config text: parsing never panics, and an accepted config upholds the
//! invariants the rest of the program relies on.
#![no_main]

use libfuzzer_sys::fuzz_target;
use spf_flatten::config::Config;
use spf_flatten::eval::MAX_LOOKUPS;
use spf_flatten::spf::{self, Mechanism, Term};

fuzz_target!(|text: &str| {
    let Ok(cfg) = Config::parse(text) else {
        return;
    };
    assert!(!spf::has_macro(&cfg.domain));
    assert!((1..=MAX_LOOKUPS).contains(&cfg.max_lookups));
    assert!(cfg.headroom < cfg.max_lookups);
    assert!((100..=4000).contains(&cfg.max_record_bytes));
    assert!(!cfg.terms.is_empty());
    assert_eq!(cfg.terms.len(), cfg.keep.len());
    for (term, &kept) in cfg.terms.iter().zip(&cfg.keep) {
        assert!(matches!(term, Term::Directive(..)), "{term}");
        assert!(!(kept && matches!(term, Term::Directive(_, Mechanism::Ip(..)))));
    }
    // Chained record names must be valid for any chain length a plan can reach.
    for n in [1, 9, 99] {
        let name = cfg.chain_name(n);
        assert_eq!(spf::domain_spec(&name).as_deref(), Ok(name.as_str()));
    }
});
