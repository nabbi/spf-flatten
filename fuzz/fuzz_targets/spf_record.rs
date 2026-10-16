// SPDX-License-Identifier: GPL-3.0-or-later
//! Any text: parsing never panics, and a parsed record prints as text that
//! parses back to the same record and prints identically.
#![no_main]

use libfuzzer_sys::fuzz_target;
use spf_flatten::spf::{self, Record, Term};

fuzz_target!(|text: &str| {
    for word in text.split(' ') {
        if let Ok(term) = Term::parse(word) {
            let shown = term.to_string();
            assert_eq!(
                Term::parse(&shown).as_ref(),
                Ok(&term),
                "{word:?} -> {shown:?}"
            );
        }
    }
    let _ = spf::domain_spec(text);
    let _ = spf::uses_current_domain(text);

    let Ok(record) = Record::parse(text) else {
        return;
    };
    assert!(spf::is_spf(text));
    let shown = record.to_string();
    let again = Record::parse(&shown).unwrap_or_else(|e| panic!("{text:?} -> {shown:?}: {e}"));
    assert_eq!(again, record, "{text:?} -> {shown:?}");
    assert_eq!(again.to_string(), shown);
});
