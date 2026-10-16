// SPDX-License-Identifier: GPL-3.0-or-later
//! TXT values split into character-strings concatenate back exactly, and no
//! string is over 255 bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use spf_flatten::output::split_strings;

fuzz_target!(|value: &str| {
    let parts = split_strings(value);
    assert!(!parts.is_empty());
    assert!(parts.iter().all(|p| p.len() <= 255), "{parts:?}");
    assert_eq!(parts.concat(), value);
});
