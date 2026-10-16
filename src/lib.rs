// SPDX-License-Identifier: GPL-3.0-or-later
//! Flatten SPF records to stay within the RFC 7208 lookup and size limits.
//!
//! [`config::Config`] lists the sources a domain needs. [`eval::Evaluator`]
//! resolves them as a receiver would, [`flatten::pack`] writes the resulting
//! addresses into a chain of TXT records, and [`flatten::verify`] evaluates
//! those records as if published to confirm they authorize exactly the same
//! senders within the limits.

pub mod config;
pub mod dns;
pub mod eval;
pub mod flatten;
pub mod import;
pub mod output;
pub mod spf;
