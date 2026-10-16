// SPDX-License-Identifier: GPL-3.0-or-later
//! The input file: the domain, its policy, and the sources it needs.

use route_summarization::{Range, parse_entry};
use serde::Deserialize;

use crate::eval::MAX_LOOKUPS;
use crate::spf::{self, Mechanism, Qualifier, Term};

pub const DEFAULT_MAX_RECORD_BYTES: usize = 450;
pub const DEFAULT_CHAIN_PREFIX: &str = "_spf";
pub const DEFAULT_TTL: u32 = 3600;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    domain: String,
    policy: String,
    #[serde(default = "default_max_lookups")]
    max_lookups: usize,
    #[serde(default = "default_max_record_bytes")]
    max_record_bytes: usize,
    #[serde(default = "default_chain_prefix")]
    chain_prefix: String,
    #[serde(default = "default_ttl")]
    ttl: u32,
    #[serde(default = "default_true")]
    apex_ips: bool,
    #[serde(default)]
    exclude: Vec<String>,
    widen_ipv4: Option<u8>,
    widen_ipv6: Option<u8>,
    #[serde(default)]
    strategy: Strategy,
    headroom: Option<usize>,
    #[serde(default, rename = "source")]
    sources: Vec<Source>,
}

fn default_max_lookups() -> usize {
    MAX_LOOKUPS
}
fn default_max_record_bytes() -> usize {
    DEFAULT_MAX_RECORD_BYTES
}
fn default_chain_prefix() -> String {
    DEFAULT_CHAIN_PREFIX.into()
}
fn default_ttl() -> u32 {
    DEFAULT_TTL
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
    }
}

/// One `[[source]]` table. Exactly one mechanism key must be set.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    include: Option<String>,
    a: Option<String>,
    mx: Option<String>,
    ptr: Option<String>,
    exists: Option<String>,
    ip4: Option<OneOrMany>,
    ip6: Option<OneOrMany>,
    #[serde(default)]
    keep: bool,
    #[allow(dead_code)]
    note: Option<String>,
}

impl Source {
    /// The SPF terms this source stands for, as text.
    fn terms(self) -> Result<Vec<String>, String> {
        // `a`, `mx` and `ptr` take "@" for the domain itself, optionally with CIDR lengths.
        let host = |mech: &str, v: String| match v.strip_prefix('@') {
            Some(rest) => format!("{mech}{rest}"),
            None => format!("{mech}:{v}"),
        };
        let mut kinds: Vec<Vec<String>> = Vec::new();
        if let Some(d) = self.include {
            kinds.push(vec![format!("include:{d}")]);
        }
        if let Some(v) = self.a {
            kinds.push(vec![host("a", v)]);
        }
        if let Some(v) = self.mx {
            kinds.push(vec![host("mx", v)]);
        }
        if let Some(v) = self.ptr {
            kinds.push(vec![host("ptr", v)]);
        }
        if let Some(d) = self.exists {
            kinds.push(vec![format!("exists:{d}")]);
        }
        for (mech, list) in [("ip4", self.ip4), ("ip6", self.ip6)] {
            if let Some(list) = list {
                let list = list.into_vec();
                if list.is_empty() {
                    return Err(format!("{mech} list is empty"));
                }
                kinds.push(list.into_iter().map(|a| format!("{mech}:{a}")).collect());
            }
        }
        match kinds.len() {
            1 => Ok(kinds.pop().unwrap()),
            0 => Err("needs one of include, a, mx, ptr, exists, ip4, ip6".into()),
            _ => Err("sets more than one of include, a, mx, ptr, exists, ip4, ip6".into()),
        }
    }
}

/// How much to flatten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Strategy {
    /// Flatten every source not marked keep.
    #[default]
    Full,
    /// Flatten only as many sources as the lookup budget needs, lowest drift
    /// risk first; the rest stay live.
    Minimal,
}

/// A validated config.
#[derive(Debug, Clone)]
pub struct Config {
    pub domain: String,
    pub policy: Qualifier,
    pub max_lookups: usize,
    pub max_record_bytes: usize,
    pub chain_prefix: String,
    pub ttl: u32,
    /// Put addresses in the apex record when they fit, saving a lookup.
    pub apex_ips: bool,
    pub exclude: Vec<Range>,
    /// Round flattened prefixes longer than this out to it ("aggressive" mode).
    pub widen_ipv4: Option<u8>,
    pub widen_ipv6: Option<u8>,
    pub strategy: Strategy,
    /// Lookups to leave unused under the minimal strategy.
    pub headroom: usize,
    pub terms: Vec<Term>,
    /// Parallel to `terms`: written verbatim instead of flattened.
    pub keep: Vec<bool>,
    pub warnings: Vec<String>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        let raw: Raw = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut warnings = Vec::new();

        let domain = spf::domain_spec(&raw.domain).map_err(|e| format!("domain: {e}"))?;
        if spf::has_macro(&domain) {
            return Err("domain: macros are not allowed here".into());
        }

        let policy = match Term::parse(&raw.policy) {
            Ok(Term::Directive(Qualifier::Pass, Mechanism::All)) => {
                return Err("policy: +all authorizes everyone; use -all or ~all".into());
            }
            Ok(Term::Directive(q, Mechanism::All)) => q,
            _ => {
                return Err(format!(
                    "policy: {:?} is not -all, ~all or ?all",
                    raw.policy
                ));
            }
        };

        if !(1..=MAX_LOOKUPS).contains(&raw.max_lookups) {
            return Err(format!("max_lookups must be 1 to {MAX_LOOKUPS}"));
        }
        if !(100..=4000).contains(&raw.max_record_bytes) {
            return Err("max_record_bytes must be 100 to 4000".into());
        }
        if raw.max_record_bytes > DEFAULT_MAX_RECORD_BYTES {
            warnings.push(format!(
                "max_record_bytes {} is over {DEFAULT_MAX_RECORD_BYTES}; answers may not fit in a 512-byte UDP response (RFC 7208 §3.4)",
                raw.max_record_bytes
            ));
        }
        if raw.chain_prefix.is_empty()
            || !raw
                .chain_prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("chain_prefix must be letters, digits, '-' or '_'".into());
        }
        spf::domain_spec(&format!("{}99.{domain}", raw.chain_prefix))
            .map_err(|e| format!("chain_prefix: {e}"))?;

        let exclude = raw
            .exclude
            .iter()
            .map(|e| parse_entry(e, true).map_err(|err| format!("exclude {e:?}: {err}")))
            .collect::<Result<Vec<_>, _>>()?;

        if let Some(n) = raw.widen_ipv4
            && !(16..=32).contains(&n)
        {
            return Err("widen_ipv4 must be 16 to 32".into());
        }
        if let Some(n) = raw.widen_ipv6
            && !(32..=128).contains(&n)
        {
            return Err("widen_ipv6 must be 32 to 128".into());
        }

        // One spare lookup by default, so a provider adding a nested include
        // doesn't push a minimally flattened record straight over the limit.
        let headroom = raw.headroom.unwrap_or(usize::from(raw.max_lookups > 1));
        if headroom >= raw.max_lookups {
            return Err(format!(
                "headroom must be less than max_lookups ({})",
                raw.max_lookups
            ));
        }

        if raw.sources.is_empty() {
            return Err("no [[source]] entries".into());
        }
        let (mut terms, mut keep) = (Vec::new(), Vec::new());
        for (i, source) in raw.sources.into_iter().enumerate() {
            let n = i + 1;
            let kept = source.keep;
            for text in source.terms().map_err(|e| format!("source #{n}: {e}"))? {
                let term = Term::parse(&text).map_err(|e| format!("source #{n}: {e}"))?;
                if kept && matches!(term, Term::Directive(_, Mechanism::Ip(..))) {
                    return Err(format!("source #{n}: keep has no effect on ip4/ip6"));
                }
                if terms.contains(&term) {
                    warnings.push(format!("source #{n}: {term} is listed more than once"));
                    continue;
                }
                terms.push(term);
                keep.push(kept);
            }
        }

        Ok(Self {
            domain,
            policy,
            max_lookups: raw.max_lookups,
            max_record_bytes: raw.max_record_bytes,
            chain_prefix: raw.chain_prefix,
            ttl: raw.ttl,
            apex_ips: raw.apex_ips,
            exclude,
            widen_ipv4: raw.widen_ipv4,
            widen_ipv6: raw.widen_ipv6,
            strategy: raw.strategy,
            headroom,
            terms,
            keep,
            warnings,
        })
    }

    /// The policy as a term, e.g. `-all`.
    pub fn policy_term(&self) -> String {
        format!("{}all", self.policy.prefix())
    }

    /// Name of the `n`th chained record, counting from 1.
    pub fn chain_name(&self, n: usize) -> String {
        format!("{}{n}.{}", self.chain_prefix, self.domain)
    }
}

/// One source line for [`render`].
pub struct Entry {
    pub key: &'static str,
    pub values: Vec<String>,
    pub keep: bool,
    pub note: Option<String>,
}

/// Write a config file. `comments` go at the top.
pub fn render(domain: &str, policy: &str, entries: &[Entry], comments: &[String]) -> String {
    let q = |s: &str| toml::Value::String(s.to_string()).to_string();
    let mut out = String::new();
    for c in comments {
        out.push_str(&format!("# {c}\n"));
    }
    out.push_str(&format!(
        "\ndomain = {}\npolicy = {}\n",
        q(domain),
        q(policy)
    ));
    out.push_str(&format!(
        "\n# Defaults, shown for reference:\n\
         # max_lookups = {MAX_LOOKUPS}\n\
         # max_record_bytes = {DEFAULT_MAX_RECORD_BYTES}\n\
         # chain_prefix = {}\n\
         # ttl = {DEFAULT_TTL}\n\
         # apex_ips = true\n\
         # exclude = []\n\
         # strategy = \"full\"       # or \"minimal\": flatten only what the budget needs\n\
         # headroom = 1             # lookups minimal leaves unused\n",
        q(DEFAULT_CHAIN_PREFIX)
    ));
    for e in entries {
        out.push_str("\n[[source]]\n");
        match e.values.as_slice() {
            [one] if !e.key.starts_with("ip") => out.push_str(&format!("{} = {}\n", e.key, q(one))),
            values => {
                out.push_str(&format!("{} = [\n", e.key));
                for v in values {
                    out.push_str(&format!("    {},\n", q(v)));
                }
                out.push_str("]\n");
            }
        }
        if e.keep {
            out.push_str("keep = true\n");
        }
        if let Some(note) = &e.note {
            out.push_str(&format!("note = {}\n", q(note)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASIC: &str = r#"
        domain = "Example.com."
        policy = "-all"

        [[source]]
        include = "_spf.google.com"

        [[source]]
        mx = "@"

        [[source]]
        a = "@/24"
        keep = true

        [[source]]
        ip4 = ["192.0.2.0/24", "198.51.100.1"]
        note = "office"
    "#;

    #[test]
    fn parses_sources_in_order() {
        let cfg = Config::parse(BASIC).unwrap();
        assert_eq!(cfg.domain, "example.com");
        assert_eq!(cfg.policy, Qualifier::Fail);
        let terms: Vec<String> = cfg.terms.iter().map(|t| t.to_string()).collect();
        assert_eq!(
            terms,
            [
                "include:_spf.google.com",
                "mx",
                "a/24",
                "ip4:192.0.2.0/24",
                "ip4:198.51.100.1"
            ]
        );
        assert_eq!(cfg.keep, [false, false, true, false, false]);
        assert_eq!(cfg.chain_name(2), "_spf2.example.com");
    }

    #[test]
    fn rejects_bad_configs() {
        let base = "domain = \"example.com\"\npolicy = \"-all\"\n";
        for (body, why) in [
            (
                "[[source]]\ninclude = \"a.example\"\nmx = \"@\"\n",
                "more than one",
            ),
            ("[[source]]\nnote = \"x\"\n", "needs one of"),
            ("[[source]]\nip4 = \"10.0.0.0/33\"\n", "prefix length"),
            (
                "[[source]]\nip4 = \"10.0.0.1\"\nkeep = true\n",
                "keep has no effect",
            ),
            (
                "[[source]]\ninclude = \"x.example\"\nbogus = 1\n",
                "unknown field",
            ),
            ("", "no [[source]]"),
        ] {
            let e = Config::parse(&format!("{base}{body}")).unwrap_err();
            assert!(e.contains(why), "{body:?}: {e}");
        }
        let e = Config::parse("domain = \"example.com\"\npolicy = \"+all\"\n").unwrap_err();
        assert!(e.contains("+all"));
    }

    #[test]
    fn render_round_trips() {
        let text = render(
            "example.com",
            "~all",
            &[
                Entry {
                    key: "include",
                    values: vec!["_spf.google.com".into()],
                    keep: false,
                    note: Some("4 lookups".into()),
                },
                Entry {
                    key: "ip4",
                    values: vec!["192.0.2.1".into()],
                    keep: false,
                    note: None,
                },
                Entry {
                    key: "mx",
                    values: vec!["@".into()],
                    keep: true,
                    note: None,
                },
            ],
            &["imported".into()],
        );
        let cfg = Config::parse(&text).unwrap();
        assert_eq!(cfg.terms.len(), 3);
        assert_eq!(cfg.keep, [false, false, true]);
        assert_eq!(cfg.policy, Qualifier::SoftFail);
    }
}
