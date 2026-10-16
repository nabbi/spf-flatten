// SPDX-License-Identifier: GPL-3.0-or-later
//! SPF record syntax (RFC 7208 §4.6, §5, §6, §7): parsing and display.

use std::fmt;

use route_summarization::{Family, Range, parse_entry};

/// Why a record or term was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{term:?}: {reason}")]
pub struct ParseError {
    pub term: String,
    pub reason: String,
}

fn err(term: &str, reason: impl Into<String>) -> ParseError {
    ParseError {
        term: term.to_string(),
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Qualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

impl Qualifier {
    /// The prefix written before a mechanism; empty for the default `+`.
    pub fn prefix(self) -> &'static str {
        match self {
            Qualifier::Pass => "",
            Qualifier::Fail => "-",
            Qualifier::SoftFail => "~",
            Qualifier::Neutral => "?",
        }
    }
}

/// The domain and dual CIDR lengths of an `a` or `mx` mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct HostSpec {
    /// `None` means the current domain.
    pub domain: Option<String>,
    pub v4: Option<u8>,
    pub v6: Option<u8>,
}

impl fmt::Display for HostSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(d) = &self.domain {
            write!(f, ":{d}")?;
        }
        if let Some(n) = self.v4 {
            write!(f, "/{n}")?;
        }
        if let Some(n) = self.v6 {
            write!(f, "//{n}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Mechanism {
    All,
    Include(String),
    A(HostSpec),
    Mx(HostSpec),
    /// `None` means the current domain.
    Ptr(Option<String>),
    /// The address text as written, and the range it covers.
    Ip(Family, String, Range),
    Exists(String),
}

impl Mechanism {
    /// True for the mechanisms that count against the 10-lookup limit.
    pub fn is_dns(&self) -> bool {
        !matches!(self, Mechanism::All | Mechanism::Ip(..))
    }

    /// The domain-spec this mechanism queries, if it names one.
    pub fn domain_spec(&self) -> Option<&str> {
        match self {
            Mechanism::Include(d) | Mechanism::Exists(d) => Some(d),
            Mechanism::A(h) | Mechanism::Mx(h) => h.domain.as_deref(),
            Mechanism::Ptr(d) => d.as_deref(),
            Mechanism::All | Mechanism::Ip(..) => None,
        }
    }
}

impl fmt::Display for Mechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mechanism::All => f.write_str("all"),
            Mechanism::Include(d) => write!(f, "include:{d}"),
            Mechanism::A(h) => write!(f, "a{h}"),
            Mechanism::Mx(h) => write!(f, "mx{h}"),
            Mechanism::Ptr(None) => f.write_str("ptr"),
            Mechanism::Ptr(Some(d)) => write!(f, "ptr:{d}"),
            Mechanism::Ip(Family::V4, text, _) => write!(f, "ip4:{text}"),
            Mechanism::Ip(Family::V6, text, _) => write!(f, "ip6:{text}"),
            Mechanism::Exists(d) => write!(f, "exists:{d}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Term {
    Directive(Qualifier, Mechanism),
    Redirect(String),
    Exp(String),
    /// Unrecognized modifiers are ignored by receivers (§6).
    Unknown(String, String),
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Term::Directive(q, m) => write!(f, "{}{m}", q.prefix()),
            Term::Redirect(d) => write!(f, "redirect={d}"),
            Term::Exp(d) => write!(f, "exp={d}"),
            Term::Unknown(n, v) => write!(f, "{n}={v}"),
        }
    }
}

impl Term {
    /// Parse one space-separated term.
    pub fn parse(word: &str) -> Result<Self, ParseError> {
        if let Some((name, value)) = word.split_once('=')
            && is_modifier_name(name)
        {
            let lower = name.to_ascii_lowercase();
            return match lower.as_str() {
                "redirect" => Ok(Term::Redirect(
                    domain_spec(value).map_err(|r| err(word, r))?,
                )),
                "exp" => Ok(Term::Exp(domain_spec(value).map_err(|r| err(word, r))?)),
                _ => {
                    validate_macro_string(value).map_err(|r| err(word, r))?;
                    Ok(Term::Unknown(name.to_string(), value.to_string()))
                }
            };
        }

        let (qualifier, rest) = match word.as_bytes().first() {
            Some(b'+') => (Qualifier::Pass, &word[1..]),
            Some(b'-') => (Qualifier::Fail, &word[1..]),
            Some(b'~') => (Qualifier::SoftFail, &word[1..]),
            Some(b'?') => (Qualifier::Neutral, &word[1..]),
            _ => (Qualifier::Pass, word),
        };
        let (name, arg) = rest.split_at(rest.find([':', '/']).unwrap_or(rest.len()));
        let e = |r: String| err(word, r);
        let mechanism = match name.to_ascii_lowercase().as_str() {
            "all" if arg.is_empty() => Mechanism::All,
            "all" => return Err(err(word, "\"all\" takes no arguments")),
            "include" => Mechanism::Include(required_domain(arg).map_err(e)?),
            "exists" => Mechanism::Exists(required_domain(arg).map_err(e)?),
            "a" => Mechanism::A(host_spec(arg).map_err(e)?),
            "mx" => Mechanism::Mx(host_spec(arg).map_err(e)?),
            "ptr" if arg.is_empty() => Mechanism::Ptr(None),
            "ptr" => Mechanism::Ptr(Some(required_domain(arg).map_err(e)?)),
            "ip4" => ip(arg, Family::V4).map_err(e)?,
            "ip6" => ip(arg, Family::V6).map_err(e)?,
            _ => return Err(err(word, "unknown mechanism")),
        };
        Ok(Term::Directive(qualifier, mechanism))
    }
}

/// A parsed `v=spf1` record.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Record {
    pub terms: Vec<Term>,
}

impl Record {
    pub fn parse(txt: &str) -> Result<Self, ParseError> {
        if !is_spf(txt) {
            return Err(err(txt, "not an SPF record (must start with \"v=spf1\")"));
        }
        let (mut redirect, mut exp) = (false, false);
        let mut terms = Vec::new();
        for word in txt[6..].split(' ').filter(|w| !w.is_empty()) {
            let term = Term::parse(word)?;
            let seen = match term {
                Term::Redirect(_) => &mut redirect,
                Term::Exp(_) => &mut exp,
                _ => {
                    terms.push(term);
                    continue;
                }
            };
            if std::mem::replace(seen, true) {
                return Err(err(word, "modifier may appear only once"));
            }
            terms.push(term);
        }
        Ok(Self { terms })
    }

    /// The qualifier of the `all` mechanism, if present.
    pub fn all(&self) -> Option<Qualifier> {
        self.terms.iter().find_map(|t| match t {
            Term::Directive(q, Mechanism::All) => Some(*q),
            _ => None,
        })
    }

    pub fn redirect(&self) -> Option<&str> {
        self.terms.iter().find_map(|t| match t {
            Term::Redirect(d) => Some(d.as_str()),
            _ => None,
        })
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("v=spf1")?;
        for t in &self.terms {
            write!(f, " {t}")?;
        }
        Ok(())
    }
}

/// True if a TXT string is an SPF record: `v=spf1` alone or followed by a space (§4.5).
pub fn is_spf(txt: &str) -> bool {
    let b = txt.as_bytes();
    b.len() >= 6 && b[..6].eq_ignore_ascii_case(b"v=spf1") && (b.len() == 6 || b[6] == b' ')
}

/// True if a domain-spec contains macros, so it can only be resolved per message.
pub fn has_macro(spec: &str) -> bool {
    spec.contains('%')
}

/// True if a domain-spec's meaning depends on the current domain (`%{d}`, and
/// `%{p}`, which is validated against it), so it cannot be moved into another record.
pub fn uses_current_domain(spec: &str) -> bool {
    spec.as_bytes()
        .windows(3)
        .any(|w| w[0] == b'%' && w[1] == b'{' && matches!(w[2].to_ascii_lowercase(), b'd' | b'p'))
}

fn is_modifier_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn required_domain(arg: &str) -> Result<String, String> {
    match arg.strip_prefix(':') {
        Some(spec) => domain_spec(spec),
        None => Err("requires \":domain\"".into()),
    }
}

fn host_spec(arg: &str) -> Result<HostSpec, String> {
    let (rest, v6) = match arg.rfind("//") {
        Some(i) => (&arg[..i], Some(cidr_len(&arg[i + 2..], 128)?)),
        None => (arg, None),
    };
    let (rest, v4) = match rest.rfind('/') {
        Some(i) if !rest[i + 1..].contains(['.', ':', '%']) => {
            (&rest[..i], Some(cidr_len(&rest[i + 1..], 32)?))
        }
        _ => (rest, None),
    };
    let domain = match rest {
        "" => None,
        _ => Some(required_domain(rest)?),
    };
    Ok(HostSpec { domain, v4, v6 })
}

/// A CIDR length: plain decimal, no leading zeros, at most `max`.
fn cidr_len(s: &str, max: u8) -> Result<u8, String> {
    let bad = || format!("invalid CIDR length \"/{s}\"");
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return Err(bad());
    }
    s.parse::<u8>().ok().filter(|&n| n <= max).ok_or_else(bad)
}

fn ip(arg: &str, family: Family) -> Result<Mechanism, String> {
    let value = arg.strip_prefix(':').ok_or("requires \":address\"")?;
    if value.contains('-') {
        return Err("address ranges are not valid in SPF".into());
    }
    let range = parse_entry(value, false).map_err(|e| e.to_string())?;
    if range.family() != family {
        return Err("address family does not match the mechanism".into());
    }
    Ok(Mechanism::Ip(family, value.to_ascii_lowercase(), range))
}

/// Validate a domain-spec (§7.1). Literal domains are lowercased and lose any trailing dot.
pub fn domain_spec(spec: &str) -> Result<String, String> {
    if spec.is_empty() {
        return Err("empty domain".into());
    }
    if has_macro(spec) {
        validate_macro_string(spec)?;
        return Ok(spec.to_string());
    }
    let d = spec.strip_suffix('.').unwrap_or(spec);
    let labels: Vec<&str> = d.split('.').collect();
    let label_ok = |l: &&str| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if d.len() > 253 || labels.len() < 2 || !labels.iter().all(label_ok) {
        return Err(format!("invalid domain \"{spec}\""));
    }
    Ok(d.to_ascii_lowercase())
}

/// Check macro-string syntax (§7.1): `%%`, `%_`, `%-` or
/// `%{` letter [digits] [`r`] [delimiters] `}`, other characters visible ASCII.
fn validate_macro_string(s: &str) -> Result<(), String> {
    let bad = || format!("invalid macro in \"{s}\"");
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if !('\x21'..='\x7e').contains(&c) {
            return Err(format!("invalid character in \"{s}\""));
        }
        if c != '%' {
            continue;
        }
        match chars.next() {
            Some('%' | '_' | '-') => {}
            Some('{') => {
                let body: String = chars.by_ref().take_while(|&c| c != '}').collect();
                let mut b = body.chars().peekable();
                if !b
                    .next()
                    .is_some_and(|l| "slodiphcrtv".contains(l.to_ascii_lowercase()))
                {
                    return Err(bad());
                }
                while b.next_if(|c| c.is_ascii_digit()).is_some() {}
                b.next_if(|&c| c == 'r' || c == 'R');
                if !b.all(|c| ".-+,/_=".contains(c)) {
                    return Err(bad());
                }
            }
            _ => return Err(bad()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(s: &str) -> String {
        Record::parse(s).unwrap().to_string()
    }

    #[test]
    fn parses_common_records() {
        let r = "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx:mail.example.com/24//64 \
                 include:_spf.google.com ~all";
        assert_eq!(roundtrip(r), r);
        assert_eq!(Record::parse(r).unwrap().all(), Some(Qualifier::SoftFail));
    }

    #[test]
    fn normalizes_case_and_plus() {
        assert_eq!(
            roundtrip("V=SPF1 +A:Example.COM. Include:Foo.Example -ALL"),
            "v=spf1 a:example.com include:foo.example -all"
        );
    }

    #[test]
    fn modifiers() {
        let r = Record::parse("v=spf1 redirect=_spf.example.com exp=explain.%{d}").unwrap();
        assert_eq!(r.redirect(), Some("_spf.example.com"));
        assert!(Record::parse("v=spf1 redirect=a.example redirect=b.example").is_err());
        assert!(matches!(Term::parse("foo=bar").unwrap(), Term::Unknown(..)));
    }

    #[test]
    fn rejects_bad_terms() {
        for bad in [
            "v=spf1 ip4:10.0.0.0/33",
            "v=spf1 ip4:2001:db8::1",
            "v=spf1 ip4:10.0.0.1-10.0.0.9",
            "v=spf1 include",
            "v=spf1 include:nodot",
            "v=spf1 a/032",
            "v=spf1 bogus:x.example",
            "v=spf1 all:x",
            "v=spf1 exists:%{z}.example.com",
            "v=spf10 -all",
        ] {
            assert!(Record::parse(bad).is_err(), "{bad} should fail");
        }
    }

    #[test]
    fn macros() {
        let t = Term::parse("exists:%{i}._spf.mta.salesforce.com").unwrap();
        let Term::Directive(_, m) = t else { panic!() };
        let spec = m.domain_spec().unwrap();
        assert!(has_macro(spec));
        assert!(!uses_current_domain(spec));
        assert!(uses_current_domain("%{l}._spf.%{d2}"));
        assert!(Term::parse("include:%{ir}.%{v}._spf.%{d}").is_ok());
    }

    #[test]
    fn dual_cidr() {
        let Term::Directive(_, Mechanism::A(h)) = Term::parse("a//64").unwrap() else {
            panic!()
        };
        assert_eq!(
            h,
            HostSpec {
                domain: None,
                v4: None,
                v6: Some(64)
            }
        );
        let Term::Directive(_, Mechanism::Mx(h)) = Term::parse("mx:mx.example.com/28").unwrap()
        else {
            panic!()
        };
        assert_eq!(h.domain.as_deref(), Some("mx.example.com"));
        assert_eq!(h.v4, Some(28));
    }
}
