// SPDX-License-Identifier: GPL-3.0-or-later
//! Recommendations about a domain's own hosts: `a` and `mx` terms that add
//! nothing, `mx` terms that point at inbound-only gateways, and MX hosts that
//! aren't authorized at all. Also the `all` policy, read alongside DMARC.

use route_summarization::Range;
use serde::Serialize;

use crate::dns::{Dns, DnsError};
use crate::eval::Evaluator;
use crate::flatten::{ip_term, summarize};
use crate::spf::{HostSpec, Mechanism, Qualifier, Record, Term};

#[derive(Debug, Clone, Serialize)]
pub struct Advice {
    /// Stable identifier for scripts.
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub term: Option<String>,
    pub message: String,
}

/// MX host suffixes of filtering services that receive mail but don't send
/// the domain's outbound mail from those hosts.
const INBOUND_GATEWAYS: &[(&str, &str)] = &[
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("aspmx.l.google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("smtp.google.com", "Google Workspace"),
    ("pphosted.com", "Proofpoint"),
    ("ppe-hosted.com", "Proofpoint Essentials"),
    ("mimecast.com", "Mimecast"),
    ("iphmx.com", "Cisco Secure Email"),
    ("messagelabs.com", "Broadcom Email Security"),
    ("barracudanetworks.com", "Barracuda"),
];

fn gateway(host: &str) -> Option<&'static str> {
    INBOUND_GATEWAYS
        .iter()
        .find(|(suffix, _)| host == *suffix || host.ends_with(&format!(".{suffix}")))
        .map(|(_, name)| *name)
}

fn resolve(dns: &dyn Dns, domain: &str, term: &Term) -> Vec<Range> {
    Evaluator::new(dns)
        .evaluate_terms(domain, std::slice::from_ref(term), &[])
        .pass
}

fn list(ranges: &[Range]) -> String {
    summarize(ranges, &[])
        .iter()
        .map(ip_term)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Advice for the record published at `domain`.
pub fn own_hosts(domain: &str, record: &Record, dns: &dyn Dns) -> Vec<Advice> {
    let mut out = Vec::new();
    // Whether the record has `a` and `mx` terms.
    let mut has = (false, false);

    for (i, term) in record.terms.iter().enumerate() {
        let Term::Directive(Qualifier::Pass, m @ (Mechanism::A(h) | Mechanism::Mx(h))) = term
        else {
            continue;
        };
        let is_mx = matches!(m, Mechanism::Mx(_));
        if is_mx {
            has.1 = true;
        } else {
            has.0 = true;
        }
        let text = term.to_string();
        let target = h.domain.as_deref().unwrap_or(domain);
        if h.domain.as_deref().is_some_and(crate::spf::has_macro) {
            continue;
        }
        let own = resolve(dns, domain, term);
        if own.is_empty() {
            continue; // Already reported as a void lookup.
        }
        let others: Vec<Term> = record
            .terms
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, t)| t.clone())
            .collect();
        let rest = Evaluator::new(dns)
            .evaluate_terms(domain, &others, &[])
            .pass;
        let uncovered = summarize(&own, &rest);

        if is_mx {
            let hosts = dns.mx(target).unwrap_or_default();
            let gateways: Vec<&str> = hosts.iter().filter_map(|h| gateway(h)).collect();
            if !hosts.is_empty() && gateways.len() == hosts.len() {
                out.push(Advice {
                    code: "mx-inbound-gateway",
                    term: Some(text.clone()),
                    message: format!(
                        "{text}: the MX hosts are {} inbound gateways, which don't send your \
                         outbound mail; remove it to save a lookup unless you relay out through them",
                        gateways[0]
                    ),
                });
                continue;
            }
        }
        if uncovered.is_empty() {
            out.push(Advice {
                code: "redundant-own-host",
                term: Some(text.clone()),
                message: format!(
                    "{text}: its addresses ({}) are already covered by other terms; \
                     removing it saves a lookup",
                    list(&own)
                ),
            });
        } else {
            out.push(Advice {
                code: "keep-own-host",
                term: Some(text.clone()),
                message: format!(
                    "{text}: authorizes {} from your own DNS; when flattening, consider \
                     keep = true so it follows host moves (1 lookup)",
                    list(&own)
                ),
            });
        }
    }

    // MX hosts the record doesn't mention: say so only if they're unauthorized.
    // A domain's own A records are usually its website, not a mail sender, so
    // only MX hosts are checked.
    if !has.1 {
        let hosts = dns.mx(domain).unwrap_or_default();
        if !hosts.is_empty() && !hosts.iter().all(|h| gateway(h).is_some()) {
            let pass = Evaluator::new(dns)
                .evaluate_terms(domain, &record.terms, &[])
                .pass;
            let mx = Term::Directive(Qualifier::Pass, Mechanism::Mx(HostSpec::default()));
            let uncovered = summarize(&resolve(dns, domain, &mx), &pass);
            if !uncovered.is_empty() {
                out.push(Advice {
                    code: "mx-not-authorized",
                    term: None,
                    message: format!(
                        "{domain}'s MX hosts ({}) aren't authorized; if they also send \
                         mail, add \"mx\" (1 lookup) or list the addresses as ip4/ip6",
                        uncovered.iter().map(ip_term).collect::<Vec<_>>().join(" ")
                    ),
                });
            }
        }
    }
    out
}

/// The DMARC policy that applies to a domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dmarc {
    /// Where the record was found: `_dmarc.<domain>` or a parent's.
    pub name: String,
    /// `none`, `quarantine` or `reject`: `sp` when inherited from a parent
    /// that sets it, otherwise `p`.
    pub policy: String,
}

impl Dmarc {
    /// True if receivers are asked to act on failing mail.
    pub fn enforcing(&self) -> bool {
        self.policy != "none"
    }
}

/// The tags of a `v=DMARC1` record, or `None` if `txt` isn't one.
fn dmarc_tags(txt: &str) -> Option<Vec<(String, String)>> {
    let mut parts = txt.split(';').map(str::trim);
    let version = parts.next()?.split_once('=')?;
    if !(version.0.trim().eq_ignore_ascii_case("v") && version.1.trim() == "DMARC1") {
        return None;
    }
    Some(
        parts
            .filter_map(|p| p.split_once('='))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_ascii_lowercase()))
            .collect(),
    )
}

/// Find the DMARC policy for `domain`: `_dmarc.<domain>`, then each parent up
/// to (not including) the top-level domain, as in the DMARCbis tree walk.
/// `Ok(None)` means no valid record exists.
pub fn dmarc(domain: &str, dns: &dyn Dns) -> Result<Option<Dmarc>, DnsError> {
    let labels: Vec<&str> = domain.split('.').collect();
    for i in 0..labels.len().saturating_sub(1).min(8) {
        let name = format!("_dmarc.{}", labels[i..].join("."));
        let records: Vec<_> = dns
            .txt(&name)?
            .iter()
            .filter_map(|t| dmarc_tags(t))
            .collect();
        // Several DMARC records are as good as none (RFC 7489 §6.6.3).
        let [tags] = records.as_slice() else {
            continue;
        };
        let tag = |k: &str| {
            tags.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        let policy = match (i, tag("sp")) {
            (1.., Some(sp)) => sp,
            _ => tag("p").unwrap_or("none"),
        };
        let policy = match policy {
            "quarantine" | "reject" => policy,
            _ => "none",
        };
        return Ok(Some(Dmarc {
            name,
            policy: policy.to_string(),
        }));
    }
    Ok(None)
}

/// Advice on the record's `all` qualifier, given the domain's DMARC policy.
/// `+all` and a missing `all` are reported as problems, not here.
pub fn policy(domain: &str, all: Option<Qualifier>, dmarc: Option<&Dmarc>) -> Vec<Advice> {
    let enforcing = dmarc.is_some_and(Dmarc::enforcing);
    let advice = |code, term: &str, message: String| Advice {
        code,
        term: Some(term.into()),
        message,
    };
    match all {
        Some(Qualifier::Neutral) => vec![advice(
            "all-neutral",
            "?all",
            "?all: unlisted senders get neutral, the same as having no SPF record; \
             use ~all with a DMARC policy, or -all"
                .into(),
        )],
        Some(Qualifier::SoftFail) if !enforcing => {
            let dmarc = match dmarc {
                Some(d) => format!("{} has p={}", d.name, d.policy),
                None => format!("_dmarc.{domain} has no DMARC record"),
            };
            vec![advice(
                "softfail-unenforced",
                "~all",
                format!(
                    "~all: {dmarc}, so unlisted senders are only marked suspicious and \
                     usually delivered; publish DMARC with p=quarantine or p=reject, or use -all"
                ),
            )]
        }
        Some(Qualifier::Fail) if enforcing => vec![advice(
            "fail-preempts-dmarc",
            "-all",
            format!(
                "-all: some receivers reject on the SPF fail before DMARC runs, losing \
                 forwarded mail that a DKIM pass would have saved; with p={} at {}, \
                 ~all leaves the decision to DMARC",
                dmarc.map_or("", |d| d.policy.as_str()),
                dmarc.map_or("", |d| d.name.as_str()),
            ),
        )],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::StaticDns;

    fn advise(zone: &str) -> Vec<(&'static str, Option<String>)> {
        let dns = StaticDns::parse(zone).unwrap();
        let txt = dns.txt("example.com").unwrap();
        let record = Record::parse(&txt[0]).unwrap();
        own_hosts("example.com", &record, &dns)
            .into_iter()
            .map(|a| (a.code, a.term))
            .collect()
    }

    #[test]
    fn redundant_and_kept_hosts() {
        let got = advise(
            r#"
            example.com TXT "v=spf1 a mx:relay.example.com ip4:192.0.2.0/24 -all"
            example.com A 192.0.2.10
            relay.example.com MX out.example.com
            out.example.com A 198.51.100.5
            "#,
        );
        assert_eq!(
            got,
            [
                ("redundant-own-host", Some("a".into())),
                ("keep-own-host", Some("mx:relay.example.com".into())),
            ]
        );
    }

    #[test]
    fn inbound_gateway_mx() {
        let got = advise(
            r#"
            example.com TXT "v=spf1 mx include:spf.protection.outlook.com -all"
            example.com MX example-com.mail.protection.outlook.com
            example-com.mail.protection.outlook.com A 52.101.1.1
            spf.protection.outlook.com TXT "v=spf1 ip4:40.92.0.0/15 -all"
            "#,
        );
        assert_eq!(got, [("mx-inbound-gateway", Some("mx".into()))]);
    }

    #[test]
    fn unauthorized_own_hosts() {
        let got = advise(
            r#"
            example.com TXT "v=spf1 ip4:192.0.2.1 -all"
            example.com A 203.0.113.80
            example.com MX mail.example.com
            mail.example.com A 198.51.100.25
            "#,
        );
        // Only the MX host is reported; the website's A record is not.
        assert_eq!(got, [("mx-not-authorized", None)]);
    }

    fn policy_codes(zone: &str, all: Qualifier) -> Vec<&'static str> {
        let dns = StaticDns::parse(zone).unwrap();
        let d = dmarc("mail.example.com", &dns).unwrap();
        policy("mail.example.com", Some(all), d.as_ref())
            .into_iter()
            .map(|a| a.code)
            .collect()
    }

    #[test]
    fn dmarc_lookup_walks_up_and_uses_sp() {
        let dns = StaticDns::parse(
            r#"
            _dmarc.example.com TXT "v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com"
            _dmarc.direct.example.com TXT "v=DMARC1;p=none"
            _dmarc.two.example.com TXT "v=DMARC1; p=reject"
            _dmarc.two.example.com TXT "v=DMARC1; p=none"
            _dmarc.bogus.example.com TXT "v=spf1 -all"
            "#,
        )
        .unwrap();
        let got = |d: &str| dmarc(d, &dns).unwrap().map(|d| (d.name, d.policy));
        assert_eq!(
            got("example.com"),
            Some(("_dmarc.example.com".into(), "reject".into()))
        );
        assert_eq!(
            got("a.b.example.com"),
            Some(("_dmarc.example.com".into(), "quarantine".into()))
        );
        assert_eq!(
            got("direct.example.com"),
            Some(("_dmarc.direct.example.com".into(), "none".into()))
        );
        // Two records count as none; the walk goes on to the parent.
        assert_eq!(got("two.example.com").unwrap().0, "_dmarc.example.com");
        assert_eq!(got("bogus.example.com").unwrap().0, "_dmarc.example.com");
        assert_eq!(got("example.org"), None);
    }

    #[test]
    fn all_qualifier_against_dmarc() {
        let reject = r#"_dmarc.example.com TXT "v=DMARC1; p=reject""#;
        let monitor = r#"_dmarc.example.com TXT "v=DMARC1; p=none""#;
        assert_eq!(policy_codes("", Qualifier::Neutral), ["all-neutral"]);
        assert_eq!(policy_codes(reject, Qualifier::Neutral), ["all-neutral"]);
        assert_eq!(
            policy_codes("", Qualifier::SoftFail),
            ["softfail-unenforced"]
        );
        assert_eq!(
            policy_codes(monitor, Qualifier::SoftFail),
            ["softfail-unenforced"]
        );
        assert!(policy_codes(reject, Qualifier::SoftFail).is_empty());
        assert_eq!(
            policy_codes(reject, Qualifier::Fail),
            ["fail-preempts-dmarc"]
        );
        assert!(policy_codes(monitor, Qualifier::Fail).is_empty());
        assert!(policy_codes("", Qualifier::Fail).is_empty());
    }
}
