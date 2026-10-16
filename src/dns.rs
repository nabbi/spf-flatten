// SPDX-License-Identifier: GPL-3.0-or-later
//! DNS lookups behind a small trait, so evaluation runs the same against live
//! DNS, fixtures in tests, or a proposed set of records layered over live DNS.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::{Resolver, TokioResolver};

#[derive(Debug, Clone, thiserror::Error)]
#[error("DNS {rtype} lookup of {name} failed: {reason}")]
pub struct DnsError {
    pub name: String,
    pub rtype: &'static str,
    pub reason: String,
}

/// The lookups SPF evaluation needs. An empty answer means NXDOMAIN or NODATA,
/// which RFC 7208 calls a void lookup; `Err` is a temporary failure.
pub trait Dns {
    fn txt(&self, name: &str) -> Result<Vec<String>, DnsError>;
    fn a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError>;
    fn aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError>;
    fn mx(&self, name: &str) -> Result<Vec<String>, DnsError>;
}

/// Live DNS through hickory, blocking on a private single-threaded runtime.
pub struct SystemDns {
    rt: tokio::runtime::Runtime,
    resolver: TokioResolver,
}

impl SystemDns {
    /// Use the given name servers, or the system configuration when empty.
    pub fn new(nameservers: &[IpAddr]) -> anyhow::Result<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (servers, options) = if nameservers.is_empty() {
            let (config, options) = read_system_conf()?;
            // resolv.conf may list fe80:: servers with an interface scope, which
            // hickory drops, leaving them unreachable. Skip them if others exist.
            let routable: Vec<NameServerConfig> = config
                .name_servers()
                .iter()
                .filter(|s| !matches!(s.ip, IpAddr::V6(ip) if ip.is_unicast_link_local()))
                .cloned()
                .collect();
            let servers = if routable.is_empty() {
                config.name_servers().to_vec()
            } else {
                routable
            };
            (servers, options)
        } else {
            let servers = nameservers
                .iter()
                .map(|&ip| NameServerConfig::udp_and_tcp(ip))
                .collect();
            (servers, ResolverOpts::default())
        };
        let builder = Resolver::builder_with_config(
            ResolverConfig::from_name_servers(servers),
            TokioRuntimeProvider::default(),
        )
        .with_options(options);
        // The resolver spawns background tasks, so build it inside the runtime.
        let resolver = {
            let _guard = rt.enter();
            builder.build()?
        };
        Ok(Self { rt, resolver })
    }

    fn lookup<T>(
        &self,
        name: &str,
        rtype: RecordType,
        label: &'static str,
        pick: impl Fn(&RData) -> Option<T>,
    ) -> Result<Vec<T>, DnsError> {
        let fqdn = if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        };
        match self.rt.block_on(self.resolver.lookup(fqdn.as_str(), rtype)) {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|r| pick(&r.data))
                .collect()),
            Err(e) if e.is_no_records_found() => Ok(Vec::new()),
            Err(e) => Err(DnsError {
                name: name.to_string(),
                rtype: label,
                reason: e.to_string(),
            }),
        }
    }
}

fn exchange_name(name: impl ToString) -> String {
    name.to_string().trim_end_matches('.').to_ascii_lowercase()
}

impl Dns for SystemDns {
    fn txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        self.lookup(name, RecordType::TXT, "TXT", |d| match d {
            // A TXT record's strings are concatenated with no separator (RFC 7208 §3.3).
            RData::TXT(t) => Some(
                t.txt_data
                    .iter()
                    .map(|s| String::from_utf8_lossy(s))
                    .collect::<String>(),
            ),
            _ => None,
        })
    }

    fn a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        self.lookup(name, RecordType::A, "A", |d| match d {
            RData::A(a) => Some(a.0),
            _ => None,
        })
    }

    fn aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        self.lookup(name, RecordType::AAAA, "AAAA", |d| match d {
            RData::AAAA(a) => Some(a.0),
            _ => None,
        })
    }

    fn mx(&self, name: &str) -> Result<Vec<String>, DnsError> {
        self.lookup(name, RecordType::MX, "MX", |d| match d {
            RData::MX(mx) => Some(exchange_name(&mx.exchange)),
            _ => None,
        })
    }
}

/// Records held in memory, for tests and offline use. Names are matched
/// case-insensitively and without a trailing dot.
#[derive(Debug, Default, Clone)]
pub struct StaticDns {
    txt: HashMap<String, Vec<String>>,
    a: HashMap<String, Vec<Ipv4Addr>>,
    aaaa: HashMap<String, Vec<Ipv6Addr>>,
    mx: HashMap<String, Vec<String>>,
    fail: Vec<String>,
}

fn key(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

impl StaticDns {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse zone-like lines: `name TYPE value`, where TYPE is TXT, A, AAAA,
    /// MX or FAIL (every lookup of the name is a temporary error). TXT values
    /// may be quoted. Blank lines and `;` or `#` comments are skipped.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut dns = Self::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with([';', '#']) {
                continue;
            }
            let bad = || format!("line {}: {line:?}", n + 1);
            let Some((name, rest)) = line.split_once(char::is_whitespace) else {
                return Err(bad());
            };
            let rest = rest.trim_start();
            let (rtype, value) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            let value = value.trim();
            match rtype.to_ascii_uppercase().as_str() {
                "TXT" => dns.add_txt(name, value.trim_matches('"')),
                "A" => dns.add_a(name, value.parse().map_err(|_| bad())?),
                "AAAA" => dns.add_aaaa(name, value.parse().map_err(|_| bad())?),
                "MX" => dns.add_mx(name, value),
                "FAIL" => dns.add_failure(name),
                _ => return Err(bad()),
            };
        }
        Ok(dns)
    }

    pub fn add_txt(&mut self, name: &str, value: &str) -> &mut Self {
        self.txt
            .entry(key(name))
            .or_default()
            .push(value.to_string());
        self
    }

    pub fn add_a(&mut self, name: &str, ip: Ipv4Addr) -> &mut Self {
        self.a.entry(key(name)).or_default().push(ip);
        self
    }

    pub fn add_aaaa(&mut self, name: &str, ip: Ipv6Addr) -> &mut Self {
        self.aaaa.entry(key(name)).or_default().push(ip);
        self
    }

    pub fn add_mx(&mut self, name: &str, exchange: &str) -> &mut Self {
        self.mx.entry(key(name)).or_default().push(key(exchange));
        self
    }

    pub fn add_failure(&mut self, name: &str) -> &mut Self {
        self.fail.push(key(name));
        self
    }

    fn get<T: Clone>(
        &self,
        map: &HashMap<String, Vec<T>>,
        name: &str,
        rtype: &'static str,
    ) -> Result<Vec<T>, DnsError> {
        let k = key(name);
        if self.fail.contains(&k) {
            return Err(DnsError {
                name: name.to_string(),
                rtype,
                reason: "SERVFAIL".into(),
            });
        }
        Ok(map.get(&k).cloned().unwrap_or_default())
    }
}

impl Dns for StaticDns {
    fn txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        self.get(&self.txt, name, "TXT")
    }
    fn a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        self.get(&self.a, name, "A")
    }
    fn aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        self.get(&self.aaaa, name, "AAAA")
    }
    fn mx(&self, name: &str) -> Result<Vec<String>, DnsError> {
        self.get(&self.mx, name, "MX")
    }
}

/// TXT records for some names replaced, everything else from `inner`. Used to
/// evaluate generated records as if they were already published.
pub struct Overlay<'a> {
    pub txt: HashMap<String, Vec<String>>,
    pub inner: &'a dyn Dns,
}

impl<'a> Overlay<'a> {
    pub fn new(inner: &'a dyn Dns, records: impl IntoIterator<Item = (String, String)>) -> Self {
        let mut txt: HashMap<String, Vec<String>> = HashMap::new();
        for (name, value) in records {
            txt.entry(key(&name)).or_default().push(value);
        }
        Self { txt, inner }
    }
}

impl Dns for Overlay<'_> {
    fn txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        match self.txt.get(&key(name)) {
            Some(v) => Ok(v.clone()),
            None => self.inner.txt(name),
        }
    }
    fn a(&self, name: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        self.inner.a(name)
    }
    fn aaaa(&self, name: &str) -> Result<Vec<Ipv6Addr>, DnsError> {
        self.inner.aaaa(name)
    }
    fn mx(&self, name: &str) -> Result<Vec<String>, DnsError> {
        self.inner.mx(name)
    }
}
