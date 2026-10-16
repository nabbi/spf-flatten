// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};

use spf_flatten::config::{Config, DEFAULT_MAX_RECORD_BYTES};
use spf_flatten::dns::{Dns, Overlay, StaticDns, SystemDns};
use spf_flatten::eval::{Evaluator, Flat, MAX_LOOKUPS, MAX_VOIDS, Problem, Severity};
use spf_flatten::flatten::{self, Plan};
use spf_flatten::{import, output, spf};

/// Flatten SPF records to stay within the RFC 7208 lookup and size limits.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Query this name server instead of the system resolver (repeatable)
    #[arg(long = "nameserver", global = true, value_name = "IP")]
    nameservers: Vec<IpAddr>,

    /// Answer DNS queries from a fixture file instead of the network
    #[arg(
        long,
        global = true,
        value_name = "FILE",
        conflicts_with = "nameservers"
    )]
    dns_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Resolve the sources in a config file and print flattened records
    Flatten {
        /// Config file, or - for stdin
        #[arg(short, long, default_value = "spf.toml")]
        input: PathBuf,
        #[arg(short, long, value_enum, default_value_t = Format::Zone)]
        format: Format,
        /// Write here instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Write a config file from the SPF record a domain publishes now
    Import {
        domain: String,
        /// Write here instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Evaluate a domain's published SPF record and report problems
    Check { domain: String },
    /// Compare what a config would publish with what DNS serves now.
    /// Exits 1 when the published records authorize different senders.
    Diff {
        /// Config file, or - for stdin
        #[arg(short, long, default_value = "spf.toml")]
        input: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    /// BIND zone-file lines
    Zone,
    /// JSON with records, strings and lookup counts
    Json,
    /// One name<TAB>value line per record
    Plain,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

/// Ok(false) means the command ran but found problems.
fn run(cli: Cli) -> Result<bool> {
    let dns: Box<dyn Dns> = match &cli.dns_file {
        Some(path) => Box::new(
            StaticDns::parse(&read(path)?)
                .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?,
        ),
        None => Box::new(SystemDns::new(&cli.nameservers)?),
    };
    let dns = dns.as_ref();
    match cli.command {
        Command::Flatten {
            input,
            format,
            output,
        } => flatten_cmd(dns, &input, format, output.as_deref()),
        Command::Import { domain, output } => import_cmd(dns, &domain, output.as_deref()),
        Command::Check { domain } => check_cmd(dns, &domain),
        Command::Diff { input } => diff_cmd(dns, &input),
    }
}

fn read(path: &Path) -> Result<String> {
    if path == Path::new("-") {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        return Ok(s);
    }
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

fn write(path: Option<&Path>, text: &str) -> Result<()> {
    match path {
        Some(p) => std::fs::write(p, text).with_context(|| format!("writing {}", p.display())),
        None => Ok(std::io::stdout().write_all(text.as_bytes())?),
    }
}

fn report(problems: &[Problem]) -> bool {
    for p in problems {
        eprintln!("{p}");
    }
    !problems.iter().any(|p| p.severity == Severity::Error)
}

fn load(path: &Path) -> Result<Config> {
    let cfg =
        Config::parse(&read(path)?).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    for w in &cfg.warnings {
        eprintln!("warning: {w}");
    }
    Ok(cfg)
}

/// Evaluate, pack and verify. The second value is the config evaluated
/// without `keep`, i.e. everything it authorizes.
fn build(dns: &dyn Dns, cfg: &Config) -> Result<(Plan, Flat, Vec<Problem>)> {
    let mut ev = Evaluator::new(dns);
    let flat = ev.evaluate_terms(&cfg.domain, &cfg.terms, &cfg.keep);
    if !report(&ev.problems) {
        bail!("cannot flatten until the errors above are fixed");
    }
    let warnings = ev.problems;
    let plan = flatten::pack(cfg, &flat).map_err(anyhow::Error::msg)?;
    let mut ev = Evaluator::new(dns);
    let expected = ev.evaluate_terms(&cfg.domain, &cfg.terms, &[]);
    let problems = flatten::verify(cfg, &plan, &expected, dns);
    if !report(&problems) {
        bail!("the generated records failed verification");
    }
    Ok((plan, expected, warnings))
}

fn flatten_cmd(dns: &dyn Dns, input: &Path, format: Format, out: Option<&Path>) -> Result<bool> {
    let cfg = load(input)?;
    let (plan, expected, warnings) = build(dns, &cfg)?;
    let text = match format {
        Format::Zone => output::zone(&cfg, &plan),
        Format::Json => output::json(&cfg, &plan, &warnings),
        Format::Plain => output::plain(&plan),
    };
    write(out, &text)?;
    eprintln!(
        "{}: {} prefixes in {} record(s), {} of {} lookups (unflattened: {})",
        cfg.domain,
        plan.prefixes,
        plan.records.len(),
        plan.lookups,
        cfg.max_lookups,
        expected.lookups
    );
    Ok(true)
}

fn import_cmd(dns: &dyn Dns, domain: &str, out: Option<&Path>) -> Result<bool> {
    let domain = spf::domain_spec(domain).map_err(anyhow::Error::msg)?;
    match import::import(&domain, dns) {
        Ok(imported) => {
            report(&imported.problems);
            write(out, &imported.config)?;
            Ok(true)
        }
        Err(problems) => {
            report(&problems);
            Ok(false)
        }
    }
}

fn check_cmd(dns: &dyn Dns, domain: &str) -> Result<bool> {
    let domain = spf::domain_spec(domain).map_err(anyhow::Error::msg)?;
    let mut ev = Evaluator::new(dns);
    let Some(flat) = ev.evaluate_domain(&domain) else {
        return Ok(report(&ev.problems));
    };
    let record = dns
        .txt(&domain)?
        .into_iter()
        .find(|t| spf::is_spf(t))
        .unwrap_or_default();

    println!("{domain}\n  {record}\n");
    print!("{}", output::tree(&flat.tree));
    println!();

    let mut problems = ev.problems;
    let mut add = |severity, message: String| {
        problems.push(Problem {
            severity,
            path: domain.clone(),
            message,
        })
    };
    if flat.lookups > MAX_LOOKUPS {
        add(
            Severity::Error,
            format!(
                "{} lookups, over the limit of {MAX_LOOKUPS} (permerror)",
                flat.lookups
            ),
        );
    }
    if flat.voids > MAX_VOIDS {
        add(
            Severity::Error,
            format!(
                "{} void lookups, over the limit of {MAX_VOIDS} (permerror)",
                flat.voids
            ),
        );
    }
    if record.len() > DEFAULT_MAX_RECORD_BYTES {
        add(
            Severity::Warning,
            format!(
                "record is {} bytes; over {DEFAULT_MAX_RECORD_BYTES} risks DNS truncation",
                record.len()
            ),
        );
    }
    if flat.all.is_none() {
        add(
            Severity::Warning,
            "no \"all\" mechanism; unmatched senders get neutral".into(),
        );
    }
    let prefixes = flatten::summarize(&flat.pass, &[]).len();
    println!("lookups:      {} of {MAX_LOOKUPS}", flat.lookups);
    println!("void lookups: {} of {MAX_VOIDS}", flat.voids);
    println!("record size:  {} bytes", record.len());
    println!(
        "authorizes:   {prefixes} prefixes, {} per-message terms",
        flat.live.len()
    );
    Ok(report(&problems))
}

fn diff_cmd(dns: &dyn Dns, input: &Path) -> Result<bool> {
    let cfg = load(input)?;
    let (plan, _, _) = build(dns, &cfg)?;

    let overlay = Overlay::new(
        dns,
        plan.records
            .iter()
            .map(|r| (r.name.clone(), r.value.clone())),
    );
    let want = Evaluator::new(&overlay)
        .evaluate_domain(&cfg.domain)
        .context("evaluating the generated records")?;
    let mut ev = Evaluator::new(dns);
    let Some(have) = ev.evaluate_domain(&cfg.domain) else {
        report(&ev.problems);
        println!("{} has no usable SPF record; publish:", cfg.domain);
        print!("{}", output::zone(&cfg, &plan));
        return Ok(false);
    };
    report(&ev.problems);

    let cmp = flatten::compare(&want, &[], &have);
    for p in &cmp.missing {
        println!("+ {p}");
    }
    for p in &cmp.extra {
        println!("- {p}");
    }
    for t in &cmp.missing_live {
        println!("+ {t}");
    }
    for t in &cmp.extra_live {
        println!("- {t}");
    }
    if let Some((want, have)) = &cmp.all {
        println!("policy: published {have}, config has {want}");
    }

    let mut text_differs = false;
    for r in &plan.records {
        let published: Vec<String> = dns
            .txt(&r.name)?
            .into_iter()
            .filter(|t| spf::is_spf(t))
            .collect();
        if published.as_slice() != std::slice::from_ref(&r.value) {
            text_differs = true;
        }
    }
    let stale = cfg.chain_name(plan.records.len());
    if dns.txt(&stale)?.iter().any(|t| spf::is_spf(t)) {
        println!("note: {stale} is still published but no longer included; it can be removed");
    }

    if cmp.is_empty() {
        if text_differs {
            println!("in sync: the published records authorize the same senders (text differs)");
        } else {
            println!("in sync");
        }
        return Ok(true);
    }
    println!("\nout of sync; publish:");
    print!("{}", output::zone(&cfg, &plan));
    Ok(false)
}
