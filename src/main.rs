// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::{Value, json};

use spf_flatten::config::{Config, DEFAULT_MAX_RECORD_BYTES, Strategy};
use spf_flatten::dns::{Dns, Overlay, StaticDns, SystemDns};
use spf_flatten::eval::{Evaluator, Flat, MAX_LOOKUPS, MAX_VOIDS, Problem, Severity};
use spf_flatten::flatten::{self, Plan};
use spf_flatten::minimal::{self, Minimal};
use spf_flatten::output::{self, SCHEMA_VERSION};
use spf_flatten::risk::{self, Level, State};
use spf_flatten::{advice, import, spf};

/// Flatten SPF records to stay within the RFC 7208 lookup and size limits.
///
/// Exit status: 0 clean, 1 findings (errors, drift, risk over --fail-on),
/// 2 the command could not run.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// Name server to query (repeatable)
    #[arg(
        long = "nameserver",
        global = true,
        value_name = "IP",
        default_value = "1.1.1.1"
    )]
    nameservers: Vec<IpAddr>,

    /// Use the system resolver (/etc/resolv.conf) instead of --nameserver
    #[arg(long, global = true, conflicts_with = "nameservers")]
    system_resolver: bool,

    /// Answer DNS queries from a fixture file instead of the network
    #[arg(
        long,
        global = true,
        value_name = "FILE",
        conflicts_with_all = ["nameservers", "system_resolver"]
    )]
    dns_file: Option<PathBuf>,

    /// Print one JSON document on stdout (schema in docs/json.md)
    #[arg(long, global = true)]
    json: bool,

    /// Flatten only as many sources as the lookup budget needs, lowest drift
    /// risk first, and keep the rest live (same as strategy = "minimal")
    #[arg(long, global = true)]
    minimal: bool,

    /// Lookups to leave unused under --minimal (overrides the config's headroom)
    #[arg(long, global = true, value_name = "N")]
    headroom: Option<usize>,

    /// No diagnostics on stderr
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Evaluate a domain's published SPF record, report problems, and
    /// suggest flattened records
    Check { domain: String },
    /// Write a config file from the SPF record a domain publishes now
    Import {
        domain: String,
        /// Write here instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
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
    /// Compare what a config would publish with what DNS serves now; exits 1
    /// when the published records authorize different senders
    Diff {
        /// Config file, or - for stdin
        #[arg(short, long, default_value = "spf.toml")]
        input: PathBuf,
    },
    /// Score each source's risk of drifting after it's flattened
    Risk {
        /// Config file, or - for stdin
        #[arg(short, long, default_value = "spf.toml")]
        input: PathBuf,
        /// Record each source's prefixes here and score observed changes
        #[arg(long, value_name = "FILE")]
        state: Option<PathBuf>,
        /// Exit 1 when any source is at this level or above
        #[arg(long, value_enum)]
        fail_on: Option<FailOn>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    /// BIND zone-file lines
    Zone,
    /// The same JSON document as --json
    Json,
    /// One name<TAB>value line per record
    Plain,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    Medium,
    High,
}

/// Options every command shares.
struct Ctx<'a> {
    dns: &'a dyn Dns,
    quiet: bool,
    minimal: bool,
    headroom: Option<usize>,
}

impl Ctx<'_> {
    /// Command-line overrides of the config's strategy.
    fn apply(&self, cfg: &mut Config) -> Result<(), Fatal> {
        if self.minimal {
            cfg.strategy = Strategy::Minimal;
        }
        if let Some(h) = self.headroom {
            if h >= cfg.max_lookups {
                return Err(Fatal::new(format!(
                    "--headroom must be less than max_lookups ({})",
                    cfg.max_lookups
                )));
            }
            cfg.headroom = h;
        }
        Ok(())
    }

    fn diag(&self, problems: &[Problem]) {
        if !self.quiet {
            problems.iter().for_each(|p| eprintln!("{p}"));
        }
    }

    fn note(&self, msg: &str) {
        if !self.quiet {
            eprintln!("{msg}");
        }
    }
}

/// What a command produced: its text for people, its JSON document, and
/// whether it found nothing wrong.
struct Report {
    ok: bool,
    text: String,
    json: Value,
}

/// A command that could not run.
struct Fatal {
    message: String,
    problems: Vec<Problem>,
}

impl Fatal {
    fn new(message: impl std::fmt::Display) -> Self {
        Self {
            message: message.to_string(),
            problems: Vec::new(),
        }
    }
}

impl<E: std::error::Error> From<E> for Fatal {
    fn from(e: E) -> Self {
        Fatal::new(e)
    }
}

fn errors(problems: &[Problem]) -> bool {
    problems.iter().any(|p| p.severity == Severity::Error)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let command = match &cli.command {
        Command::Check { .. } => "check",
        Command::Import { .. } => "import",
        Command::Flatten { .. } => "flatten",
        Command::Diff { .. } => "diff",
        Command::Risk { .. } => "risk",
    };
    let json_out = cli.json
        || matches!(
            cli.command,
            Command::Flatten {
                format: Format::Json,
                ..
            }
        );
    let quiet = cli.quiet;
    match run(cli) {
        Ok((report, dest)) => {
            let text = if json_out {
                serde_json::to_string_pretty(&report.json).expect("serializable") + "\n"
            } else {
                report.text
            };
            if let Err(e) = write(dest.as_deref(), &text) {
                eprintln!("error: {}", e.message);
                return ExitCode::from(2);
            }
            ExitCode::from(if report.ok { 0 } else { 1 })
        }
        Err(fatal) => {
            if json_out {
                let doc = json!({
                    "schema_version": SCHEMA_VERSION,
                    "command": command,
                    "ok": false,
                    "error": fatal.message,
                    "problems": fatal.problems,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&doc).expect("serializable")
                );
            }
            if !(quiet && json_out) {
                fatal.problems.iter().for_each(|p| eprintln!("{p}"));
                eprintln!("error: {}", fatal.message);
            }
            ExitCode::from(2)
        }
    }
}

/// Runs the command; the path is where to write its output (stdout if None).
fn run(cli: Cli) -> Result<(Report, Option<PathBuf>), Fatal> {
    let dns: Box<dyn Dns> = match &cli.dns_file {
        Some(path) => Box::new(
            StaticDns::parse(&read(path)?)
                .map_err(|e| Fatal::new(format!("{}: {e}", path.display())))?,
        ),
        None => {
            let servers: &[IpAddr] = if cli.system_resolver {
                &[]
            } else {
                &cli.nameservers
            };
            let dns = SystemDns::new(servers).map_err(Fatal::new)?;
            // Drift scoring (risk, and the minimal strategy's choices) needs the
            // TTLs zones publish; a resolver's cached countdowns would make the
            // choices change from run to run.
            if !matches!(cli.command, Command::Import { .. }) {
                Box::new(dns.authoritative_ttls())
            } else {
                Box::new(dns)
            }
        }
    };
    let ctx = Ctx {
        dns: dns.as_ref(),
        quiet: cli.quiet,
        minimal: cli.minimal,
        headroom: cli.headroom,
    };
    match cli.command {
        Command::Check { domain } => Ok((check_cmd(&ctx, &domain)?, None)),
        Command::Import { domain, output } => Ok((import_cmd(&ctx, &domain)?, output)),
        Command::Flatten {
            input,
            format,
            output,
        } => Ok((flatten_cmd(&ctx, &input, format)?, output)),
        Command::Diff { input } => Ok((diff_cmd(&ctx, &input)?, None)),
        Command::Risk {
            input,
            state,
            fail_on,
        } => Ok((risk_cmd(&ctx, &input, state.as_deref(), fail_on)?, None)),
    }
}

fn read(path: &Path) -> Result<String, Fatal> {
    if path == Path::new("-") {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        return Ok(s);
    }
    std::fs::read_to_string(path)
        .map_err(|e| Fatal::new(format!("reading {}: {e}", path.display())))
}

fn write(path: Option<&Path>, text: &str) -> Result<(), Fatal> {
    match path {
        Some(p) => {
            std::fs::write(p, text).map_err(|e| Fatal::new(format!("writing {}: {e}", p.display())))
        }
        None => Ok(std::io::stdout().write_all(text.as_bytes())?),
    }
}

fn load(ctx: &Ctx, path: &Path) -> Result<Config, Fatal> {
    let text = read(path)?;
    let mut cfg =
        Config::parse(&text).map_err(|e| Fatal::new(format!("{}: {e}", path.display())))?;
    ctx.apply(&mut cfg)?;
    for w in &cfg.warnings {
        ctx.note(&format!("warning: {w}"));
    }
    Ok(cfg)
}

/// A config evaluated, packed and verified.
struct Built {
    plan: Plan,
    /// The config evaluated without `keep`: everything it authorizes.
    expected: Flat,
    /// Warnings from evaluation.
    problems: Vec<Problem>,
    /// What the minimal strategy chose, if used.
    minimal: Option<Minimal>,
}

fn build(dns: &dyn Dns, cfg: &Config) -> Result<Built, Fatal> {
    if cfg.strategy == Strategy::Full {
        return build_exact(dns, cfg);
    }
    let mut ev = Evaluator::new(dns);
    let expected = ev.evaluate_terms(&cfg.domain, &cfg.terms, &[]);
    if errors(&ev.problems) {
        return Err(Fatal {
            message: "cannot flatten until the errors above are fixed".into(),
            problems: ev.problems,
        });
    }
    let risks = risk::assess(cfg, &expected, dns, None, risk::now());
    let m = minimal::choose(cfg, dns, &risks).map_err(Fatal::new)?;
    let mut chosen = cfg.clone();
    chosen.keep = m.keep.clone();
    let mut b = build_exact(dns, &chosen)?;
    b.minimal = Some(m);
    Ok(b)
}

/// Flatten exactly the sources `cfg.keep` doesn't pin live.
fn build_exact(dns: &dyn Dns, cfg: &Config) -> Result<Built, Fatal> {
    let mut ev = Evaluator::new(dns);
    let flat = ev.evaluate_terms(&cfg.domain, &cfg.terms, &cfg.keep);
    if errors(&ev.problems) {
        return Err(Fatal {
            message: "cannot flatten until the errors above are fixed".into(),
            problems: ev.problems,
        });
    }
    let problems = ev.problems;
    let plan = flatten::pack(cfg, &flat).map_err(|e| Fatal {
        message: e,
        problems: problems.clone(),
    })?;
    let expected = Evaluator::new(dns).evaluate_terms(&cfg.domain, &cfg.terms, &[]);
    let failures = flatten::verify(cfg, &plan, &expected, dns);
    if !failures.is_empty() {
        return Err(Fatal {
            message: "the generated records failed verification".into(),
            problems: problems.into_iter().chain(failures).collect(),
        });
    }
    Ok(Built {
        plan,
        expected,
        problems,
        minimal: None,
    })
}

/// The JSON for a built plan, shared by flatten and check.
fn plan_json(cfg: &Config, b: &Built) -> Value {
    json!({
        "domain": cfg.domain,
        "policy": cfg.policy_term(),
        "lookups": b.plan.lookups,
        "max_lookups": cfg.max_lookups,
        "unflattened_lookups": b.expected.lookups,
        "strategy": cfg.strategy,
        "headroom": cfg.headroom,
        "minimal": b.minimal,
        "prefixes": b.plan.prefixes,
        "widening": b.plan.widening,
        "records": output::json_records(cfg, &b.plan),
        "kept": b.plan.live,
    })
}

fn summary(cfg: &Config, b: &Built) -> String {
    let mut s = format!(
        "{}: {} prefixes in {} record(s), {} of {} lookups (unflattened: {})",
        cfg.domain,
        b.plan.prefixes,
        b.plan.records.len(),
        b.plan.lookups,
        cfg.max_lookups,
        b.expected.lookups
    );
    if let Some(w) = &b.plan.widening {
        s.push_str(&format!(
            "\nwidened {} prefixes: authorizes {} more IPv4 addresses than the sources list",
            w.widened, w.extra_ipv4_addresses
        ));
    }
    if let Some(m) = &b.minimal {
        s.push_str(&format!(
            "\nminimal: target {} lookups (max {} - headroom {})",
            m.target, cfg.max_lookups, cfg.headroom
        ));
        for c in &m.choices {
            s.push_str(&format!(
                "\n  {:<9} {:<6} {} ({})",
                if c.flattened { "flattened" } else { "live" },
                c.level.to_string(),
                c.source,
                c.reason
            ));
        }
    }
    s
}

/// Wrap a command's fields with the fields every document has.
fn document(command: &str, ok: bool, mut body: Value, problems: &[Problem]) -> Value {
    let mut doc = serde_json::Map::new();
    doc.insert("schema_version".into(), json!(SCHEMA_VERSION));
    doc.insert("command".into(), json!(command));
    doc.insert("ok".into(), json!(ok));
    doc.append(body.as_object_mut().expect("object"));
    doc.insert("problems".into(), json!(problems));
    Value::Object(doc)
}

fn flatten_cmd(ctx: &Ctx, input: &Path, format: Format) -> Result<Report, Fatal> {
    let cfg = load(ctx, input)?;
    let b = build(ctx.dns, &cfg)?;
    ctx.diag(&b.problems);
    ctx.note(&summary(&cfg, &b));
    let mut problems = b.problems.clone();
    problems.extend(cfg.warnings.iter().map(|w| Problem {
        severity: Severity::Warning,
        path: String::new(),
        message: w.clone(),
    }));
    let text = match format {
        Format::Plain => output::plain(&b.plan),
        Format::Zone | Format::Json => output::zone(&cfg, &b.plan),
    };
    Ok(Report {
        ok: true,
        text,
        json: document("flatten", true, plan_json(&cfg, &b), &problems),
    })
}

fn import_cmd(ctx: &Ctx, domain: &str) -> Result<Report, Fatal> {
    let domain = spf::domain_spec(domain).map_err(Fatal::new)?;
    match import::import(&domain, ctx.dns) {
        Ok(imported) => {
            ctx.diag(&imported.problems);
            let body = json!({ "domain": domain, "config": imported.config });
            Ok(Report {
                ok: true,
                json: document("import", true, body, &imported.problems),
                text: imported.config,
            })
        }
        Err(problems) => Err(Fatal {
            message: format!("{domain} has no usable SPF record to import"),
            problems,
        }),
    }
}

/// Import the live record and flatten it, for check's suggestion. Sources
/// named in `keep` stay live.
fn suggest(ctx: &Ctx, domain: &str, keep: &[String]) -> Result<(Config, Built), Fatal> {
    let imported = import::import(domain, ctx.dns).map_err(|problems| Fatal {
        message: "could not import the record".into(),
        problems,
    })?;
    let mut cfg = Config::parse(&imported.config).map_err(Fatal::new)?;
    for (term, k) in cfg.terms.iter().zip(cfg.keep.iter_mut()) {
        *k |= keep.contains(&term.to_string());
    }
    // Suggest the least flattening that fixes the record.
    cfg.strategy = Strategy::Minimal;
    ctx.apply(&mut cfg)?;
    let b = build(ctx.dns, &cfg)?;
    Ok((cfg, b))
}

fn check_cmd(ctx: &Ctx, domain: &str) -> Result<Report, Fatal> {
    let domain = spf::domain_spec(domain).map_err(Fatal::new)?;
    let mut ev = Evaluator::new(ctx.dns);
    let Some(flat) = ev.evaluate_domain(&domain) else {
        return Err(Fatal {
            message: format!("{domain} has no usable SPF record"),
            problems: ev.problems,
        });
    };
    let record = ctx
        .dns
        .txt(&domain)?
        .into_iter()
        .find(|t| spf::is_spf(t))
        .unwrap_or_default();

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
    let ok = !errors(&problems);
    ctx.diag(&problems);
    let prefixes = flatten::summarize(&flat.pass, &[]).len();

    let mut text = format!("{domain}\n  {record}\n\n{}\n", output::tree(&flat.tree));
    text.push_str(&format!(
        "lookups:      {} of {MAX_LOOKUPS}\n\
         void lookups: {} of {MAX_VOIDS}\n\
         record size:  {} bytes\n\
         authorizes:   {prefixes} prefixes, {} per-message terms\n",
        flat.lookups,
        flat.voids,
        record.len(),
        flat.live.len()
    ));

    let dmarc = match advice::dmarc(&domain, ctx.dns) {
        Ok(d) => {
            text.push_str(&format!(
                "dmarc:        {}\n",
                d.as_ref().map_or("none published".into(), |d| format!(
                    "p={} at {}",
                    d.policy, d.name
                ))
            ));
            Some(d)
        }
        Err(e) => {
            ctx.note(&format!("DMARC not checked: {e}"));
            None
        }
    };

    let mut recommendations = spf::Record::parse(&record)
        .map(|r| advice::own_hosts(&domain, &r, ctx.dns))
        .unwrap_or_default();
    if let Some(d) = &dmarc {
        recommendations.extend(advice::policy(&domain, flat.all, d.as_ref()));
    }
    if !recommendations.is_empty() {
        text.push_str("\nrecommendations:\n");
        for a in &recommendations {
            text.push_str(&format!("  [{}] {}\n", a.code, a.message));
        }
    }

    let keep: Vec<String> = recommendations
        .iter()
        .filter(|a| a.code == "keep-own-host")
        .filter_map(|a| a.term.clone())
        .collect();
    let needed = flat.lookups > MAX_LOOKUPS || flat.voids > MAX_VOIDS;
    let suggested = match suggest(ctx, &domain, &keep) {
        Ok((cfg, b)) => {
            text.push_str(&format!(
                "\nsuggested flattened records ({} of {} lookups, verified{}):\n{}",
                b.plan.lookups,
                cfg.max_lookups,
                if needed {
                    ""
                } else {
                    "; not needed, the record is within limits"
                },
                output::zone(&cfg, &b.plan)
            ));
            if let Some(m) = &b.minimal {
                text.push_str("\nminimal flattening, lowest drift risk first:\n");
                for c in &m.choices {
                    text.push_str(&format!(
                        "  {:<9} {:<6} {} ({})\n",
                        if c.flattened { "flattened" } else { "live" },
                        c.level.to_string(),
                        c.source,
                        c.reason
                    ));
                }
            }
            let mut v = plan_json(&cfg, &b);
            v["ok"] = json!(true);
            v["needed"] = json!(needed);
            v
        }
        Err(f) => {
            text.push_str(&format!("\nno flattened suggestion: {}\n", f.message));
            for p in &f.problems {
                text.push_str(&format!("  {p}\n"));
            }
            json!({ "ok": false, "error": f.message, "problems": f.problems })
        }
    };

    let body = json!({
        "domain": domain,
        "record": record,
        "bytes": record.len(),
        "lookups": flat.lookups,
        "max_lookups": MAX_LOOKUPS,
        "void_lookups": flat.voids,
        "max_void_lookups": MAX_VOIDS,
        "policy": flat.all.map(|q| format!("{}all", q.prefix())),
        "dmarc": dmarc.flatten(),
        "prefixes": prefixes,
        "live": flat.live,
        "tree": flat.tree,
        "recommendations": recommendations,
        "suggested": suggested,
    });
    Ok(Report {
        ok,
        text,
        json: document("check", ok, body, &problems),
    })
}

#[derive(Serialize)]
struct PolicyChange {
    config: String,
    published: String,
}

fn diff_cmd(ctx: &Ctx, input: &Path) -> Result<Report, Fatal> {
    let cfg = load(ctx, input)?;
    let b = build(ctx.dns, &cfg)?;
    let plan = &b.plan;

    let overlay = Overlay::new(
        ctx.dns,
        plan.records
            .iter()
            .map(|r| (r.name.clone(), r.value.clone())),
    );
    let want = Evaluator::new(&overlay)
        .evaluate_domain(&cfg.domain)
        .ok_or_else(|| Fatal::new("could not evaluate the generated records"))?;
    let mut ev = Evaluator::new(ctx.dns);
    let have = ev.evaluate_domain(&cfg.domain);
    let mut problems = b.problems.clone();
    problems.extend(ev.problems);
    ctx.diag(&problems);

    let cmp = flatten::compare(&want, have.as_ref().unwrap_or(&Flat::default()));
    let mut text_differs = false;
    for r in &plan.records {
        let published: Vec<String> = ctx
            .dns
            .txt(&r.name)?
            .into_iter()
            .filter(|t| spf::is_spf(t))
            .collect();
        if published.as_slice() != std::slice::from_ref(&r.value) {
            text_differs = true;
        }
    }
    let mut stale = Vec::new();
    for n in plan.records.len().. {
        let name = cfg.chain_name(n);
        if !ctx.dns.txt(&name)?.iter().any(|t| spf::is_spf(t)) {
            break;
        }
        stale.push(name);
    }
    let in_sync = have.is_some() && cmp.is_empty();

    let mut text = String::new();
    if have.is_none() {
        text.push_str(&format!("{} has no usable SPF record\n", cfg.domain));
    }
    for p in cmp.missing.iter().chain(&cmp.missing_live) {
        text.push_str(&format!("+ {p}\n"));
    }
    for p in cmp.extra.iter().chain(&cmp.extra_live) {
        text.push_str(&format!("- {p}\n"));
    }
    if let Some((want, have)) = &cmp.all {
        text.push_str(&format!("policy: published {have}, config has {want}\n"));
    }
    for name in &stale {
        text.push_str(&format!(
            "note: {name} is still published but no longer included; it can be removed\n"
        ));
    }
    if in_sync {
        text.push_str(if text_differs {
            "in sync: the published records authorize the same senders (text differs)\n"
        } else {
            "in sync\n"
        });
    } else {
        text.push_str(&format!(
            "\nout of sync; publish:\n{}",
            output::zone(&cfg, plan)
        ));
    }

    let body = json!({
        "domain": cfg.domain,
        "in_sync": in_sync,
        "published": have.is_some(),
        "missing": cmp.missing,
        "extra": cmp.extra,
        "missing_live": cmp.missing_live,
        "extra_live": cmp.extra_live,
        "policy": cmp.all.as_ref().map(|(want, have)| PolicyChange {
            config: want.clone(),
            published: have.clone(),
        }),
        "text_differs": text_differs,
        "stale_records": stale,
        "lookups": plan.lookups,
        "max_lookups": cfg.max_lookups,
        "widening": plan.widening,
        "records": output::json_records(&cfg, plan),
    });
    Ok(Report {
        ok: in_sync,
        text,
        json: document("diff", in_sync, body, &problems),
    })
}

fn risk_cmd(
    ctx: &Ctx,
    input: &Path,
    state_path: Option<&Path>,
    fail_on: Option<FailOn>,
) -> Result<Report, Fatal> {
    let cfg = load(ctx, input)?;
    let b = build(ctx.dns, &cfg)?;
    ctx.diag(&b.problems);

    let mut state = match state_path {
        Some(p) if p.exists() => {
            let s: State = serde_json::from_str(&read(p)?)
                .map_err(|e| Fatal::new(format!("{}: {e}", p.display())))?;
            if s.domain != cfg.domain {
                return Err(Fatal::new(format!(
                    "{} records {}, not {}",
                    p.display(),
                    s.domain,
                    cfg.domain
                )));
            }
            Some(s)
        }
        Some(_) => Some(State {
            schema_version: SCHEMA_VERSION,
            domain: cfg.domain.clone(),
            ..State::default()
        }),
        None => None,
    };
    let risks = risk::assess(&cfg, &b.expected, ctx.dns, state.as_mut(), risk::now());
    if let (Some(p), Some(s)) = (state_path, &state) {
        let text = serde_json::to_string_pretty(s).expect("serializable") + "\n";
        write(Some(p), &text)?;
    }
    let headroom = cfg.max_lookups.saturating_sub(b.plan.lookups);
    let suggestions = risk::suggest(&risks, headroom);
    let worst = risks.iter().map(|r| r.level).max().unwrap_or(Level::Low);
    let ok = match fail_on {
        Some(FailOn::Medium) => worst < Level::Medium,
        Some(FailOn::High) => worst < Level::High,
        None => true,
    };

    let mut text = format!(
        "{}: {} of {} lookups after flattening, {headroom} to spare\n\n",
        cfg.domain, b.plan.lookups, cfg.max_lookups
    );
    text.push_str(&output::risk(&risks, &suggestions));
    if state_path.is_none() {
        text.push_str(
            "\nheuristics only: run with --state FILE on a schedule to score observed changes\n",
        );
    }
    let body = json!({
        "domain": cfg.domain,
        "lookups": b.plan.lookups,
        "max_lookups": cfg.max_lookups,
        "spare_lookups": headroom,
        "worst": worst,
        "state_file": state_path.map(|p| p.display().to_string()),
        "sources": risks,
        "suggestions": suggestions,
    });
    Ok(Report {
        ok,
        text,
        json: document("risk", ok, body, &b.problems),
    })
}
