# spf-flatten

Flatten SPF records to stay within the RFC 7208 limits: 10 DNS lookups,
2 void lookups, and records small enough for a single UDP answer.

You list the senders a domain needs. `spf-flatten` resolves them the way a
receiver would, replaces lookup terms with the `ip4:`/`ip6:` ranges they expand
to, aggregates those into the fewest CIDR blocks, and packs them into a chain of
TXT records. It then evaluates the generated records as if they were published
and refuses to print them unless they authorize exactly the same senders within
the limits.

```console
$ spf-flatten check github.com                   # what's wrong, and a fix
$ spf-flatten import github.com -o spf.toml      # start a config from what's live
$ spf-flatten flatten -i spf.toml --minimal      # flatten only what's needed
$ spf-flatten risk -i spf.toml --state state.json
$ spf-flatten diff -i spf.toml                   # on a schedule: has it drifted?
```

## Commands

| Command | What it does | Exit 1 when |
|---|---|---|
| `check DOMAIN` | Evaluate the published record: lookup tree, limits, own-host and `all`/DMARC advice, and a verified minimal flattening | the record has errors (over 10 lookups, missing includes...) |
| `import DOMAIN [-o FILE]` | Write a config from the published record, with each source's lookup cost | |
| `flatten [-i FILE] [-f zone\|json\|plain] [-o FILE]` | Resolve, pack and verify; print the records | |
| `diff [-i FILE]` | Compare what the config would publish with what DNS serves now | the published records authorize different senders |
| `risk [-i FILE] [--state FILE] [--fail-on medium\|high]` | Score each source's chance of drifting once flattened | a source reaches `--fail-on` |

Exit status 2 means the command could not run: a bad config, a DNS failure, or
a result that can't fit the budget. `-i -` reads the config from stdin.

Global options:

- `--json`: print one JSON document on stdout ([schema](docs/json.md))
- `-q`: no diagnostics on stderr
- `--minimal`, `--headroom N`: the minimal strategy (below)
- `--nameserver IP` (repeatable, default 1.1.1.1), `--system-resolver`, or
  `--dns-file FILE` (fixtures, see `tests/fixtures/zone.txt`). The default
  avoids local resolvers whose blocklists or split views skew results.

## Strategies: how much to flatten

Every flattened address is a snapshot. When a provider changes its ranges, a
flattened record keeps the old ones until you republish, and mail from the new
ones fails. A source left live (`include:`) can't go stale. So flatten as little
as you can.

- **`strategy = "full"`** (default): flatten every source except those marked
  `keep = true`. The fewest lookups, the most snapshots.
- **`strategy = "minimal"`** (or `--minimal`): start from the record as
  published, every source live, and flatten one source at a time, lowest drift
  risk first, until the record fits `max_lookups - headroom`. Then return any
  source that is no longer needed to live, riskiest first. `headroom` defaults
  to 1, so a provider adding a nested include doesn't push the record straight
  back over the limit. If the record already fits, nothing is flattened.

`check` always suggests the minimal plan and says what it flattened and why:

```
suggested flattened records (9 of 10 lookups, verified):
...
minimal flattening, lowest drift risk first:
  live      low    exists:%{i}._spf.mta.salesforce.com (live: not needed to meet the budget)
  flattened low    include:spf.protection.outlook.com (flattened: low drift risk, saves lookups)
  live      high   include:_spf.example-saas.com (live: not needed to meet the budget)
```

## Drift risk

`risk` scores each source from evidence the code can see:

| Signal | Why it predicts drift | Points |
|---|---|---|
| Authoritative TTL ≤ 300s / < 3600s | the publisher expects to change it soon | 2 / 1 |
| Mostly single-address prefixes (5+) | cloud instances get replaced | 2 (1 for 3+) |
| 2+ nested records | the provider can rearrange its tree | 1 |
| `a` / `mx` source | follows your own hosts as they move | 1 |
| Changed within 30 days (with `--state`) | observed churn | 3 (1 if older) |

0-1 points is **low**, 2-3 **medium**, 4+ **high**. Sources with nothing
flattened from them (kept, or only per-message terms) are always low.

TTLs come from each zone's own name servers, not the resolver: a caching
resolver returns TTLs that count down, which would make scores, and the minimal
strategy's choices, change from run to run.

History is the strongest signal. Run `risk --state FILE` on a schedule (daily is
plenty); each run records every source's resolved prefixes and counts changes.
DNS failures are never recorded as changes. `risk` also suggests which risky
sources to keep live within the spare lookups.

## Own hosts (`a` and `mx`)

`check` validates the record, then looks at the domain's own hosts:

- `redundant-own-host`: an `a`/`mx` term whose addresses other terms already
  cover. Removing it saves a lookup.
- `mx-inbound-gateway`: `mx` points at an inbound filtering service (Microsoft
  365, Google, Proofpoint, Mimecast...) that doesn't send your outbound mail.
- `keep-own-host`: an `a`/`mx` term that does authorize your hosts. Keep it live
  when flattening, so it follows host moves; `check`'s suggestion does.
- `mx-not-authorized`: the domain's MX hosts aren't authorized. Only MX hosts
  are checked; a domain's A record is usually its website, not a mail sender.

It also reads the `all` qualifier alongside the domain's DMARC policy, found at
`_dmarc.<domain>` or the nearest parent (using the parent's `sp=` when set):

- `all-neutral`: `?all` gives unlisted senders the same result as no SPF.
- `softfail-unenforced`: `~all` with no DMARC record, or `p=none`, so
  unlisted senders are usually still delivered.
- `fail-preempts-dmarc`: `-all` with `p=quarantine` or `p=reject`. Some
  receivers reject on the SPF fail before DMARC can accept a forwarded message
  on its DKIM signature; `~all` leaves that decision to DMARC.

`~all` with an enforcing DMARC policy, and `-all` without one, get no advice.

## Config

See [`examples/spf.toml`](examples/spf.toml). Each `[[source]]` sets exactly one
of `include`, `a`, `mx`, `ptr`, `exists`, `ip4` or `ip6` (a list is allowed for
`ip4` and `ip6`). For `a`, `mx` and `ptr`, `"@"` means the domain itself.
`keep = true` pins a source live under either strategy; it still counts against
`max_lookups`.

### Widening (use with care)

`widen_ipv4 = 24` / `widen_ipv6 = 48` round every flattened prefix out to at
least that size, so a provider adding a host next to its existing ones stays
covered. The cost is real: widening a cloud host to its /24 also authorizes
every other tenant on that /24 to send as you. Every run reports how many extra
addresses widening authorizes. Prefer the minimal strategy.

## What can't be flattened

- **Macros** (`exists:%{i}._spf.example`, `include:%{d}...`) depend on the
  message being checked. Terms that don't depend on the current domain are
  lifted into the top-level record. If an include's macros use `%{d}`, the
  whole include stays live.
- **`ptr`** is resolved per message. It is kept live, with a deprecation warning.
- **Non-pass terms** inside includes (`-ip4:...`) are honored: the addresses they
  match are taken out of later pass terms, as a receiver would. In the
  top-level sources only pass terms are supported. `import` drops the others
  and lists them in comments.

## Automation

See [docs/automation.md](docs/automation.md) for cron and systemd timers, CI,
publishing through DNS APIs, and alerting with `jq`.

## Build

```sh
cargo build --release --locked
cargo test
```

Requires Rust 1.88 or newer. CIDR aggregation comes from
[route-summarization](https://crates.io/crates/route-summarization).

`cargo test` includes property tests (`tests/properties.rs`; set
`PROPTEST_CASES` for longer runs). `fuzz/` holds libFuzzer targets for the SPF
parser, the config parser, zone fixtures with evaluation, TXT string splitting,
and the full flatten-then-verify promise. `fuzz/run.sh [target] [seconds]`
builds and runs them on a stable toolchain; `cargo fuzz run <target>` also
works where cargo-fuzz and nightly are installed.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
