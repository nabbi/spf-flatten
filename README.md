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
- `--minimal`, `--headroom N`: the minimal strategy ([strategies](docs/strategies.md))
- `--nameserver IP` (repeatable, default 1.1.1.1), `--system-resolver`, or
  `--dns-file FILE` (fixtures, see `tests/fixtures/zone.txt`). The default
  avoids local resolvers whose blocklists or split views skew results.

## Documentation

- [Strategies and drift risk](docs/strategies.md): how much to flatten, and how `risk` scores sources
- [`check` advice](docs/check.md): own-host (`a`/`mx`) findings and `all`/DMARC advice
- [Config](docs/config.md): sources, widening, and what can't be flattened
- [Automation](docs/automation.md): cron and systemd timers, CI, DNS APIs, alerting
- [JSON output](docs/json.md): the `--json` schema
- [Building and testing](docs/development.md): build, property tests, fuzzing

## Install

With Homebrew (macOS or Linux), from the
[oubliette tap](https://github.com/nabbi/homebrew-oubliette):

```sh
brew install nabbi/oubliette/spf-flatten
```

Or with Cargo, or from a checkout:

```sh
cargo install --locked --git https://github.com/nabbi/spf-flatten
cargo build --release --locked     # target/release/spf-flatten
```

Requires Rust 1.88 or newer. CIDR aggregation comes from
[route-summarization](https://github.com/nabbi/route-summarization-rs).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
