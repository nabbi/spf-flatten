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
$ spf-flatten import github.com -o spf.toml      # start from what's live
$ spf-flatten flatten -i spf.toml
; SPF for github.com flattened by spf-flatten 0.1.0: 58 prefixes, 3 of 10 lookups
github.com.       3600 IN TXT "v=spf1 ip4:37.188.97.188 ip4:40.92.0.0/15 ..." " ... exists:%{i}._spf.mta.salesforce.com include:_spf1.github.com include:_spf2.github.com ~all"
_spf1.github.com. 3600 IN TXT "v=spf1 ip4:134.128.64.0/18 ..."
_spf2.github.com. 3600 IN TXT "v=spf1 ip4:208.117.48.0/20 ... ip6:2c0f:fb50:4000::/36"
github.com: 58 prefixes in 3 record(s), 3 of 10 lookups (unflattened: 10)
```

## Commands

| Command | What it does | Exit status |
|---|---|---|
| `check DOMAIN` | Evaluate the published record: per-term lookup tree, lookup and void counts, size, problems | 1 on errors |
| `import DOMAIN [-o FILE]` | Write a config from the published record, with each source's lookup cost | 1 if there's no usable record |
| `flatten [-i FILE] [-f zone\|json\|plain] [-o FILE]` | Resolve, pack and verify; print the records | 2 on errors |
| `diff [-i FILE]` | Compare what the config would publish with what DNS serves now | 1 on drift |

`-i -` reads the config from stdin. Global options: `--nameserver IP`
(repeatable) to bypass the system resolver, and `--dns-file FILE` to answer
from a fixture file instead (see `tests/fixtures/zone.txt`).

Exit status 2 means the command could not run: a bad config, a DNS failure,
or a result that can't fit the budget.

## Config

See [`examples/spf.toml`](examples/spf.toml). Each `[[source]]` sets exactly one
of `include`, `a`, `mx`, `ptr`, `exists`, `ip4` or `ip6` (a list is allowed for
`ip4` and `ip6`). For `a`, `mx` and `ptr`, `"@"` means the domain itself.
`keep = true` publishes a source as a live term instead of flattening it.
Kept sources still count against `max_lookups`.

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

## Drift

Flattened records go stale when providers change their ranges. Run `diff`
on a schedule, and republish when it exits 1:

```sh
spf-flatten diff -i spf.toml || notify "SPF drift for example.com"
```

`diff` compares what the records *authorize*, not their text. A repack that
moves addresses between records but authorizes the same senders counts as
in sync.

## Build

```sh
cargo build --release --locked
cargo test
```

Requires Rust 1.88 or newer. CIDR aggregation comes from
[route-summarization](https://crates.io/crates/route-summarization).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
