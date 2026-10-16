# JSON output

With `--json`, every command prints exactly one JSON document on stdout, and
nothing else. Diagnostics still go to stderr; add `-q` to silence them.
`flatten -f json` prints the same document as `flatten --json`.

## Contract

- `schema_version` is `1`. It changes only for incompatible changes (a field
  removed, renamed or retyped). New fields can appear at any time, so ignore
  fields you don't know.
- Exit status matches `ok`: `0` when `ok` is true, `1` when the command found
  something (`ok` false), `2` when it could not run.
- On exit 2 the document is the error form below, so scripts can always parse
  stdout.
- Addresses are SPF terms (`ip4:192.0.2.0/24`, `ip6:2001:db8::/32`), prefixes
  are minimal and sorted (IPv4 first), and a host route has no length
  (`ip4:192.0.2.1`).

## Fields every document has

| Field | Type | |
|---|---|---|
| `schema_version` | int | `1` |
| `command` | string | `check`, `import`, `flatten`, `diff`, `risk` |
| `ok` | bool | see each command |
| `problems` | [Problem] | errors and warnings found while evaluating |

**Problem**: `{ "severity": "error" | "warning", "path": "example.com > include:x", "message": "..." }`.
`path` is the chain of domains being evaluated (may be empty).

**Error form** (exit 2): `{ schema_version, command, ok: false, error: "message", problems }`.

## Shared objects

**Record**: one TXT record to publish.

```json
{ "name": "_spf1.example.com", "ttl": 3600, "value": "v=spf1 ip4:...",
  "strings": ["v=spf1 ip4:...", " ip4:..."], "bytes": 412 }
```

`strings` is `value` split into the 255-byte character-strings a zone or DNS API
needs; concatenated, they equal `value`. Records are listed apex first.

**Plan**: what `flatten` produces, also nested in `check.suggested`.

| Field | Type | |
|---|---|---|
| `domain`, `policy` | string | `policy` is `-all`, `~all` or `?all` |
| `lookups`, `max_lookups` | int | lookups the records need, and the budget |
| `unflattened_lookups` | int | lookups the sources would need published as-is |
| `strategy` | string | `full` or `minimal` |
| `headroom` | int | lookups the minimal strategy leaves unused |
| `minimal` | Minimal \| null | the minimal strategy's choices |
| `prefixes` | int | flattened prefixes |
| `widening` | Widening \| null | set when `widen_ipv4`/`widen_ipv6` are configured |
| `records` | [Record] | |
| `kept` | [Live] | terms published verbatim |

**Live**: `{ "term": "include:x.example", "lookups": 2, "reason": "kept live" }`.

**Minimal**: `{ "target": 9, "lookups": 9, "choices": [Choice] }`, with one
choice per source that costs lookups:

```json
{ "source": "include:sendgrid.net", "flattened": true, "level": "low",
  "score": 1, "lookups": 2, "reason": "flattened: low drift risk, saves lookups" }
```

**Widening**: `{ "ipv4_prefix": 24, "ipv6_prefix": null, "widened": 4,
"extra_ipv4_addresses": 251, "extra_ipv6_64s": 0 }`.

## check

`ok` is false when the published record has errors: over 10 lookups or 2 void
lookups, a missing include target, several SPF records, and so on.

| Field | Type | |
|---|---|---|
| `domain`, `record` | string | the published record |
| `bytes` | int | its length |
| `lookups`, `max_lookups` | int | |
| `void_lookups`, `max_void_lookups` | int | |
| `policy` | string \| null | the effective `all` |
| `dmarc` | `{ name, policy }` \| null | the DMARC record that applies and its effective policy (`none`, `quarantine`, `reject`); null when none is published or the lookup failed |
| `prefixes` | int | prefixes it authorizes |
| `live` | [Live] | per-message terms (macros, `exists`, `ptr`) |
| `tree` | [Node] | evaluation tree |
| `recommendations` | [Advice] | own-host and `all`/DMARC advice |
| `suggested` | Plan + `ok`, `needed` | a verified minimal flattening; `needed` is false when the record already fits. On failure: `{ ok: false, error, problems }` |

**Node**: `{ term, lookups, void, ranges, hosts, ttl?, note?, children? }`.
`lookups` includes everything under the node; `ttl` is the lowest TTL of the
records the node itself looked up.

**Advice**: `{ code, term?, message }`. Codes: `redundant-own-host`,
`mx-inbound-gateway`, `keep-own-host`, `mx-not-authorized`, `all-neutral`,
`softfail-unenforced`, `fail-preempts-dmarc`.

## import

`{ domain, config }`, where `config` is the TOML text that `import` would
otherwise print.

## flatten

A Plan. `ok` is always true; anything that stops flattening is exit 2.

## diff

`ok` and `in_sync` are true when the published records authorize exactly the
senders the config would publish.

| Field | Type | |
|---|---|---|
| `in_sync` | bool | |
| `published` | bool | false when the domain has no usable SPF record |
| `missing` | [string] | addresses the config needs that DNS doesn't authorize: **mail from these fails now** |
| `extra` | [string] | addresses DNS still authorizes that the config dropped |
| `missing_live`, `extra_live` | [string] | the same for per-message terms |
| `policy` | `{ config, published }` \| null | set when the `all` differs |
| `text_differs` | bool | the records' text differs (even if in sync) |
| `stale_records` | [string] | chain records still published past the new chain's end |
| `lookups`, `max_lookups`, `widening` | | of the records to publish |
| `records` | [Record] | what to publish to get back in sync |

## risk

`ok` is false only when `--fail-on` is given and a source reaches that level.

| Field | Type | |
|---|---|---|
| `lookups`, `max_lookups` | int | after flattening with the config's strategy |
| `spare_lookups` | int | `max_lookups - lookups` |
| `worst` | string | highest level among sources |
| `state_file` | string \| null | |
| `sources` | [SourceRisk] | one per source except `ip4`/`ip6` |
| `suggestions` | [`{ source, lookups, advice }`] | which risky sources to keep live |

**SourceRisk**:

```json
{ "source": "include:cloud.example", "level": "high", "score": 4,
  "reasons": ["TTL 300s: ...", "5 of 5 prefixes are single addresses, ..."],
  "live": false, "kept": false, "lookups": 1, "prefixes": 5, "hosts": 5,
  "nested": 0, "min_ttl": 300,
  "history": { "checks": 12, "changes": 2, "first_seen": "2026-10-01T06:00:00Z",
               "last_changed": "2026-10-14T06:00:00Z",
               "added": ["ip4:192.0.2.40"], "removed": [] } }
```

`history` is present only with `--state`. `added`/`removed` list the changes
since the previous run.

## State file

`risk --state FILE` reads and rewrites a JSON file:

```json
{ "schema_version": 1, "domain": "example.com",
  "sources": { "include:sendgrid.net": {
      "prefixes": ["ip4:149.72.0.0/16", "..."],
      "first_seen": 1792108800, "last_checked": 1792195200,
      "last_changed": null, "checks": 2, "changes": 0 } } }
```

Times are Unix seconds. Keep one state file per domain, somewhere that
persists between runs (a CI cache, or a committed file).
