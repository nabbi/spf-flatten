# Config

See [`examples/spf.toml`](../examples/spf.toml). Each `[[source]]` sets exactly one
of `include`, `a`, `mx`, `ptr`, `exists`, `ip4` or `ip6` (a list is allowed for
`ip4` and `ip6`). For `a`, `mx` and `ptr`, `"@"` means the domain itself.
`keep = true` pins a source live under either strategy; it still counts against
`max_lookups`.

## Widening (use with care)

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
