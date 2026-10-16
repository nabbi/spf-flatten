# Building and testing

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

CI (`.github/workflows/ci.yml`) runs fmt and clippy, the tests on Linux and
macOS against stable and the 1.88 MSRV, and a 20000-case property run. Fuzzing
is too slow for CI; run `fuzz/run.sh` locally.
