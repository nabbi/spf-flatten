#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Build and run the libFuzzer targets on a stable toolchain (no cargo-fuzz or
# nightly needed: only the sanitizer-coverage instrumentation is used, which
# safe Rust doesn't need ASan for). With cargo-fuzz installed,
# `cargo fuzz run <target>` works on this directory as well.
#
#   fuzz/run.sh                  build, then run every target for 60s
#   fuzz/run.sh flatten 600      run one target for 600s
#   fuzz/run.sh flatten 0        run until stopped
#
# Replay a crash: target/<host triple>/release/<target> artifacts/<target>/crash-...
set -eu
cd "$(dirname "$0")"

triple=$(rustc -vV | sed -n 's/^host: //p')
RUSTFLAGS="--cfg fuzzing -Cdebug-assertions -Coverflow-checks -Cpasses=sancov-module \
-Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
-Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares" \
    cargo build --release --target "$triple" --bins
bin=target/$triple/release

targets=${1:-"spf_record config split_strings zone_eval flatten"}
secs=${2:-60}
[ $# -gt 0 ] && shift
[ $# -gt 0 ] && shift

for t in $targets; do
    mkdir -p "corpus/$t" "artifacts/$t"
    dict=""
    [ -f "dict/$t.dict" ] && dict="-dict=dict/$t.dict"
    seeds=""
    [ -d "seeds/$t" ] && seeds="seeds/$t"
    echo "== $t (${secs}s)"
    "$bin/$t" -artifact_prefix="artifacts/$t/" -max_total_time="$secs" -timeout=10 \
        -rss_limit_mb=2048 -print_final_stats=1 $dict "$@" "corpus/$t" $seeds
done
