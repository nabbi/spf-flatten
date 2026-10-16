# Strategies and drift risk

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
