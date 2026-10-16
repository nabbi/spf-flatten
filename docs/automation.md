# Automation

Flattened records go stale when providers change their ranges, so the useful
setup is a scheduled job that checks for drift and either alerts or republishes.
Every command can print one JSON document (`--json`, see [json.md](json.md))
and uses exit codes scripts can branch on:

| Exit | Meaning |
|---|---|
| 0 | clean: in sync, no errors, risk under `--fail-on` |
| 1 | a finding: drift, record errors, risk at or over `--fail-on` |
| 2 | could not run: bad config, DNS failure, budget can't be met |

Treat 2 as "try again later or fix the config", never as drift.

## The loop

```sh
spf-flatten diff -i spf.toml          # 0 in sync, 1 republish, 2 broken
spf-flatten risk -i spf.toml --state state.json   # builds change history
```

Run `diff` often (hourly is cheap) and `risk --state` daily. Use the same
config for `flatten` and `diff`, so both make the same choices: set
`strategy = "minimal"` in the file rather than passing `--minimal` to one of
them.

## cron

```cron
# m h dom mon dow  command
15 * * * *  cd /etc/spf && spf-flatten -q diff -i example.com.toml >/var/log/spf-diff.log || mail -s "SPF drift: example.com" hostmaster@example.com </var/log/spf-diff.log
30 6 * * *  cd /etc/spf && spf-flatten -q risk -i example.com.toml --state example.com.state.json --fail-on high >/dev/null || echo "high drift risk" | mail -s "SPF risk: example.com" hostmaster@example.com
```

## systemd timer

`/etc/systemd/system/spf-diff.service`:

```ini
[Unit]
Description=Check SPF drift for example.com

[Service]
Type=oneshot
WorkingDirectory=/etc/spf
ExecStart=/usr/local/bin/spf-flatten -q diff -i example.com.toml
# Exit 1 (drift) marks the unit failed; hook OnFailure= to your alerting.
```

`/etc/systemd/system/spf-diff.timer`:

```ini
[Timer]
OnCalendar=hourly
RandomizedDelaySec=10m
Persistent=true

[Install]
WantedBy=timers.target
```

## GitHub Actions

Keep `spf.toml` in a repository, check daily, and open an issue on drift.
`state.json` is cached so risk history survives between runs.

```yaml
name: spf
on:
  schedule: [{ cron: "17 6 * * *" }]
  workflow_dispatch:

jobs:
  drift:
    runs-on: ubuntu-latest
    permissions: { issues: write }
    steps:
      - uses: actions/checkout@v4
      - run: cargo install --locked spf-flatten
      - uses: actions/cache@v4
        with: { path: state.json, key: spf-state-${{ github.run_id }}, restore-keys: spf-state- }
      - name: risk
        run: spf-flatten -q --json risk -i spf.toml --state state.json > risk.json || true
      - name: diff
        id: diff
        run: |
          set +e
          spf-flatten -q --json diff -i spf.toml > diff.json
          echo "status=$?" >> "$GITHUB_OUTPUT"
      - name: report drift
        if: steps.diff.outputs.status == '1'
        env: { GH_TOKEN: "${{ github.token }}" }
        run: |
          {
            echo "Mail from these addresses fails until republished:"
            jq -r '.missing[]' diff.json
            echo; echo "Publish:"; echo '```'
            jq -r '.records[] | "\(.name). \(.ttl) IN TXT " + ([.strings[] | @json] | join(" "))' diff.json
            echo '```'
          } > body.md
          gh issue create --title "SPF drift for $(jq -r .domain diff.json)" --body-file body.md
      - name: fail on error
        if: steps.diff.outputs.status == '2'
        run: jq -r .error diff.json; exit 1
```

## Reading results with jq

```sh
# Is mail failing right now? (addresses the config needs but DNS lacks)
spf-flatten -q --json diff -i spf.toml | jq -r '.missing[]'

# Only alert on breakage, not on stale extras:
spf-flatten -q --json diff -i spf.toml | jq -e '.missing == [] and .missing_live == []'

# Lookup headroom of a live domain:
spf-flatten -q --json check example.com | jq '.max_lookups - .lookups'

# Which sources the minimal strategy flattened:
spf-flatten -q --json flatten -i spf.toml | jq -r '.minimal.choices[] | select(.flattened) | .source'

# High-risk sources and why:
spf-flatten -q --json risk -i spf.toml | jq -r '.sources[] | select(.level == "high") | "\(.source): \(.reasons | join("; "))"'
```

## Publishing

`flatten --json` gives each record's `strings`, ready for any DNS API. Publish
chained records (`_spf1`, `_spf2`...) before the apex, so the apex never points
at a record that doesn't exist yet, and delete `stale_records` from `diff` after.

### RFC 2136 (BIND, Knot, PowerDNS) with nsupdate

```sh
spf-flatten -q --json flatten -i spf.toml > plan.json
{
  echo "server ns1.example.com"
  echo "zone example.com"
  # chain records first, apex last
  jq -r '(.records[1:] + .records[:1])[] |
    "update delete \(.name). TXT\nupdate add \(.name). \(.ttl) TXT " + ([.strings[] | @json] | join(" "))' plan.json
  echo "send"
} | nsupdate -k /etc/bind/spf-update.key
```

`update delete NAME TXT` removes every TXT record at that name. If the apex
holds other TXT records (site verification tokens and the like), delete only the
old SPF value instead: `update delete example.com. TXT "v=spf1 ..."`.

### Cloudflare

```sh
spf-flatten -q --json flatten -i spf.toml > plan.json
for name in $(jq -r '(.records[1:] + .records[:1])[].name' plan.json); do
  value=$(jq -r --arg n "$name" '.records[] | select(.name == $n) | .value' plan.json)
  id=$(curl -s -H "Authorization: Bearer $CF_TOKEN" \
    "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=TXT&name=$name" |
    jq -r '.result[] | select(.content | startswith("\"v=spf1") or startswith("v=spf1")) | .id' | head -1)
  body=$(jq -n --arg n "$name" --arg v "$value" '{type:"TXT", name:$n, content:$v, ttl:3600}')
  if [ -n "$id" ]; then
    curl -s -X PUT -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json" \
      "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$id" -d "$body" >/dev/null
  else
    curl -s -X POST -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json" \
      "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" -d "$body" >/dev/null
  fi
done
```

### AWS Route 53

```sh
spf-flatten -q --json flatten -i spf.toml |
  jq '{Changes: [(.records[1:] + .records[:1])[] | {Action: "UPSERT",
        ResourceRecordSet: {Name: .name, Type: "TXT", TTL: .ttl,
          ResourceRecords: [{Value: ([.strings[] | @json] | join(" "))}]}}]}' > change.json
aws route53 change-resource-record-sets --hosted-zone-id "$ZONE_ID" --change-batch file://change.json
```

Route 53 applies a change batch atomically, so order matters less there. UPSERT
replaces every TXT value at the name; if the apex has other TXT records, include
them in the batch.

## Republish automatically, or alert?

Republishing on every `diff` exit 1 keeps mail flowing, but it also publishes
whatever a provider's DNS says, including a mistake or a compromise. A safer
middle ground: republish automatically only when the change adds addresses
(`missing` non-empty, `extra` empty), and alert a person when addresses would be
removed or a policy changed.

```sh
spf-flatten -q --json diff -i spf.toml > diff.json
case $? in
  0) exit 0 ;;
  2) echo "diff failed: $(jq -r .error diff.json)" >&2; exit 2 ;;
esac
if jq -e '.extra == [] and .extra_live == [] and .policy == null' diff.json >/dev/null; then
  ./publish.sh diff.json          # additions only: safe to apply
else
  ./alert.sh diff.json            # removals or policy change: a person decides
fi
```
