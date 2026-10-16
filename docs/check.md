# `check` advice

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
