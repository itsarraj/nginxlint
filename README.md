# nginxlint

Lints an nginx config file for the misconfigurations that actually bite
in production — missing security headers, a leaked version string,
missing/weak TLS protocol pins, a wildcard server name paired with SSL,
and an upload endpoint with no body-size limit. Every one of these is a
real, common way a hand-written nginx config quietly ships broken.

## Usage

```bash
nginxlint /etc/nginx/sites-enabled/app.conf
cat app.conf | nginxlint            # reads stdin if no path is given
nginxlint app.conf --no-fail        # still prints findings, exits 0 regardless
```

Exit code `2` if any `error`-severity finding exists, `1` if only
`warning`s, `0` if clean (or with `--no-fail`).

## The five checks

- **Missing security headers**: no `X-Frame-Options` or
  `X-Content-Type-Options` anywhere in the server block or its locations.
- **`server_tokens on`**: leaks the nginx version in error pages and the
  `Server` response header — free reconnaissance for an attacker.
- **Missing `ssl_protocols`**: a server with `ssl_certificate` set but no
  explicit `ssl_protocols` falls back to nginx's compiled-in default,
  which can include old, weak TLS versions depending on how it was built.
- **Wildcard `server_name` + SSL**: `server_name *.example.com` on a
  server that also terminates SSL — a single cert almost never actually
  matches every possible subdomain that could hit it.
- **Missing `client_max_body_size` on an upload path**: a location that
  proxies to a backend (a `proxy_pass`, the shape an upload endpoint
  usually takes) with no `client_max_body_size` set on it or the
  enclosing server — falls back to nginx's 1MB default, which silently
  rejects any larger upload with a 413.

## Status: built and verified against a realistic misconfigured config and its fixed counterpart

- **31 unit tests** (`cargo test --lib`) across `parser` (nginx's real
  block-nesting syntax — `server { location { ... } }`, directives
  spanning to the next `;`, comments) and `rules` (each of the five
  checks in isolation, including that a *correctly* configured
  equivalent of each — `server_tokens off`, an explicit
  `ssl_protocols`, a non-wildcard `server_name`, a set
  `client_max_body_size` — produces zero false positives for that rule).
- **Live-verified against the actual compiled binary and two realistic
  configs**: a deliberately misconfigured server block (wildcard
  `server_name` + SSL, `server_tokens on`, no `ssl_protocols`, no
  security headers, an upload location with no body-size limit)
  produced exactly the 6 expected findings (2 errors, 4 warnings) with
  correct line numbers and exit code `2`; the same block with every
  issue fixed produced "clean, no findings" and exit code `0` — proving
  every rule has a real, working "already correct" path, not just a
  "flag everything" one.

**Not done / deliberately deferred**: `include`d files aren't followed
(a directive set in an included snippet looks missing from the block
that includes it — this only ever parses one file's own text); HTTP-level
directives set in the outer `http {}` block and inherited down into a
`server {}` that doesn't repeat them aren't tracked as "set" — each
server block is checked for what it *itself* declares, which can be a
false positive for a real config that intentionally sets shared
directives once at the top; and TLS cipher-suite auditing (which
specific ciphers are weak) — this only checks that `ssl_protocols` is
set at all, not which protocol versions or ciphers it lists (this
workspace's separate `tlsaudit` tool covers that deeper check, but
against a live endpoint rather than a config file).
