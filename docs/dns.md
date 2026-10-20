# DNS

Caddy obtains a certificate per hostname. Sitegate does not ask for a wildcard certificate, and it does not enable on-demand TLS. A wildcard DNS record is still useful: one name pattern covers the hub, `www`, `auth`, and every site you add later.

For `example.com`, publish either of these:

- `A` and `AAAA` for `example.com` and for `*.example.com`, or
- `A` and `AAAA` for `example.com`, `www.example.com`, `auth.example.com`, and each site subdomain.

Point every one of those names at the VPS. `www` is a permanent redirect to the apex. `auth` is the reverse proxy in front of the loopback check service. The apex serves the hub.

HTTP-01 and TLS-ALPN-01 both need the public ports in `sites.toml` (80 and 443 unless you changed them) to reach Caddy. Do not put another web server on those ports.

Check before you expect a certificate:

```sh
dig +short example.com
dig +short auth.example.com
dig +short hello.example.com
```

Internal TLS (`tls = "internal"`) is for a laptop or a lab. Caddy then signs with its local CA, and the example manifest turns that on. A public VPS should use `tls = "auto"` and set `acme_email`.

Adding a site does not require a new DNS record when `*.example.com` already points at the VPS. It does require a new certificate, which Caddy requests on the next reload after `sitegate deploy`.
