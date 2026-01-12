# PlugCrossOriginProtection

[![Hex.pm](https://img.shields.io/hexpm/v/plug_cross_origin_protection.svg)](https://hex.pm/packages/plug_cross_origin_protection)
[![Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/plug_cross_origin_protection)

A Plug to protect against Cross-Site Request Forgery (CSRF) attacks using modern
header-based checks instead of tokens.

Based on [Filippo Valsorda's blog post](https://words.filippo.io/csrf/) and the
[Go 1.25 `net/http` CrossOriginProtection](https://pkg.go.dev/net/http@go1.25rc2#CrossOriginProtection).

## How it works

Modern browsers (since 2023) send the `Sec-Fetch-Site` header which reliably
indicates whether a request is same-origin, same-site, cross-site, or
user-initiated. This plug uses that header (with a fallback to `Origin` header
comparison) to reject cross-origin requests without requiring CSRF tokens.

1. **Safe methods** (GET, HEAD, OPTIONS) are always allowed
2. If `Origin` header matches a **trusted origin**, the request is allowed
3. If `Sec-Fetch-Site` is `same-origin` or `none`, the request is allowed
4. If `Sec-Fetch-Site` indicates cross-origin, the request is **rejected**
5. If no headers are present, the request is allowed (non-browser client)
6. If only `Origin` is present, it's compared against the `Host` header

## Installation

Add `plug_cross_origin_protection` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:plug_cross_origin_protection, "~> 0.1.0"}
  ]
end
```

## Usage

### Basic usage

If you're using Phoenix, `PlugCrossOriginProtection` is a direct replacement for
the `protect_from_forgery` helper which invokes
[`Plug.CSRFProtection`](https://hexdocs.pm/plug/Plug.CSRFProtection.html).

```diff
# In your YourAppWeb.Router
- plug :protect_from_forgery
+ plug PlugCrossOriginProtection
```

### With trusted origins

For SSO callbacks or partner integrations:

```elixir
plug PlugCrossOriginProtection,
  trusted_origins: [
    "https://sso.example.com",
    "https://partner.example.com"
  ]
```

## Security considerations

- **Safe methods**: Ensure your application never performs state-changing actions
  on GET, HEAD, or OPTIONS requests
- **HTTPS**: Use HTTPS in production. The `Sec-Fetch-Site` header is only sent to
  secure origins
- **HSTS**: Consider using HTTP Strict Transport Security to protect against
  HTTP→HTTPS attacks on older browsers
- **Browser support**: `Sec-Fetch-Site` is supported in all major browsers since
  2023. Older browsers fall back to Origin/Host comparison

## License

MIT License. See [LICENSE](LICENSE) for details.
