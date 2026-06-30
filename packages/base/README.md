# @hors/base

Zero-dependency HTTP security headers middleware.
17 security headers. ~130 lines of code. Full control.

## Install

npm install @hors/base

## Quick Start

const { hors } = require('@hors/base');

app.use(hors());

This sets all 17 headers with secure defaults:

| Header | Default value |
|--------|---------------|
| Content-Security-Policy | default-src 'self'; frame-ancestors 'none'; upgrade-insecure-requests |
| Strict-Transport-Security | max-age=31536000; includeSubDomains |
| X-Content-Type-Options | nosniff |
| X-Frame-Options | DENY |
| X-XSS-Protection | 0 |
| Referrer-Policy | strict-origin-when-cross-origin |
| Permissions-Policy | camera=(), microphone=(), geolocation=() |
| Cross-Origin-Resource-Policy | same-origin |
| Cross-Origin-Opener-Policy | same-origin |
| Cross-Origin-Embedder-Policy | disabled |
| Cache-Control | no-store, max-age=0 |
| X-Permitted-Cross-Domain-Policies | none |
| X-Download-Options | noopen |
| X-DNS-Prefetch-Control | off |
| X-Powered-By | hidden |
| Origin-Agent-Cluster | ?1 |

## Configuration

Any header can be overridden or disabled:

app.use(hors({
  // Override CSP
  csp: "default-src 'self'; script-src 'self' cdn.example.com",

  // Configure HSTS
  hsts: {
    maxAge: 63072000,
    includeSubDomains: true,
    preload: true,
  },

  // Disable what you don't need
  csp: false,
  frameGuard: false,
  coep: 'credentialless',

  // For servers behind a proxy
  trustProxy: true,
}));

## Important: middleware order

Hors uses setIfNotSet — it does not overwrite headers
that you set manually or through other middleware.

This means:
- Middleware before hors: can set headers, hors won't touch them
- Middleware after hors: hors has already set everything

If you need to override a header after hors —
use hors at the route level, not globally.

## HSTS and localhost

HSTS is not set on:
- localhost, 127.0.0.1, ::1, 0.0.0.0
- HTTP connections
- Requests without a Host header

This prevents browsers from locking down your dev server.

## Compatibility

- Node.js: 16, 18, 20, 22, 24, 26
- Frameworks: Express 4+, Fastify 3+, Koa 2+
- Dependencies: 0

## API

hors(options?) — creates middleware. All options are optional.

Utilities are exported separately:
const { isHttps, isLocalhost, sanitizeOptions } = require('@hors/base');

## Don't want npm?

Copy src/index.js into your project. It's ~130 lines. Works without installation.

## License

MIT