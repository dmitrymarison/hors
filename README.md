# Hors 🛡️

HTTP security headers middleware without magic.
0 dependencies (base). Transparent. Understandable.
Your server under a protective circle of light.

## Philosophy

Hors (Khors) is the Slavic god of the solar disk,
the protective light that draws the boundary between the world of people and darkness.

This library does the same for your server:
surrounds it with proper HTTP security headers.
No magic. No black boxes. Every header is explained and intentional.

## Packages

| Package | For | Size | Dependencies |
|---------|-----|------|--------------|
| @hors/base | APIs, microservices (90%) | ~3 KB | 0 |
| @hors/advanced | SPAs, SSR (8%) | ~5 KB | 2 (base, utils) |
| @hors/utils | Custom solutions (2%) | ~4 KB | 0 |

## Quick Start

npm install @hors/base

const { hors } = require('@hors/base');

// Defaults that just work
app.use(hors());

// With custom options
app.use(hors({
  csp: "default-src 'self'; script-src 'self' cdn.example.com",
  trustProxy: true,
}));

## Comparison with helmet

| Criteria | helmet | @hors/base |
|----------|--------|------------|
| Dependencies | 10+ | 0 |
| node_modules size | 120+ KB | ~3 KB |
| Lines of code | 2000+ | ~130 |
| Understandability | Low (black box) | High (every header explained) |
| CSP parser | Complex, object-based | Honest string |
| Customization | Nested objects | Flat config or false |
| Node.js support | 16+ | 16–26 |
| ESM | Via TypeScript | Native .mjs files |

## Should you use this in production?

Hors is built for conscious control over security headers.

If you need a solution backed by the Node.js security working group —
use helmet (https://helmetjs.github.io/).

If you want:
- To understand every header and why it's there
- To control every line of your security code
- Zero dependencies
- To learn how HTTP security headers work

— then Hors is for you.

## Don't want npm at all?

Copy packages/base/src/index.js into your project.
It's ~130 lines with comments. Remove the comments and it's 80 lines.
Fully self-contained. Works without installation.

## Project Structure

hors/
├── packages/
│   ├── base/          @hors/base — 17 headers, 0 dependencies
│   ├── advanced/      @hors/advanced — dynamic CSP and nonce
│   └── utils/         @hors/utils — helpers and utilities
├── examples/
│   ├── express/
│   ├── fastify/
│   └── koa/
├── README.md
└── LICENSE

## License

MIT