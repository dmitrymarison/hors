# @hors/advanced

Extended security headers with dynamic CSP and nonce.
Built on top of @hors/base.

## Install

npm install @hors/advanced

## Features

- Dynamic CSP — unique nonce generated per request
- CSP Report-Only — test policies without blocking
- strict-dynamic — modern CSP approach (CSP Level 3)
- Report Endpoint — collect CSP violation reports
- Everything from @hors/base included

## Quick Start

const { hors } = require('@hors/advanced');

// With nonce for scripts
app.use(hors({
  nonce: { enabled: true },
}));

// Access the nonce in templates
app.use((req, res) => {
  console.log(res.locals.cspNonce);
  // Use in <script nonce="...">
});

## Nonce configuration

app.use(hors({
  nonce: {
    enabled: true,
    byteLength: 32,
    directives: ['script-src', 'style-src'],
  },
}));

## CSP Report-Only

Test new policies without the risk of breaking your site:

app.use(hors({
  csp: "default-src 'self'; script-src 'self' new-cdn.com",
  cspReportOnly: true,
  cspReportEndpoint: '/api/csp-violations',
}));

The browser will send violation reports to /api/csp-violations
but won't block any scripts.

## strict-dynamic

Modern approach: allow a script with a nonce to load other scripts:

app.use(hors({
  nonce: { enabled: true },
  strictDynamic: true,
}));

The CSP becomes: script-src 'nonce-abc123' 'strict-dynamic'
This allows a script with a nonce to dynamically create script elements.

## Important: middleware order

Place hors from @hors/advanced before other middleware
that might set CSP. This ensures the dynamic CSP is not overwritten.

Correct:
app.use(hors({ nonce: { enabled: true } }));
app.use(compression());
app.use(express.static('public'));

Incorrect:
app.use(compression());
app.use(hors({ nonce: { enabled: true } }));

## API

hors(options?) — creates middleware with dynamic CSP.

generateNonce(byteLength?) — generates a cryptographically secure nonce.

buildDynamicCSP(baseCSP, nonceConfig, nonce, strictDynamic, reportEndpoint) —
builds the final CSP string with nonce, strict-dynamic and report-uri.

## License

MIT