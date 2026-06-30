# @hors/utils

Utilities for building custom security headers middleware.
0 dependencies. Works standalone, without @hors/base.

## Install

npm install @hors/utils

## Features

- Generate cryptographically secure nonces
- Parse, format, and merge CSP policies
- Inject nonce and strict-dynamic into CSP
- Check HTTPS and localhost
- Factory for creating custom middleware

## Quick Start

const {
  generateNonce,
  parseCSP,
  mergeCSP,
  injectNonce,
  addStrictDynamic,
  createHeaderSetter,
} = require('@hors/utils');

## Generate a nonce

const nonce = generateNonce();
const long = generateNonce(32);

## Working with CSP

### Parsing

parseCSP("default-src 'self'; script-src 'self' cdn.com; upgrade-insecure-requests");

Result:
{
  'default-src': ["'self'"],
  'script-src': ["'self'", 'cdn.com'],
  'upgrade-insecure-requests': []
}

### Formatting

stringifyCSP({
  'default-src': ["'self'"],
  'script-src': ["'self'", "'unsafe-inline'"],
});

Result: "default-src 'self'; script-src 'self' 'unsafe-inline'"

### Merging

mergeCSP(
  "default-src 'self'",
  "script-src 'self' cdn.example.com",
  { 'script-src': ["'unsafe-inline'"] }
);

Result: "default-src 'self'; script-src 'self' cdn.example.com 'unsafe-inline'"

### Injecting a nonce

injectNonce(
  "default-src 'self'; script-src 'self'",
  'abc123',
  ['script-src']
);

Result: "default-src 'self'; script-src 'self' 'nonce-abc123'"

### strict-dynamic

addStrictDynamic("script-src 'self' 'nonce-abc123'");
Result: "script-src 'self' 'nonce-abc123' 'strict-dynamic'"

Without script-src — copies from default-src:
addStrictDynamic("default-src 'self'");
Result: "default-src 'self'; script-src 'self' 'strict-dynamic'"

## HTTPS checks

isHttps({ secure: true });                              // true
isHttps({ secure: false, headers: { 'x-forwarded-proto': 'https' } }, true); // true
isLocalhost({ headers: { host: 'localhost:3000' } });    // true
isLocalhost({ headers: { host: 'example.com' } });       // false

## Creating custom middleware

const { createHeaderSetter } = require('@hors/utils');

// Static header
app.use(createHeaderSetter('X-Frame-Options', 'DENY'));

// Dynamic header
app.use(createHeaderSetter('X-Request-Id', (req) => req.id));

## Normalizing CSP values

const { normalizeCSPValue } = require('@hors/utils');

normalizeCSPValue('self');            // "'self'"
normalizeCSPValue("'self'");          // "'self'"
normalizeCSPValue('cdn.example.com'); // 'cdn.example.com'
normalizeCSPValue('nonce-abc123');    // "'nonce-abc123'"

## Validating directives

const { isValidCSPDirective } = require('@hors/utils');

isValidCSPDirective('script-src');   // true
isValidCSPDirective('invalid');      // false

## All exports

| Function | Description |
|----------|-------------|
| generateNonce(byteLength?) | Generate a nonce |
| parseCSP(cspString) | Parse CSP string to object |
| stringifyCSP(cspObject) | Object to CSP string |
| mergeCSP(...policies) | Merge multiple CSPs |
| injectNonce(csp, nonce, directives?) | Inject nonce into CSP |
| addStrictDynamic(csp) | Add strict-dynamic |
| normalizeCSPValue(value) | Normalize CSP value |
| isHttps(req, trustProxy?) | Check HTTPS |
| isLocalhost(req) | Check localhost |
| createHeaderSetter(name, value) | Middleware factory |
| isValidCSPDirective(directive) | Validate directive name |

## License

MIT