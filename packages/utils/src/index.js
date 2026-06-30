'use strict';

/**
 * @module @hors/utils
 * @description Utilities for building custom security headers.
 * 0 dependencies. Node.js 16+.
 */

const crypto = require('node:crypto');

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** @type {Set<string>} */
const CSP_DIRECTIVES = new Set([
  'default-src', 'child-src', 'connect-src', 'font-src',
  'frame-src', 'img-src', 'manifest-src', 'media-src',
  'object-src', 'prefetch-src', 'script-src', 'script-src-elem',
  'script-src-attr', 'style-src', 'style-src-elem', 'style-src-attr',
  'worker-src', 'base-uri', 'sandbox', 'form-action',
  'frame-ancestors', 'navigate-to', 'report-uri', 'report-to',
  'require-trusted-types-for', 'trusted-types',
  'upgrade-insecure-requests', 'block-all-mixed-content',
]);

/** @type {Set<string>} */
const LOCALHOST_HOSTNAMES = new Set([
  'localhost', '127.0.0.1', '::1', '0.0.0.0', '[::1]',
]);

// ---------------------------------------------------------------------------
// Nonce
// ---------------------------------------------------------------------------

/**
 * Generates a cryptographically secure nonce.
 *
 * @param {number} [byteLength=16] - length in bytes
 * @returns {string} base64-encoded nonce
 * @throws {RangeError} if byteLength < 8 or > 256
 */
function generateNonce(byteLength = 16) {
  if (byteLength < 8) throw new RangeError('Nonce must be at least 8 bytes');
  if (byteLength > 256) throw new RangeError('Nonce must not exceed 256 bytes');
  return crypto.randomBytes(byteLength).toString('base64');
}

// ---------------------------------------------------------------------------
// CSP: parsing and formatting
// ---------------------------------------------------------------------------

/**
 * Parses a CSP string into an object.
 * Supports directives without values (e.g. `upgrade-insecure-requests`).
 *
 * @param {string} cspString - CSP string
 * @returns {object} object { directive: string[] }
 *
 * @example
 * ```js
 * parseCSP("default-src 'self'; upgrade-insecure-requests; script-src 'self'");
 * // {
 * //   'default-src': ["'self'"],
 * //   'upgrade-insecure-requests': [],
 * //   'script-src': ["'self'"]
 * // }
 * ```
 */
function parseCSP(cspString) {
  if (!cspString || typeof cspString !== 'string') return {};

  const directives = {};

  cspString
    .split(';')
    .map(d => d.trim())
    .filter(d => d.length > 0)
    .forEach(directive => {
      const parts = directive.split(/\s+/);
      const name = parts[0].toLowerCase();
      const values = parts.slice(1);

      if (name) {
        directives[name] = values; // keep even if values is empty
      }
    });

  return directives;
}

/**
 * Converts a CSP object into a string.
 * Directives without values are written without a trailing space.
 *
 * @param {object} cspObject - CSP object
 * @returns {string} CSP string
 */
function stringifyCSP(cspObject) {
  if (!cspObject || typeof cspObject !== 'object') return '';

  return Object.entries(cspObject)
    .filter(([_, values]) => {
      if (Array.isArray(values)) return values.length > 0;
      return values !== undefined && values !== null;
    })
    .map(([directive, values]) => {
      if (Array.isArray(values) && values.length > 0) {
        return `${directive} ${values.join(' ')}`;
      }
      return directive;
    })
    .join('; ');
}

/**
 * Merges multiple CSP strings or objects into a single string.
 * Values are deduplicated.
 *
 * @param {...(string|object)} policies
 * @returns {string}
 */
function mergeCSP(...policies) {
  if (policies.length === 0) return '';
  if (policies.length === 1 && typeof policies[0] === 'string') return policies[0];

  const merged = {};

  policies.forEach(policy => {
    const parsed = typeof policy === 'string' ? parseCSP(policy) : policy;
    if (!parsed || typeof parsed !== 'object') return;

    Object.entries(parsed).forEach(([directive, values]) => {
      if (!merged[directive]) merged[directive] = new Set();
      values.forEach(v => merged[directive].add(v));
    });
  });

  const result = {};
  Object.entries(merged).forEach(([directive, values]) => {
    result[directive] = [...values];
  });

  return stringifyCSP(result);
}

/**
 * Injects a nonce into a CSP string for the specified directives.
 * Does not duplicate existing nonces.
 *
 * @param {string} csp - original CSP string
 * @param {string} nonce - nonce to inject
 * @param {string[]} [directives=['script-src', 'script-src-elem']]
 * @returns {string} new CSP string
 */
function injectNonce(csp, nonce, directives = ['script-src', 'script-src-elem']) {
  if (!csp || !nonce) return csp;

  const parsed = parseCSP(csp);
  const nonceValue = `'nonce-${nonce}'`;

  directives.forEach(directive => {
    if (parsed[directive]) {
      const hasNonce = parsed[directive].some(v => v.startsWith("'nonce-"));
      if (!hasNonce) parsed[directive].push(nonceValue);
    } else {
      parsed[directive] = [nonceValue];
    }
  });

  return stringifyCSP(parsed);
}

/**
 * Adds 'strict-dynamic' to a CSP string.
 *
 * If script-src/script-src-elem is absent:
 * - Copies values from default-src (per CSP3 spec)
 * - If default-src is also absent — creates an empty script-src
 *
 * Does NOT remove URL sources — that is the developer's responsibility.
 *
 * @param {string} csp - original CSP string
 * @returns {string} CSP string with strict-dynamic
 *
 * @example
 * ```js
 * // Has script-src
 * addStrictDynamic("script-src 'self' cdn.com");
 * // => "script-src 'self' cdn.com 'strict-dynamic'"
 *
 * // No script-src — copies from default-src
 * addStrictDynamic("default-src 'self'");
 * // => "default-src 'self'; script-src 'self' 'strict-dynamic'"
 * ```
 */
function addStrictDynamic(csp) {
  if (!csp) return csp;

  const parsed = parseCSP(csp);

  // Determine which directive controls scripts
  let scriptDirective = null;

  if (parsed['script-src-elem'] && parsed['script-src-elem'].length > 0) {
    scriptDirective = 'script-src-elem';
  } else if (parsed['script-src'] && parsed['script-src'].length > 0) {
    scriptDirective = 'script-src';
  } else if (parsed['default-src'] && parsed['default-src'].length > 0) {
    // Create script-src from default-src (per CSP3 spec)
    scriptDirective = 'script-src';
    parsed[scriptDirective] = [...parsed['default-src']];
  } else {
    // Create empty script-src — strict-dynamic will be the only source
    scriptDirective = 'script-src';
    parsed[scriptDirective] = [];
  }

  // Add strict-dynamic if not already present
  if (!parsed[scriptDirective].includes("'strict-dynamic'")) {
    parsed[scriptDirective].push("'strict-dynamic'");
  }

  return stringifyCSP(parsed);
}

/**
 * Normalizes a CSP directive value (adds quotes around keywords).
 *
 * @param {string} value
 * @returns {string}
 */
function normalizeCSPValue(value) {
  if (!value || typeof value !== 'string') return value;

  const keywords = new Set([
    'self', 'none', 'unsafe-inline', 'unsafe-eval',
    'strict-dynamic', 'unsafe-hashes', 'report-sample',
  ]);

  const clean = value.replace(/^['"]|['"]$/g, '');

  if (keywords.has(clean)) return `'${clean}'`;
  if (clean.startsWith('nonce-') || clean.startsWith('sha')) return `'${clean}'`;

  return value;
}

// ---------------------------------------------------------------------------
// HTTPS
// ---------------------------------------------------------------------------

/**
 * Checks whether the request is HTTPS.
 *
 * @param {object} req
 * @param {boolean} [trustProxy=false]
 * @returns {boolean}
 */
function isHttps(req, trustProxy = false) {
  if (!req) return false;
  if (req.secure === true) return true;

  if (trustProxy && req.headers) {
    if (req.headers['x-forwarded-proto'] === 'https') return true;
  }

  const socket = req.socket || req.connection;
  if (socket && socket.encrypted === true) return true;

  return false;
}

/**
 * Checks whether the host is localhost.
 *
 * @param {object} req
 * @returns {boolean}
 */
function isLocalhost(req) {
  if (!req || !req.headers || !req.headers['host']) {
    return req && req.secure !== true;
  }

  const host = req.headers['host'];
  const hostname = host.split(':')[0].toLowerCase();
  return LOCALHOST_HOSTNAMES.has(hostname);
}

// ---------------------------------------------------------------------------
// Middleware factory
// ---------------------------------------------------------------------------

/**
 * Creates a middleware that sets a single header.
 *
 * @param {string} headerName - header name
 * @param {string|function} headerValue - value or function (req, res) => value
 * @returns {function}
 */
function createHeaderSetter(headerName, headerValue) {
  if (!headerName || typeof headerName !== 'string') {
    throw new TypeError('headerName must be a non-empty string');
  }

  return function headerSetterMiddleware(req, res, next) {
    if (res.headersSent) return next();

    const value = typeof headerValue === 'function'
      ? headerValue(req, res)
      : headerValue;

    if (value !== undefined && value !== null && value !== false) {
      res.setHeader(headerName, value);
    }

    next();
  };
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Checks whether a string is a valid CSP directive.
 *
 * @param {string} directive
 * @returns {boolean}
 */
function isValidCSPDirective(directive) {
  if (!directive || typeof directive !== 'string') return false;
  return CSP_DIRECTIVES.has(directive.toLowerCase());
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  generateNonce,
  parseCSP,
  stringifyCSP,
  mergeCSP,
  injectNonce,
  addStrictDynamic,
  normalizeCSPValue,
  isHttps,
  isLocalhost,
  createHeaderSetter,
  isValidCSPDirective,
  CSP_DIRECTIVES,
};