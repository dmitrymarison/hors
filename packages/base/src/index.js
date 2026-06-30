'use strict';

/**
 * @module @hors/base
 * @description Zero-dependency HTTP security headers for Node.js 16+.
 *
 * Hors (Khors) — a protective circle of light around your server.
 * Every header is intentional, every default is justified.
 *
 * @example
 * ```js
 * const { hors } = require('@hors/base');
 * app.use(hors());
 * ```
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const LOCALHOST_HOSTNAMES = new Set([
  'localhost', '127.0.0.1', '::1', '0.0.0.0', '[::1]',
]);

const NO_HEADERS_STATUS_CODES = new Set([101, 204, 304]);

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/**
 * @typedef {object} HSTSOptions
 * @property {boolean} [enabled=true]
 * @property {number} [maxAge=31536000]
 * @property {boolean} [includeSubDomains=true]
 * @property {boolean} [preload=false]
 */

/**
 * @typedef {object} HorsOptions
 * @property {string|false} [csp="default-src 'self'; frame-ancestors 'none'; upgrade-insecure-requests"]
 * @property {HSTSOptions|false} [hsts]
 * @property {boolean} [noSniff=true]
 * @property {string|false} [frameGuard='DENY']
 * @property {string|false} [xssFilter='0']
 * @property {string|false} [referrerPolicy='strict-origin-when-cross-origin']
 * @property {string|false} [permissionsPolicy='camera=(), microphone=(), geolocation=()']
 * @property {string|false} [corp='same-origin']
 * @property {string|false} [coop='same-origin']
 * @property {string|false} [coep=false]
 * @property {string|false} [cacheControl='no-store, max-age=0']
 * @property {string|false} [crossDomainPolicy='none']
 * @property {string|false} [downloadOptions='noopen']
 * @property {string|false} [dnsPrefetchControl='off']
 * @property {boolean} [hidePoweredBy=true]
 * @property {string|false} [originAgentCluster='?1']
 * @property {boolean} [trustProxy=false]
 */

const DEFAULTS = Object.freeze({
  /** @type {string} */
  csp: "default-src 'self'; frame-ancestors 'none'; upgrade-insecure-requests",

  /** @type {HSTSOptions} */
  hsts: Object.freeze({
    enabled: true,
    maxAge: 31536000,
    includeSubDomains: true,
    preload: false,
  }),

  noSniff: true,
  frameGuard: 'DENY',
  xssFilter: '0',
  referrerPolicy: 'strict-origin-when-cross-origin',
  permissionsPolicy: 'camera=(), microphone=(), geolocation=()',
  corp: 'same-origin',
  coop: 'same-origin',
  coep: false,
  cacheControl: 'no-store, max-age=0',
  crossDomainPolicy: 'none',
  downloadOptions: 'noopen',
  dnsPrefetchControl: 'off',
  hidePoweredBy: true,
  originAgentCluster: '?1',
  trustProxy: false,
});

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/**
 * Safely retrieves the request socket.
 *
 * req.socket — standard approach (Node 0.x – 26+)
 * req.connection — deprecated (Node 13+), fallback for older versions
 *
 * @param {object} req - request object
 * @returns {object|null}
 */
function getSocket(req) {
  if (req.socket) return req.socket;
  if (req.connection) return req.connection;
  if (req.res && req.res.socket) return req.res.socket;
  return null;
}

/**
 * Checks whether the request is HTTPS.
 *
 * @param {object} req - request object
 * @param {boolean} trustProxy - whether to trust X-Forwarded-Proto
 * @returns {boolean}
 */
function isHttps(req, trustProxy) {
  if (req.secure === true) return true;

  if (trustProxy && req.headers) {
    const proto = req.headers['x-forwarded-proto'];
    if (proto === 'https') return true;
  }

  const socket = getSocket(req);
  if (socket && socket.encrypted === true) return true;

  return false;
}

/**
 * Checks whether the host is localhost.
 *
 * Logic:
 * - No Host header + HTTPS → not localhost (real request)
 * - No Host header + HTTP → likely localhost (safe assumption)
 * - Has Host → check against the list
 *
 * @param {object} req - request object
 * @returns {boolean}
 */
function isLocalhost(req) {
  if (!req.headers || !req.headers['host']) {
    return req.secure !== true;
  }

  const host = req.headers['host'];
  // Use lastIndexOf for IPv6 addresses like [::1]:3000
  const portIndex = host.lastIndexOf(':');
  const hostname = portIndex === -1 
    ? host.toLowerCase() 
    : host.substring(0, portIndex).toLowerCase();
  
  // Remove brackets from IPv6
  const clean = hostname.replace(/^\[|\]$/g, '');
  return LOCALHOST_HOSTNAMES.has(clean);
}

/**
 * Checks whether response headers can still be modified.
 *
 * @param {object} res - response object
 * @returns {boolean}
 */
function canModifyHeaders(res) {
  if (res.headersSent) return false;
  if (res.statusCode && NO_HEADERS_STATUS_CODES.has(res.statusCode)) return false;
  return true;
}

/**
 * Checks whether a header is already set.
 * Compatible with: Express (hasHeader), Fastify (getHeader), Koa (get).
 *
 * @param {object} res - response object
 * @param {string} header - header name
 * @returns {boolean}
 */
function hasHeader(res, header) {
  if (typeof res.hasHeader === 'function') return res.hasHeader(header);
  if (typeof res.getHeader === 'function') return res.getHeader(header) !== undefined;
  if (typeof res.get === 'function') return res.get(header) !== undefined;
  return false;
}

/**
 * Safely sets a header (does not overwrite existing ones).
 *
 * @param {object} res - response object
 * @param {string} name - header name
 * @param {string} value - header value
 */
function setIfNotSet(res, name, value) {
  if (!canModifyHeaders(res)) return;
  if (!hasHeader(res, name)) {
    res.setHeader(name, value);
  }
}

/**
 * Safely removes a header.
 *
 * @param {object} res - response object
 * @param {string} name - header name
 */
function safeRemoveHeader(res, name) {
  if (!canModifyHeaders(res)) return;
  if (typeof res.removeHeader === 'function') {
    res.removeHeader(name);
  }
}

/**
 * Prototype pollution protection.
 * Uses for...in with hasOwnProperty for maximum safety.
 *
 * @param {object} options - user-provided options
 * @returns {object} sanitized options
 */
function sanitizeOptions(options) {
  if (!options || typeof options !== 'object') return {};

  const clean = {};

  for (const key in options) {
    if (!Object.prototype.hasOwnProperty.call(options, key)) continue;
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    clean[key] = options[key];
  }

  return clean;
}

// ---------------------------------------------------------------------------
// Main function
// ---------------------------------------------------------------------------

/**
 * Creates a middleware that sets security headers.
 *
 * @param {HorsOptions} [options={}] - user configuration
 * @returns {function} Express/Fastify/Koa middleware
 */
function hors(options = {}) {
  const safeOptions = sanitizeOptions(options);
  const config = { ...DEFAULTS, ...safeOptions };

  // Deep merge for hsts
  if (safeOptions.hsts && typeof safeOptions.hsts === 'object') {
    config.hsts = { ...DEFAULTS.hsts, ...safeOptions.hsts };
  }

  // -----------------------------------------------------------------------
  // Precompute static values (once at initialization)
  // -----------------------------------------------------------------------

  /** @type {string|null} */
  const precomputedHSTS = (() => {
    if (!config.hsts || !config.hsts.enabled) return null;
    const { maxAge, includeSubDomains, preload } = config.hsts;
    let value = `max-age=${maxAge}`;
    if (includeSubDomains) value += '; includeSubDomains';
    if (preload) value += '; preload';
    return value;
  })();

  const STATIC = {
    csp: config.csp || null,
    hsts: precomputedHSTS,
    frameGuard: config.frameGuard || null,
    xssFilter: config.xssFilter || null,
    referrerPolicy: config.referrerPolicy || null,
    permissionsPolicy: config.permissionsPolicy || null,
    corp: config.corp || null,
    coop: config.coop || null,
    coep: config.coep || null,
    cacheControl: config.cacheControl || null,
    crossDomainPolicy: config.crossDomainPolicy || null,
    downloadOptions: config.downloadOptions || null,
    dnsPrefetchControl: config.dnsPrefetchControl || null,
    originAgentCluster: config.originAgentCluster || null,
  };

  /**
   * Middleware that sets security headers.
   *
   * @param {object} req - request
   * @param {object} res - response
   * @param {function} next - next middleware
   */
  return function horsMiddleware(req, res, next) {
    if (!canModifyHeaders(res)) return next();

    // 1. Content-Security-Policy
    if (STATIC.csp) {
      setIfNotSet(res, 'Content-Security-Policy', STATIC.csp);
    }

    // 2. Strict-Transport-Security (HTTPS only, not localhost)
    if (STATIC.hsts && isHttps(req, config.trustProxy) && !isLocalhost(req)) {
      setIfNotSet(res, 'Strict-Transport-Security', STATIC.hsts);
    }

    // 3. X-Content-Type-Options
    if (config.noSniff) {
      setIfNotSet(res, 'X-Content-Type-Options', 'nosniff');
    }

    // 4. X-Frame-Options
    if (STATIC.frameGuard) {
      setIfNotSet(res, 'X-Frame-Options', STATIC.frameGuard);
    }

    // 5. X-XSS-Protection
    if (STATIC.xssFilter) {
      setIfNotSet(res, 'X-XSS-Protection', STATIC.xssFilter);
    }

    // 6. Referrer-Policy
    if (STATIC.referrerPolicy) {
      setIfNotSet(res, 'Referrer-Policy', STATIC.referrerPolicy);
    }

    // 7. Permissions-Policy
    if (STATIC.permissionsPolicy) {
      setIfNotSet(res, 'Permissions-Policy', STATIC.permissionsPolicy);
    }

    // 8. Cross-Origin-Resource-Policy
    if (STATIC.corp) {
      setIfNotSet(res, 'Cross-Origin-Resource-Policy', STATIC.corp);
    }

    // 9. Cross-Origin-Opener-Policy
    if (STATIC.coop) {
      setIfNotSet(res, 'Cross-Origin-Opener-Policy', STATIC.coop);
    }

    // 10. Cross-Origin-Embedder-Policy
    if (STATIC.coep) {
      setIfNotSet(res, 'Cross-Origin-Embedder-Policy', STATIC.coep);
    }

    // 11. Cache-Control
    if (STATIC.cacheControl) {
      setIfNotSet(res, 'Cache-Control', STATIC.cacheControl);
    }

    // 12. X-Permitted-Cross-Domain-Policies
    if (STATIC.crossDomainPolicy) {
      setIfNotSet(res, 'X-Permitted-Cross-Domain-Policies', STATIC.crossDomainPolicy);
    }

    // 13. X-Download-Options
    if (STATIC.downloadOptions) {
      setIfNotSet(res, 'X-Download-Options', STATIC.downloadOptions);
    }

    // 14. X-DNS-Prefetch-Control
    if (STATIC.dnsPrefetchControl) {
      setIfNotSet(res, 'X-DNS-Prefetch-Control', STATIC.dnsPrefetchControl);
    }

    // 15. X-Powered-By — hide it
    if (config.hidePoweredBy) {
      safeRemoveHeader(res, 'X-Powered-By');
    }

    // 16. Origin-Agent-Cluster
    if (STATIC.originAgentCluster) {
      setIfNotSet(res, 'Origin-Agent-Cluster', STATIC.originAgentCluster);
    }

    next();
  };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  hors,
  DEFAULTS,
  isHttps,
  isLocalhost,
  hasHeader,
  setIfNotSet,
  safeRemoveHeader,
  canModifyHeaders,
  getSocket,
  sanitizeOptions,
};