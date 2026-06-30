'use strict';

/**
 * @module @hors/advanced
 * @description Extended security headers with dynamic CSP and nonce.
 *
 * Built on top of @hors/base.
 * - Single base middleware instance for the entire app
 * - Dynamic CSP applied after base middleware
 *
 * @example
 * ```js
 * const { hors } = require('@hors/advanced');
 * app.use(hors({ nonce: { enabled: true } }));
 * ```
 */

const { hors: baseHors, DEFAULTS: BASE_DEFAULTS, hasHeader, safeRemoveHeader } = require('@hors/base');
const { generateNonce, injectNonce, addStrictDynamic } = require('@hors/utils');

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const ADVANCED_DEFAULTS = Object.freeze({
  ...BASE_DEFAULTS,

  nonce: Object.freeze({
    enabled: false,
    byteLength: 16,
    directives: ['script-src', 'script-src-elem'],
  }),

  cspReportOnly: false,
  cspReportEndpoint: null,
  strictDynamic: false,
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Builds the final CSP string.
 * Does not mutate arguments.
 *
 * @param {string} baseCSP
 * @param {object} nonceConfig
 * @param {string|null} nonce
 * @param {boolean} strictDynamic
 * @param {string|null} reportEndpoint
 * @returns {string}
 */
function buildDynamicCSP(baseCSP, nonceConfig, nonce, strictDynamic, reportEndpoint) {
  let csp = baseCSP;

  if (nonce && nonceConfig && nonceConfig.enabled) {
    csp = injectNonce(csp, nonce, nonceConfig.directives);
  }

  if (strictDynamic && nonce) {
    csp = addStrictDynamic(csp);
  }

  if (reportEndpoint && !csp.includes('report-uri')) {
    csp += `; report-uri ${reportEndpoint}`;
  }

  return csp;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

/**
 * Creates middleware with extended security headers.
 *
 * @param {object} [options={}]
 * @param {object|false} [options.nonce] - nonce generation settings
 * @param {boolean} [options.nonce.enabled=false]
 * @param {number} [options.nonce.byteLength=16]
 * @param {string[]} [options.nonce.directives=['script-src', 'script-src-elem']]
 * @param {boolean} [options.cspReportOnly=false] - reporting only, no blocking
 * @param {string|null} [options.cspReportEndpoint=null] - URL for violation reports
 * @param {boolean} [options.strictDynamic=false] - enable strict-dynamic
 * @returns {function} middleware
 */
function hors(options = {}) {
  const safeOptions = {};
  for (const key in options) {
    if (!Object.prototype.hasOwnProperty.call(options, key)) continue;
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    safeOptions[key] = options[key];
  }

  const config = { ...ADVANCED_DEFAULTS, ...safeOptions };

  if (safeOptions.nonce && typeof safeOptions.nonce === 'object') {
    config.nonce = { ...ADVANCED_DEFAULTS.nonce, ...safeOptions.nonce };
  }
  if (safeOptions.hsts && typeof safeOptions.hsts === 'object') {
    config.hsts = { ...ADVANCED_DEFAULTS.hsts, ...safeOptions.hsts };
  }

  // Do we need dynamic CSP?
  const needsDynamicCSP = !!(
    config.csp &&
    (config.nonce.enabled || config.cspReportOnly || config.strictDynamic || config.cspReportEndpoint)
  );

  // Create base middleware ONCE
  const baseConfig = { ...config };
  if (needsDynamicCSP) {
    baseConfig.csp = false; // base should not set a static CSP
  }
  const baseMiddleware = baseHors(baseConfig);

  /**
   * Middleware.
   *
   * @param {object} req
   * @param {object} res
   * @param {function} next
   */
  return function horsAdvancedMiddleware(req, res, next) {
    if (res.headersSent) return next();

    let nonce = null;

    // Generate nonce
    if (config.nonce && config.nonce.enabled) {
      nonce = generateNonce(config.nonce.byteLength);
      req.cspNonce = nonce;
      if (!res.locals) res.locals = {};
      res.locals.cspNonce = nonce;
    }

    // Call base middleware first
    baseMiddleware(req, res, (err) => {
      if (err) return next(err);

      // Apply dynamic CSP after base
      if (needsDynamicCSP) {
        const dynamicCSP = buildDynamicCSP(
          config.csp, config.nonce, nonce,
          config.strictDynamic, config.cspReportEndpoint
        );

        if (config.cspReportOnly) {
          if (hasHeader(res, 'Content-Security-Policy')) {
            safeRemoveHeader(res, 'Content-Security-Policy');
          }
          res.setHeader('Content-Security-Policy-Report-Only', dynamicCSP);
        } else {
          res.setHeader('Content-Security-Policy', dynamicCSP);
        }
      }

      next();
    });
  };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  hors,
  ADVANCED_DEFAULTS,
  buildDynamicCSP,
  generateNonce,
};