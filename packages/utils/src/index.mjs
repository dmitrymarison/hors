/**
 * ESM export for @hors/utils.
 * Use with Node.js 26+ or bundlers.
 */

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const cjsModule = require('./index.js');

export const {
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
} = cjsModule;

export default {
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
};