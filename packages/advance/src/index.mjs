/**
 * ESM export for @hors/advanced.
 * Use with Node.js 26+ or bundlers.
 */

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const cjsModule = require('./index.js');

export const {
  hors,
  ADVANCED_DEFAULTS,
  buildDynamicCSP,
  generateNonce,
} = cjsModule;

export default hors;