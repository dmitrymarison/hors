/**
 * ESM export for @hors/base.
 * Use with Node.js 26+ or bundlers.
 *
 * @example
 * import { hors } from '@hors/base';
 * app.use(hors());
 */

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const cjsModule = require('./index.js');

export const {
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
} = cjsModule;

export default hors;