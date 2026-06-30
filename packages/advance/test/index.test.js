'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { hors, ADVANCED_DEFAULTS, buildDynamicCSP, generateNonce } = require('../src/index');

function mockRequest(opts = {}) {
  const req = {
    secure: opts.secure !== undefined ? opts.secure : true,
    headers: opts.headers || { host: 'example.com' },
    socket: null,
    connection: null,
  };

  const store = {};
  const res = {
    statusCode: opts.statusCode || 200,
    headersSent: false,
    locals: {},
    setHeader(name, value) {
      store[name.toLowerCase()] = value;
    },
    getHeader(name) {
      return store[name.toLowerCase()];
    },
    hasHeader(name) {
      return name.toLowerCase() in store;
    },
    removeHeader(name) {
      delete store[name.toLowerCase()];
    },
  };

  let nextCalled = false;
  const next = () => { nextCalled = true; };

  const middleware = hors(opts.middlewareOptions);
  middleware(req, res, next);

  return { headers: store, nextCalled, req, res };
}

describe('hors (advanced)', () => {
  describe('basic behavior', () => {
    it('should work like base when nonce is disabled', () => {
      const { headers, nextCalled } = mockRequest();
      assert.strictEqual(nextCalled, true);
      assert.ok(headers['content-security-policy']);
      assert.ok(headers['x-content-type-options']);
    });
  });

  describe('nonce', () => {
    it('should generate nonce and add it to CSP', () => {
      const { headers, req } = mockRequest({
        middlewareOptions: {
          nonce: { enabled: true },
        },
      });

      assert.ok(req.cspNonce, 'req.cspNonce should be set');
      const csp = headers['content-security-policy'];
      assert.ok(csp, 'CSP header should be set');
      assert.ok(csp.includes(`'nonce-${req.cspNonce}'`), 'CSP should contain the nonce');
    });

    it('should pass nonce to res.locals', () => {
      const { req, res } = mockRequest({
        middlewareOptions: {
          nonce: { enabled: true },
        },
      });

      assert.strictEqual(res.locals.cspNonce, req.cspNonce);
    });

    it('should generate unique nonces for different requests', () => {
      const nonces = new Set();
      for (let i = 0; i < 10; i++) {
        const { req } = mockRequest({
          middlewareOptions: { nonce: { enabled: true } },
        });
        nonces.add(req.cspNonce);
      }
      assert.strictEqual(nonces.size, 10);
    });
  });

  describe('strict-dynamic', () => {
    it('should add strict-dynamic to CSP', () => {
      const { headers } = mockRequest({
        middlewareOptions: {
          nonce: { enabled: true },
          strictDynamic: true,
        },
      });

      const csp = headers['content-security-policy'];
      assert.ok(csp, 'CSP header should be set');
      assert.ok(csp.includes("'strict-dynamic'"), 'CSP should contain strict-dynamic');
    });
  });

  describe('CSP Report-Only', () => {
    it('should set Report-Only header', () => {
      const { headers } = mockRequest({
        middlewareOptions: {
          cspReportOnly: true,
        },
      });

      assert.ok(headers['content-security-policy-report-only'], 'Report-Only header should be set');
    });

    it('should NOT set regular CSP in Report-Only mode', () => {
      const { headers } = mockRequest({
        middlewareOptions: {
          cspReportOnly: true,
        },
      });

      assert.strictEqual(headers['content-security-policy'], undefined);
    });
  });

  describe('report endpoint', () => {
    it('should add report-uri to CSP', () => {
      const { headers } = mockRequest({
        middlewareOptions: {
          cspReportEndpoint: '/api/csp-violations',
        },
      });

      const csp = headers['content-security-policy'];
      assert.ok(csp, 'CSP header should be set');
      assert.ok(csp.includes('report-uri'), 'CSP should contain report-uri');
    });
  });
});

describe('buildDynamicCSP', () => {
  it('should return base CSP unchanged', () => {
    const result = buildDynamicCSP(
      "default-src 'self'",
      ADVANCED_DEFAULTS,
      null
    );
    assert.strictEqual(result, "default-src 'self'");
  });

  it('should inject nonce', () => {
    const nonceConfig = { enabled: true, byteLength: 16, directives: ['script-src', 'script-src-elem'] };
    const result = buildDynamicCSP(
      "default-src 'self'",
      nonceConfig,
      'test-nonce'
    );
    assert.ok(result.includes("'nonce-test-nonce'"), 'Result should contain the nonce');
  });
});

describe('generateNonce (re-export)', () => {
  it('should generate a nonce', () => {
    const nonce = generateNonce();
    assert.strictEqual(typeof nonce, 'string');
    assert.ok(nonce.length > 0);
  });
});