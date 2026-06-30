'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { hors, DEFAULTS, canModifyHeaders, sanitizeOptions, getSocket } = require('../src/index');

function mockRequest(opts = {}) {
  const req = {
    secure: opts.secure !== undefined ? opts.secure : true,
    headers: opts.headers || {},
    socket: opts.socket !== undefined ? opts.socket : null,
    connection: opts.connection || null,
  };

  const store = {};
  const removed = [];
  let statusCode = opts.statusCode || 200;
  let headersSent = opts.headersSent || false;

  const res = {
    get statusCode() { return statusCode; },
    set statusCode(v) { statusCode = v; },
    get headersSent() { return headersSent; },
    set headersSent(v) { headersSent = v; },
    setHeader(name, value) {
      if (headersSent) {
        const err = new Error('Cannot set headers after they are sent to the client');
        err.code = 'ERR_HTTP_HEADERS_SENT';
        throw err;
      }
      store[name.toLowerCase()] = value;
    },
    getHeader(name) {
      return store[name.toLowerCase()];
    },
    hasHeader(name) {
      return name.toLowerCase() in store;
    },
    removeHeader(name) {
      if (headersSent) {
        const err = new Error('Cannot remove headers after they are sent to the client');
        err.code = 'ERR_HTTP_HEADERS_SENT';
        throw err;
      }
      removed.push(name);
      delete store[name.toLowerCase()];
    },
    _removed: removed,
  };

  let nextCalled = false;
  const next = () => { nextCalled = true; };

  const middleware = hors(opts.middlewareOptions);
  middleware(req, res, next);

  return { headers: store, nextCalled, res };
}

describe('hors()', () => {
  describe('basic behavior', () => {
    it('should call next()', () => {
      const { nextCalled } = mockRequest();
      assert.strictEqual(nextCalled, true);
    });

    it('should set all default headers for HTTPS', () => {
      const { headers } = mockRequest({
        headers: { host: 'example.com' },
      });

      assert.strictEqual(headers['content-security-policy'], DEFAULTS.csp);
      assert.ok(headers['strict-transport-security'].includes('max-age=31536000'));
      assert.strictEqual(headers['x-content-type-options'], 'nosniff');
      assert.strictEqual(headers['x-frame-options'], 'DENY');
      assert.strictEqual(headers['x-xss-protection'], '0');
      assert.strictEqual(headers['referrer-policy'], 'strict-origin-when-cross-origin');
      assert.strictEqual(headers['permissions-policy'], DEFAULTS.permissionsPolicy);
      assert.strictEqual(headers['cross-origin-resource-policy'], 'same-origin');
      assert.strictEqual(headers['cross-origin-opener-policy'], 'same-origin');
      assert.strictEqual(headers['cache-control'], 'no-store, max-age=0');
      assert.strictEqual(headers['x-permitted-cross-domain-policies'], 'none');
      assert.strictEqual(headers['x-download-options'], 'noopen');
      assert.strictEqual(headers['x-dns-prefetch-control'], 'off');
      assert.strictEqual(headers['origin-agent-cluster'], '?1');
    });
  });

  describe('HSTS', () => {
    it('should NOT set HSTS for HTTP', () => {
      const { headers } = mockRequest({
        secure: false,
        headers: { host: 'example.com' },
      });
      assert.strictEqual(headers['strict-transport-security'], undefined);
    });

    it('should NOT set HSTS on localhost', () => {
      const { headers } = mockRequest({
        secure: true,
        headers: { host: 'localhost:3000' },
      });
      assert.strictEqual(headers['strict-transport-security'], undefined);
    });

    it('should NOT set HSTS on 127.0.0.1', () => {
      const { headers } = mockRequest({
        secure: true,
        headers: { host: '127.0.0.1:3000' },
      });
      assert.strictEqual(headers['strict-transport-security'], undefined);
    });

    it('should NOT set HSTS on ::1', () => {
      const { headers } = mockRequest({
        secure: true,
        headers: { host: '[::1]:3000' },
      });
      assert.strictEqual(headers['strict-transport-security'], undefined);
    });

    it('should set HSTS with custom options', () => {
      const { headers } = mockRequest({
        secure: true,
        headers: { host: 'example.com' },
        middlewareOptions: {
          hsts: { maxAge: 3600, includeSubDomains: false, preload: true },
        },
      });
      assert.strictEqual(headers['strict-transport-security'], 'max-age=3600; preload');
    });
  });

  describe('disabling headers', () => {
    it('should respect disabling all headers', () => {
      const { headers } = mockRequest({
        middlewareOptions: {
          csp: false,
          hsts: false,
          noSniff: false,
          frameGuard: false,
          xssFilter: false,
          referrerPolicy: false,
          permissionsPolicy: false,
          corp: false,
          coop: false,
          coep: false,
          cacheControl: false,
          crossDomainPolicy: false,
          downloadOptions: false,
          dnsPrefetchControl: false,
          hidePoweredBy: false,
          originAgentCluster: false,
        },
      });

      assert.strictEqual(Object.keys(headers).length, 0);
    });
  });

  describe('headersSent and status codes', () => {
    it('should NOT set headers if headersSent', () => {
      const { headers } = mockRequest({ headersSent: true });
      assert.strictEqual(Object.keys(headers).length, 0);
    });

    it('should NOT set headers for 304', () => {
      const { headers } = mockRequest({ statusCode: 304 });
      assert.strictEqual(Object.keys(headers).length, 0);
    });
  });

  describe('overwrite protection', () => {
    it('should NOT overwrite Cache-Control', () => {
      const req = {
        secure: true,
        headers: { host: 'example.com' },
      };
      const store = { 'cache-control': 'public, max-age=3600' };
      const res = {
        statusCode: 200,
        headersSent: false,
        setHeader(name, value) { store[name.toLowerCase()] = value; },
        getHeader(name) { return store[name.toLowerCase()]; },
        hasHeader(name) { return name.toLowerCase() in store; },
        removeHeader() {},
      };
      const next = () => {};

      hors()(req, res, next);

      assert.strictEqual(store['cache-control'], 'public, max-age=3600');
    });
  });

  describe('prototype pollution', () => {
    it('should ignore __proto__', () => {
      const { headers } = mockRequest({
        middlewareOptions: { __proto__: { csp: "default-src evil.com" } },
      });
      assert.strictEqual(headers['content-security-policy'], DEFAULTS.csp);
    });

    it('should ignore constructor', () => {
      const { headers } = mockRequest({
        middlewareOptions: { constructor: { csp: "default-src evil.com" } },
      });
      assert.strictEqual(headers['content-security-policy'], DEFAULTS.csp);
    });
  });

  describe('getSocket', () => {
    it('should work with req.socket', () => {
      const socket = getSocket({ socket: { encrypted: true } });
      assert.ok(socket);
    });

    it('should work with req.connection (Node 24+)', () => {
      const socket = getSocket({ socket: null, connection: { encrypted: true } });
      assert.ok(socket);
    });

    it('should return null if no socket', () => {
      const socket = getSocket({});
      assert.strictEqual(socket, null);
    });
  });
});

describe('sanitizeOptions', () => {
  it('should remove dangerous keys', () => {
    const result = sanitizeOptions({ csp: 'test', __proto__: { evil: true } });
    assert.strictEqual(result.csp, 'test');
    // __proto__ is a getter/setter on Object.prototype, not an own property
    assert.strictEqual(Object.prototype.hasOwnProperty.call(result, '__proto__'), false);
  });

  it('should work with Object.create(null)', () => {
    const input = Object.create(null);
    input.csp = 'test';
    input.__proto__ = { evil: true };

    const result = sanitizeOptions(input);
    assert.strictEqual(result.csp, 'test');
    // The __proto__ key was explicitly skipped by the sanitizer
    assert.strictEqual(Object.prototype.hasOwnProperty.call(result, '__proto__'), false);
  });

  it('should return empty object for non-objects', () => {
    assert.deepStrictEqual(sanitizeOptions(null), {});
    assert.deepStrictEqual(sanitizeOptions(undefined), {});
    assert.deepStrictEqual(sanitizeOptions('string'), {});
  });
});

describe('canModifyHeaders', () => {
  it('should return false for headersSent', () => {
    assert.strictEqual(canModifyHeaders({ headersSent: true }), false);
  });

  it('should return false for 304', () => {
    assert.strictEqual(canModifyHeaders({ statusCode: 304 }), false);
  });

  it('should return true for a normal response', () => {
    assert.strictEqual(canModifyHeaders({ statusCode: 200, headersSent: false }), true);
  });
});