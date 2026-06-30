'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const {
  generateNonce,
  parseCSP,
  stringifyCSP,
  mergeCSP,
  injectNonce,
  addStrictDynamic,
  isHttps,
  isLocalhost,
  createHeaderSetter,
  isValidCSPDirective,
} = require('../src/index');

describe('generateNonce', () => {
  it('should generate a nonce of the specified length', () => {
    const nonce = generateNonce(16);
    assert.strictEqual(typeof nonce, 'string');
    assert.ok(nonce.length >= 22); // 16 bytes in base64 ≈ 22 characters
  });

  it('should generate unique nonces', () => {
    const nonces = new Set();
    for (let i = 0; i < 100; i++) {
      nonces.add(generateNonce());
    }
    assert.strictEqual(nonces.size, 100);
  });

  it('should throw for length < 8', () => {
    assert.throws(() => generateNonce(4), RangeError);
  });

  it('should throw for length > 256', () => {
    assert.throws(() => generateNonce(300), RangeError);
  });

  it('default length should be 16 bytes', () => {
    const nonce = generateNonce();
    const decoded = Buffer.from(nonce, 'base64');
    assert.strictEqual(decoded.length, 16);
  });
});

describe('parseCSP', () => {
  it('should parse a simple CSP string', () => {
    const result = parseCSP("default-src 'self'");
    assert.deepStrictEqual(result, {
      'default-src': ["'self'"],
    });
  });

  it('should parse multiple directives', () => {
    const result = parseCSP("default-src 'self'; script-src 'self' cdn.com");
    assert.deepStrictEqual(result, {
      'default-src': ["'self'"],
      'script-src': ["'self'", 'cdn.com'],
    });
  });

  it('should handle empty string', () => {
    assert.deepStrictEqual(parseCSP(''), {});
    assert.deepStrictEqual(parseCSP(null), {});
  });

  it('should handle extra whitespace and semicolons', () => {
    const result = parseCSP("  default-src   'self' ; ; script-src 'self'  ");
    assert.deepStrictEqual(result, {
      'default-src': ["'self'"],
      'script-src': ["'self'"],
    });
  });
});

describe('stringifyCSP', () => {
  it('should convert an object to a string', () => {
    const result = stringifyCSP({
      'default-src': ["'self'"],
      'script-src': ["'self'", 'cdn.com'],
    });
    assert.strictEqual(result, "default-src 'self'; script-src 'self' cdn.com");
  });

  it('should skip empty directives', () => {
    const result = stringifyCSP({
      'default-src': ["'self'"],
      'script-src': [],
    });
    // Empty array is now filtered out
    assert.strictEqual(result, "default-src 'self'");
  });

  it('should return empty string for empty object', () => {
    assert.strictEqual(stringifyCSP({}), '');
    assert.strictEqual(stringifyCSP(null), '');
  });
});

describe('mergeCSP', () => {
  it('should merge multiple CSP strings', () => {
    const result = mergeCSP(
      "default-src 'self'",
      "script-src 'self' cdn.example.com"
    );
    assert.ok(result.includes("default-src 'self'"));
    assert.ok(result.includes("script-src 'self' cdn.example.com"));
  });

  it('should deduplicate values', () => {
    const result = mergeCSP(
      "script-src 'self' cdn.com",
      "script-src 'self' cdn.com 'unsafe-inline'"
    );
    const parsed = parseCSP(result);
    const scriptSrc = parsed['script-src'];
    const selfCount = scriptSrc.filter(v => v === "'self'").length;
    assert.strictEqual(selfCount, 1);
  });

  it('should accept objects', () => {
    const result = mergeCSP(
      "default-src 'self'",
      { 'script-src': ["'self'"] }
    );
    assert.ok(result.includes("default-src 'self'"));
    assert.ok(result.includes("script-src 'self'"));
  });

  it('should return empty string with no arguments', () => {
    assert.strictEqual(mergeCSP(), '');
  });

  it('should return the string as-is for a single argument', () => {
    assert.strictEqual(mergeCSP("default-src 'self'"), "default-src 'self'");
  });
});

describe('injectNonce', () => {
  it('should inject nonce into script-src', () => {
    const result = injectNonce("default-src 'self'; script-src 'self'", 'abc123');
    assert.ok(result.includes("'nonce-abc123'"));
  });

  it('should create script-src if absent', () => {
    const result = injectNonce("default-src 'self'", 'abc123');
    assert.ok(result.includes("script-src 'nonce-abc123'"));
  });

  it('should not duplicate nonce', () => {
    const result = injectNonce(
      "script-src 'nonce-existing' 'self'",
      'new-nonce'
    );
    const parsed = parseCSP(result);
    const nonces = parsed['script-src'].filter(v => v.startsWith("'nonce-"));
    assert.strictEqual(nonces.length, 1);
  });
});

describe('addStrictDynamic', () => {
  it('should add strict-dynamic', () => {
    const result = addStrictDynamic("script-src 'nonce-abc123'");
    assert.ok(result.includes("'strict-dynamic'"));
  });

  it('should not duplicate strict-dynamic', () => {
    const result = addStrictDynamic("script-src 'nonce-abc123' 'strict-dynamic'");
    const matches = result.match(/'strict-dynamic'/g);
    assert.strictEqual(matches.length, 1);
  });
});

describe('isHttps', () => {
  it('should detect HTTPS via req.secure', () => {
    assert.strictEqual(isHttps({ secure: true }), true);
    assert.strictEqual(isHttps({ secure: false }), false);
  });

  it('should detect HTTPS via proxy', () => {
    assert.strictEqual(
      isHttps(
        { secure: false, headers: { 'x-forwarded-proto': 'https' } },
        true
      ),
      true
    );
  });
});

describe('isLocalhost', () => {
  it('should detect localhost', () => {
    assert.strictEqual(isLocalhost({ headers: { host: 'localhost:3000' } }), true);
    assert.strictEqual(isLocalhost({ headers: { host: 'example.com' } }), false);
  });
});

describe('createHeaderSetter', () => {
  it('should create middleware for a static header', () => {
    const middleware = createHeaderSetter('X-Custom', 'value');
    const headers = {};
    const res = {
      headersSent: false,
      setHeader(name, value) { headers[name.toLowerCase()] = value; },
    };
    let nextCalled = false;

    middleware({}, res, () => { nextCalled = true; });

    assert.strictEqual(headers['x-custom'], 'value');
    assert.strictEqual(nextCalled, true);
  });

  it('should create middleware for a dynamic header', () => {
    const middleware = createHeaderSetter('X-Request-Id', (req) => req.id);
    const headers = {};
    const res = {
      headersSent: false,
      setHeader(name, value) { headers[name.toLowerCase()] = value; },
    };
    let nextCalled = false;

    middleware({ id: 'req-123' }, res, () => { nextCalled = true; });

    assert.strictEqual(headers['x-request-id'], 'req-123');
  });

  it('should not set header if value is undefined', () => {
    const middleware = createHeaderSetter('X-Custom', undefined);
    const headers = {};
    const res = {
      headersSent: false,
      setHeader(name, value) { headers[name.toLowerCase()] = value; },
    };

    middleware({}, res, () => {});

    assert.strictEqual(Object.keys(headers).length, 0);
  });
});

describe('isValidCSPDirective', () => {
  it('should return true for a valid directive', () => {
    assert.strictEqual(isValidCSPDirective('script-src'), true);
    assert.strictEqual(isValidCSPDirective('default-src'), true);
  });

  it('should return false for an invalid directive', () => {
    assert.strictEqual(isValidCSPDirective('invalid-directive'), false);
    assert.strictEqual(isValidCSPDirective(''), false);
  });
});