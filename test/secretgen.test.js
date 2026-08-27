import assert from 'node:assert/strict';
import test from 'node:test';
import { generate, generateArtifact, getPresets } from '../src/index.js';

const presets = getPresets();

test('ships exactly 67 presets', () => {
  assert.equal(presets.length, 67);
});

test('every id and alias is unique', () => {
  const names = presets.flatMap((preset) => [preset.id, ...preset.aliases]);
  assert.equal(new Set(names.map((x) => x.toLowerCase())).size, names.length);
});

test('all scalar presets generate non-empty output', () => {
  for (const preset of presets.filter((item) => item.kind === 'scalar')) {
    const value = generate(preset.id);
    assert.equal(typeof value, 'string', preset.id);
    assert.ok(value.length > 0, preset.id);
  }
});

test('all artifact presets generate structured non-empty output', async () => {
  for (const preset of presets.filter((item) => item.kind === 'artifact')) {
    const value = await generateArtifact(preset.id);
    assert.equal(value.kind, 'artifact', preset.id);
    assert.ok(value.parts.length > 0, preset.id);
    for (const part of value.parts) {
      assert.ok(part.role, preset.id);
      assert.ok(part.filename, preset.id);
      assert.ok(part.encoding === 'utf8' ? part.data.length > 0 : part.data.byteLength > 0, `${preset.id}:${part.role}`);
    }
  }
});

test('scalar and artifact APIs reject the wrong preset kind', async () => {
  assert.throws(() => generate('pem:keypair'), /artifact preset/u);
  await assert.rejects(() => generateArtifact('django:secret-key'), /scalar preset/u);
});

test('python token hex respects bytes', () => {
  assert.match(generate('token-hex', { bytes: 17 }), /^[0-9a-f]{34}$/u);
});

test('python token urlsafe is URL-safe and unpadded', () => {
  const value = generate('token-urlsafe', { bytes: 32 });
  assert.match(value, /^[A-Za-z0-9_-]+$/u);
  assert.equal(Buffer.from(value, 'base64url').length, 32);
});

test('Django key matches current 50-char alphabet', () => {
  const value = generate('django');
  assert.equal(value.length, 50);
  assert.match(value, /^[a-z0-9!@#$%^&*()\-_+=]+$/u);
});

test('Fernet key is padded URL-safe Base64 of 32 bytes', () => {
  const value = generate('fernet');
  assert.equal(value.length, 44);
  assert.match(value, /^[A-Za-z0-9_-]{43}=$/u);
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  assert.equal(Buffer.from(normalized, 'base64').length, 32);
});

test('FastAPI tutorial style is 32-byte hex', () => {
  assert.match(generate('fastapi'), /^[0-9a-f]{64}$/u);
});

test('express-session has at least 32 bytes entropy', () => {
  const value = generate('express-session');
  assert.equal(Buffer.from(value, 'base64url').length, 32);
});

test('iron-session defaults to 64 chars and rejects too short', () => {
  assert.equal(generate('iron-session').length, 64);
  assert.throws(() => generate('iron-session', { length: 31 }), /between 32/u);
});

test('Rails secret is SecureRandom.hex(64)-style', () => {
  assert.match(generate('rails'), /^[0-9a-f]{128}$/u);
});

test('Laravel APP_KEY is base64: plus 32 bytes', () => {
  const value = generate('laravel');
  assert.ok(value.startsWith('base64:'));
  assert.equal(Buffer.from(value.slice(7), 'base64').length, 32);
});

test('Phoenix secret has exact requested length and Base64 alphabet', () => {
  for (const length of [32, 64, 97]) {
    const value = generate('phoenix', { length });
    assert.equal(value.length, length);
    assert.match(value, /^[A-Za-z0-9+/]+$/u);
  }
});

test('WordPress bundle contains all 8 constants', () => {
  const value = generate('wordpress');
  for (const key of ['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT']) {
    assert.match(value, new RegExp(`define\\('${key}'`));
  }
  assert.equal(value.split('\n').length, 8);
});

test('JWT HMAC presets meet RFC 7518 key sizes', () => {
  assert.equal(Buffer.from(generate('hs256'), 'base64url').length, 32);
  assert.equal(Buffer.from(generate('hs384'), 'base64url').length, 48);
  assert.equal(Buffer.from(generate('hs512'), 'base64url').length, 64);
});

test('AES presets have exact key sizes', () => {
  assert.match(generate('aes128'), /^[0-9a-f]{32}$/u);
  assert.match(generate('aes192'), /^[0-9a-f]{48}$/u);
  assert.match(generate('aes256'), /^[0-9a-f]{64}$/u);
});

test('TOTP secret is Base32 and defaults to 160 bits', () => {
  const value = generate('totp');
  assert.equal(value.length, 32);
  assert.match(value, /^[A-Z2-7]+$/u);
});

test('fixed presets reject size overrides', () => {
  assert.throws(() => generate('fernet', { bytes: 64 }), /fixed format/u);
});
