import assert from 'node:assert/strict';
import { createPrivateKey } from 'node:crypto';
import test from 'node:test';
import sshpk from 'sshpk';
import { generate, generateArtifact, getPreset, getPresets } from '../src/index.js';
import { getCountLimit, resolvePresetOptions } from '../src/schema.js';

const NEW_PRESETS = [
  'generic:base32', 'generic:urlsafe-string', 'generic:passphrase', 'uuid:v4', 'uuid:v7',
  'better-auth:secret', 'nuxt:session-password', 'adonis:app-key', 'codeigniter:encryption-key',
  'spring:base64-key', 'github:webhook-secret', 'oauth:pkce-verifier', 'rails:master-key',
  'wireguard:preshared-key', 'paseto:v4-local-key', 'hmac:sha384', 'hotp:secret',
  'sodium:secretbox-key', 'hotp:provisioning', 'totp:provisioning', 'mfa:recovery-codes',
  'aspnet:machine-key', 'salt:argon2', 'nonce:aes-gcm', 'nonce:chacha20-poly1305',
  'nonce:xchacha20-poly1305', 'iv:aes-cbc', 'pem:keypair', 'jwk:keypair', 'jwks:keyset',
  'openssh:keypair', 'wireguard:keypair', 'age:keypair', 'paseto:v4-public-keypair',
  'sodium:box-keypair', 'sodium:sign-keypair', 'dkim:keypair',
];

test('ships the complete 37-preset expansion', () => {
  const ids = new Set(getPresets().map((preset) => preset.id));
  assert.equal(NEW_PRESETS.length, 37);
  for (const id of NEW_PRESETS) assert.ok(ids.has(id), id);
});

test('new scalar encodings and identifiers meet their contracts', () => {
  assert.match(generate('generic:base32', { bytes: 20 }), /^[A-Z2-7]{32}$/u);
  assert.match(generate('uuid:v4'), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
  assert.match(generate('uuid:v7'), /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
  assert.equal(generate('rails:master-key').length, 32);
  assert.equal(Buffer.from(generate('wireguard:preshared-key'), 'base64').length, 32);
  assert.equal(generate('oauth:pkce-verifier', { length: 96 }).length, 96);
});

test('EFF passphrases use the requested word count and separator', () => {
  const value = generate('generic:passphrase', { words: 8, separator: 'dot' });
  assert.equal(value.split('.').length, 8);
});

test('TOTP provisioning contains matching secret metadata and URI', async () => {
  const result = await generateArtifact('totp:provisioning', {
    bytes: 32, algorithm: 'SHA512', digits: 8, period: 45, issuer: 'Example', account: 'alice@example.com',
  });
  const secret = result.parts.find((part) => part.role === 'secret').data;
  const uri = new URL(result.parts.find((part) => part.role === 'provisioning-uri').data);
  assert.equal(uri.protocol, 'otpauth:');
  assert.equal(uri.hostname, 'totp');
  assert.equal(uri.searchParams.get('secret'), secret);
  assert.equal(uri.searchParams.get('algorithm'), 'SHA512');
  assert.equal(uri.searchParams.get('digits'), '8');
  assert.equal(uri.searchParams.get('period'), '45');
});

test('public salts and nonces are explicitly non-secret and preserve byte length', async () => {
  for (const [id, bytes] of [['salt:argon2', 24], ['nonce:aes-gcm', 12], ['nonce:xchacha20-poly1305', 24], ['iv:aes-cbc', 16]]) {
    const options = id === 'salt:argon2' ? { bytes, encoding: 'hex' } : {};
    const result = await generateArtifact(id, options);
    const raw = result.parts.find((part) => part.role === 'raw');
    assert.equal(raw.secret, false, id);
    assert.equal(raw.data.byteLength, bytes, id);
  }
});

test('PEM and OpenSSH private-key encryption can be read with the passphrase', async () => {
  const passphrase = 'test-only strong passphrase';
  const pem = await generateArtifact('pem:keypair', {
    algorithm: 'ed25519', encryptPrivateKey: true, passphrase,
  });
  const pemText = pem.parts.find((part) => part.role === 'private-key').data;
  assert.equal(createPrivateKey({ key: pemText, format: 'pem', passphrase }).type, 'private');

  const openssh = await generateArtifact('openssh:keypair', {
    algorithm: 'ed25519', comment: 'secretgen-test', encryptPrivateKey: true, passphrase,
  });
  const sshText = openssh.parts.find((part) => part.role === 'private-key').data;
  assert.equal(sshpk.parsePrivateKey(sshText, 'openssh', { passphrase }).type, 'ed25519');
  assert.equal(openssh.metadata.encrypted, true);
});

test('conditional key options reject irrelevant values and enforce RSA batch limits', () => {
  const preset = getPreset('pem:keypair');
  assert.throws(() => resolvePresetOptions(preset, { algorithm: 'ed25519', bits: 4096 }), /not valid/u);
  const rsa = resolvePresetOptions(preset, { algorithm: 'rsa', bits: 3072 });
  assert.equal(getCountLimit(preset, rsa), 10);
  const ed25519 = resolvePresetOptions(preset, { algorithm: 'ed25519' });
  assert.equal(getCountLimit(preset, ed25519), 100);
});

test('recovery-code and ASP.NET artifacts expose coherent bundles', async () => {
  const recovery = await generateArtifact('mfa:recovery-codes', { codes: 12, codeLength: 16, alphabet: 'alphanumeric' });
  const codes = recovery.parts.find((part) => part.role === 'codes').data.split('\n');
  assert.equal(codes.length, 12);
  assert.ok(codes.every((code) => /^[A-Za-z0-9]{16}$/u.test(code)));

  const machineKey = await generateArtifact('aspnet:machine-key');
  assert.match(machineKey.parts.find((part) => part.role === 'validation-key').data, /^[0-9A-F]{128}$/u);
  assert.match(machineKey.parts.find((part) => part.role === 'decryption-key').data, /^[0-9A-F]{64}$/u);
});
