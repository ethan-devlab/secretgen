import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { base32crockford, base32hex, base32hexnopad, base32nopad, base58 } from '@scure/base';
import { fromSeed } from '@nats-io/nkeys';
import { parseURI } from '@otplib/uri';
import { decrypt, encrypt } from 'paseto-ts/v4';
import { calculateJwkThumbprint, importJWK } from 'jose';
import { generateSync } from 'otplib';
import { validate as validateUuid, version as uuidVersion } from 'uuid';
import { generate, generateArtifact, getPreset, getPresets } from '../src/index.js';
import { encodeBase32 } from '../src/adapters/encoding.js';

const fixture = JSON.parse(await readFile(new URL('./fixtures/v0.1.1-catalog.json', import.meta.url), 'utf8'));
const artifactLayouts = JSON.parse(await readFile(new URL('./fixtures/v0.1.1-artifact-layout.json', import.meta.url), 'utf8'));

const V02_IDS = [
  'strapi:secrets', 'mongodb:keyfile', 'consul:gossip-key', 'nomad:gossip-key',
  'rabbitmq:erlang-cookie', 'nats:nkey', 'directus:secret', 'payload:secret',
  'keystone:session-secret', 'generic:base58', 'generic:base32hex',
  'generic:base32-crockford', 'id:nanoid',
];

function v011Contract(preset) {
  return {
    id: preset.id,
    aliases: preset.aliases,
    kind: preset.kind,
    category: preset.category,
    label: preset.label,
    description: preset.description,
    env: preset.env,
    options: JSON.parse(JSON.stringify(preset.options)),
    countLimit: typeof preset.countLimit === 'function' ? 'dynamic' : preset.countLimit,
    multiline: Boolean(preset.multiline),
  };
}

function part(artifact, role) {
  const value = artifact.parts.find((item) => item.role === role);
  assert.ok(value, `${artifact.preset} has ${role}`);
  return value;
}

test('Given the v0.1.1 catalog fixture, when v0.2 loads, then all 67 existing public contracts remain unchanged', async () => {
  const oldIds = fixture.presets.map((preset) => preset.id);
  assert.equal(oldIds.length, 67);
  assert.deepEqual(fixture.presets.map((expected) => v011Contract(getPreset(expected.id))), fixture.presets);

  for (const [id, expected] of Object.entries(artifactLayouts)) {
    const artifact = await generateArtifact(id);
    assert.deepEqual(Object.keys(artifact.metadata).sort(), [...expected.metadataKeys].sort(), id);
    assert.deepEqual(artifact.parts.map((item) => [item.role, item.filename]), expected.parts, id);
  }

  const all = getPresets();
  assert.equal(all.length, 80);
  assert.deepEqual(new Set(all.map((preset) => preset.id).filter((id) => !oldIds.includes(id))), new Set(V02_IDS));
});

test('Given scalar presets, when v0.2 exposes catalog metadata, then sensitivity is explicit and identifiers are public', () => {
  const publicIds = new Set(['uuid:v4', 'uuid:v7', 'id:nanoid']);
  for (const preset of getPresets().filter((item) => item.kind === 'scalar')) {
    assert.ok(['secret', 'public'].includes(preset.sensitivity), preset.id);
    assert.equal(preset.sensitivity, publicIds.has(preset.id) ? 'public' : 'secret', preset.id);
  }
  assert.equal(getPreset('id:nanoid').aliases.length, 0);
});

test('Given standard encodings, when the generic presets generate values, then upstream decoders recover the requested bytes', () => {
  const bytes = 39;
  const values = [
    [generate('generic:base32', { bytes }), base32nopad],
    [generate('generic:base32hex', { bytes }), base32hexnopad],
    [generate('generic:base32-crockford', { bytes }), base32crockford],
    [generate('generic:base58', { bytes }), base58],
  ];
  for (const [value, codec] of values) assert.equal(codec.decode(value).length, bytes);
  const padded = generate('generic:base32hex', { bytes: 31, padding: true });
  assert.ok(padded.endsWith('='));
  assert.equal(base32hex.decode(padded).length, 31);
});

test('Given RFC 4226 and RFC 6238 vectors, when otplib calculates them, then the expected OTP values are returned', () => {
  assert.equal(generateSync({
    strategy: 'hotp', secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', algorithm: 'sha1', digits: 6, counter: 0,
  }), '755224');

  for (const [algorithm, length, expected] of [
    ['sha1', 20, '94287082'], ['sha256', 32, '46119246'], ['sha512', 64, '90693936'],
  ]) {
    const secret = encodeBase32(Buffer.from('1234567890'.repeat(Math.ceil(length / 10)).slice(0, length)));
    assert.equal(generateSync({ strategy: 'totp', secret, algorithm, digits: 8, period: 30, epoch: 59 }), expected);
  }
});

test('Given Unicode provisioning fields, when an OTP artifact is generated, then otplib parses the escaped URI losslessly', async () => {
  const artifact = await generateArtifact('totp:provisioning', {
    issuer: 'Exämple & Co', account: 'a+b@example.com', algorithm: 'SHA512', digits: 8, period: 45,
  });
  const uri = part(artifact, 'provisioning-uri').data;
  const parsed = parseURI(uri);
  assert.equal(parsed.type, 'totp');
  assert.equal(parsed.label, 'Exämple & Co:a+b@example.com');
  assert.equal(parsed.params.issuer, 'Exämple & Co');
  assert.equal(parsed.params.algorithm, 'sha512');
  assert.equal(parsed.params.digits, 8);
  assert.equal(parsed.params.period, 45);
});

test('Given protocol and deployment presets, when values are generated, then every format contract is usable', async () => {
  const consul = generate('consul:gossip-key');
  assert.equal(Buffer.from(consul, 'base64').length, 32);
  assert.equal(Buffer.from(generate('nomad:gossip-key', { bits: 128 }), 'base64').length, 16);
  assert.equal(Buffer.from(generate('nomad:gossip-key'), 'base64').length, 32);
  assert.throws(() => generate('nomad:gossip-key', { bits: 192 }), /128, 256/u);

  const cookie = generate('rabbitmq:erlang-cookie', { length: 255 });
  assert.match(cookie, /^[A-Za-z0-9]{255}$/u);
  assert.throws(() => generate('rabbitmq:erlang-cookie', { length: 31 }), /between 32 and 255/u);
  assert.equal(Buffer.from(generate('directus:secret'), 'base64url').length, 32);
  assert.equal(Buffer.from(generate('payload:secret'), 'base64url').length, 32);
  assert.equal(getPreset('directus:secret').env, 'SECRET');
  assert.equal(getPreset('payload:secret').env, 'PAYLOAD_SECRET');
  assert.equal(getPreset('keystone:session-secret').env, 'SESSION_SECRET');
  assert.match(generate('keystone:session-secret'), /^[A-Za-z0-9_-]{64}$/u);
  assert.equal(generate('id:nanoid', { length: 48 }).length, 48);

  const mongo = await generateArtifact('mongodb:keyfile', { keys: 2 });
  const mongoKeys = part(mongo, 'keyfile').data.trimEnd().split('\n').map((line) => line.slice(2));
  assert.equal(mongoKeys.length, 2);
  for (const key of mongoKeys) {
    assert.equal(key.length, 1008);
    assert.equal(Buffer.from(key, 'base64').length, 756);
  }

  const strapi = await generateArtifact('strapi:secrets');
  const strapiValues = JSON.parse(part(strapi, 'secrets-json').data);
  assert.deepEqual(Object.keys(strapiValues), ['APP_KEYS', 'API_TOKEN_SALT', 'ADMIN_JWT_SECRET', 'JWT_SECRET', 'TRANSFER_TOKEN_SALT', 'ENCRYPTION_KEY']);
  const materials = [...strapiValues.APP_KEYS, ...Object.values(strapiValues).filter((value) => typeof value === 'string')];
  assert.equal(materials.length, 9);
  assert.equal(new Set(materials).size, 9);
  for (const value of materials) assert.equal(Buffer.from(value, 'base64').length, 32);

  for (const [type, seedPrefix, publicPrefix] of [
    ['user', 'SU', 'U'], ['account', 'SA', 'A'], ['operator', 'SO', 'O'], ['server', 'SN', 'N'], ['cluster', 'SC', 'C'],
  ]) {
    const nkey = await generateArtifact('nats:nkey', { type });
    const seed = part(nkey, 'seed').data;
    assert.ok(seed.startsWith(seedPrefix), type);
    assert.ok(part(nkey, 'public-key').data.startsWith(publicPrefix), type);
    assert.equal(fromSeed(new TextEncoder().encode(seed)).getPublicKey(), part(nkey, 'public-key').data);
  }
});

test('Given public metadata artifact parts, when a v0.2 artifact is generated, then metadata.json equals artifact metadata with two-space JSON', async () => {
  for (const id of ['strapi:secrets', 'mongodb:keyfile', 'nats:nkey']) {
    const artifact = await generateArtifact(id);
    const metadata = part(artifact, 'metadata');
    assert.equal(metadata.filename, 'metadata.json');
    assert.equal(metadata.secret, false);
    assert.equal(metadata.data, JSON.stringify(artifact.metadata, null, 2));
  }
});

test('Given JOSE, PASETO, UUID, and NATS adapters, when material is generated, then upstream libraries accept it', async () => {
  const jwkArtifact = await generateArtifact('jwk:keypair', { algorithm: 'ed25519' });
  const publicJwk = JSON.parse(part(jwkArtifact, 'public-jwk').data);
  assert.equal(await calculateJwkThumbprint(publicJwk), publicJwk.kid);
  assert.ok(await importJWK(publicJwk, publicJwk.alg));

  const localKey = generate('paseto:v4-local-key');
  const token = encrypt(localKey, { subject: 'secretgen-test' }, { addExp: false });
  assert.equal(decrypt(localKey, token).payload.subject, 'secretgen-test');

  const validUuid = generate('uuid:v7');
  assert.ok(validateUuid(validUuid));
  assert.equal(uuidVersion(validUuid), 7);
  const timestamp = Number.parseInt(validUuid.replaceAll('-', '').slice(0, 12), 16);
  assert.ok(Math.abs(timestamp - Date.now()) < 5_000);
});
