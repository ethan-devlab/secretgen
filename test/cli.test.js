import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createPrivateKey } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';

const execFileAsync = promisify(execFile);
const cli = path.resolve('bin/secretgen.js');

async function run(args, options = {}) {
  return execFileAsync(process.execPath, [cli, ...args], { encoding: 'utf8', windowsHide: true, ...options });
}

test('direct CLI accepts typed custom length and option flags', async () => {
  const { stdout, stderr } = await run(['generic:password', '--length', '77']);
  assert.equal(stderr, '');
  assert.equal(stdout.trimEnd().length, 77);

  const provisioning = await run(['totp:provisioning', '--bytes', '32', '--digits', '8', '--account', 'alice@example.com', '--part', 'provisioning-uri']);
  assert.match(provisioning.stdout, /^otpauth:\/\/totp\//u);
  assert.match(provisioning.stdout, /digits=8/u);
});

test('artifact stdout defaults to a structured JSON envelope', async () => {
  const { stdout } = await run(['sodium:box-keypair']);
  const value = JSON.parse(stdout);
  assert.equal(value.preset, 'sodium:box-keypair');
  assert.equal(value.artifact.parts.length, 2);
  assert.ok(value.artifact.parts.every((part) => part.encoding === 'binary'));
  assert.equal(Buffer.from(value.artifact.parts[0].data, 'base64').length, 32);
});

test('artifact directory output is complete and replacement is explicit', async (t) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'secretgen-test-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const target = path.join(parent, 'bundle');
  const first = await run(['wireguard:keypair', '--output-dir', target]);
  assert.equal(first.stdout.trim(), path.resolve(target));
  assert.deepEqual((await readdir(target)).sort(), ['privatekey', 'publickey', 'secretgen-manifest.json']);
  const manifest = JSON.parse(await readFile(path.join(target, 'secretgen-manifest.json'), 'utf8'));
  assert.equal(manifest.preset, 'wireguard:keypair');
  assert.ok(manifest.artifacts[0].parts.every((part) => !Object.hasOwn(part, 'data')));

  await assert.rejects(() => run(['wireguard:keypair', '--output-dir', target]), /already exists/u);
  await run(['wireguard:keypair', '--output-dir', target, '--force']);
  assert.deepEqual((await readdir(target)).sort(), ['privatekey', 'publickey', 'secretgen-manifest.json']);
});

test('artifact batches use numbered directories and one root manifest', async (t) => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'secretgen-batch-test-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const target = path.join(parent, 'bundle');
  await run(['nonce:aes-gcm', '--count', '2', '--output-dir', target]);
  assert.deepEqual((await readdir(target)).sort(), ['001', '002', 'secretgen-manifest.json']);
  assert.deepEqual((await readdir(path.join(target, '001'))).sort(), ['aes-gcm-nonce.bin', 'aes-gcm-nonce.txt']);
  const manifest = JSON.parse(await readFile(path.join(target, 'secretgen-manifest.json'), 'utf8'));
  assert.equal(manifest.artifacts.length, 2);
});

test('private-key passphrases come from an environment variable, never a CLI literal', async () => {
  const env = { ...process.env, SECRETGEN_TEST_PASSPHRASE: 'test passphrase for encrypted PEM' };
  const { stdout } = await run(['pem:keypair', '--algorithm', 'ed25519', '--encrypt-private-key', '--passphrase-env', 'SECRETGEN_TEST_PASSPHRASE'], { env });
  const value = JSON.parse(stdout);
  const privatePem = value.artifact.parts.find((part) => part.role === 'private-key').data;
  assert.equal(createPrivateKey({ key: privatePem, format: 'pem', passphrase: env.SECRETGEN_TEST_PASSPHRASE }).type, 'private');
  await assert.rejects(() => run(['pem:keypair', '--encrypt-private-key']), /require --passphrase-env or --passphrase-file/u);
  await assert.rejects(() => run(['pem:keypair', '--passphrase', 'visible-secret']), /Unknown argument/u);
});

test('CLI enforces preset-specific count limits', async () => {
  await assert.rejects(() => run(['pem:keypair', '--algorithm', 'rsa', '--count', '11']), /between 1 and 10/u);
  await assert.rejects(() => run(['mfa:recovery-codes', '--count', '101']), /between 1 and 100/u);
});

test('CLI rejects conflicting artifact output modes', async () => {
  await assert.rejects(() => run(['wireguard:keypair', '--part', 'public-key', '--format', 'json']), /only supports --format raw/u);
  await assert.rejects(() => run(['wireguard:keypair', '--output-dir', 'unused', '--format', 'json']), /cannot be combined/u);
  await assert.rejects(() => run(['wireguard:keypair', '--format', 'raw']), /requires --part/u);
});
