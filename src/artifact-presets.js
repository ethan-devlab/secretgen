import {
  createHash,
  generateKeyPairSync,
  randomBytes,
} from 'node:crypto';
import {
  ALPHANUMERIC,
  DIGITS,
  base32,
  base64,
  base64url,
  hex,
  randomString,
  secureBytes,
} from './random.js';

const integerOption = (name, defaultValue, min, max, unit = name, when) => ({
  name,
  cliName: name.replaceAll(/[A-Z]/gu, (letter) => `-${letter.toLowerCase()}`),
  type: 'integer',
  default: defaultValue,
  min,
  max,
  unit,
  ...(when ? { when } : {}),
});

const enumOption = (name, defaultValue, choices, when) => ({
  name,
  cliName: name.replaceAll(/[A-Z]/gu, (letter) => `-${letter.toLowerCase()}`),
  type: 'enum',
  default: defaultValue,
  choices,
  ...(when ? { when } : {}),
});

const stringOption = (name, defaultValue, { required = false, secret = false, when, maxLength = 512, cliName } = {}) => ({
  name,
  cliName: cliName === undefined
    ? name.replaceAll(/[A-Z]/gu, (letter) => `-${letter.toLowerCase()}`)
    : cliName,
  type: 'string',
  default: defaultValue,
  required,
  secret,
  maxLength,
  ...(when ? { when } : {}),
});

const booleanOption = (name, defaultValue, when) => ({
  name,
  cliName: name.replaceAll(/[A-Z]/gu, (letter) => `-${letter.toLowerCase()}`),
  type: 'boolean',
  default: defaultValue,
  ...(when ? { when } : {}),
});

const bytesOption = (defaultValue, min, max) => integerOption('bytes', defaultValue, min, max, 'bytes');

function textPart(role, filename, data, secret, mediaType = 'text/plain') {
  return { role, filename, mediaType, secret, encoding: 'utf8', data: String(data) };
}

function binaryPart(role, filename, data, secret, mediaType = 'application/octet-stream') {
  return { role, filename, mediaType, secret, encoding: 'binary', data: Uint8Array.from(data) };
}

function artifact(parts, metadata = {}) {
  return { kind: 'artifact', parts, metadata };
}

function encodeOtpUri(type, options, secret) {
  const label = options.issuer ? `${options.issuer}:${options.account}` : options.account;
  const query = new URLSearchParams({
    secret,
    ...(options.issuer ? { issuer: options.issuer } : {}),
    digits: String(options.digits),
    ...(type === 'hotp' ? { counter: String(options.counter) } : {
      algorithm: options.algorithm,
      period: String(options.period),
    }),
  });
  return `otpauth://${type}/${encodeURIComponent(label)}?${query}`;
}

function otpParts(type, options) {
  const secret = base32(options.secretBytes);
  const uri = encodeOtpUri(type, options, secret);
  const metadata = type === 'hotp'
    ? { type, counter: options.counter, digits: options.digits }
    : { type, algorithm: options.algorithm, digits: options.digits, period: options.period };
  return artifact([
    textPart('secret', 'secret.txt', secret, true),
    textPart('provisioning-uri', 'otpauth-uri.txt', uri, true),
    textPart('metadata', 'metadata.json', JSON.stringify(metadata, null, 2), false, 'application/json'),
  ], metadata);
}

function randomCodes(options) {
  const alphabet = options.alphabet === 'numeric' ? DIGITS : ALPHANUMERIC;
  const codes = Array.from({ length: options.codes }, () => randomString(options.codeLength, alphabet));
  return artifact([
    textPart('codes', 'recovery-codes.txt', codes.join('\n'), true),
    textPart('codes-json', 'recovery-codes.json', JSON.stringify(codes, null, 2), true, 'application/json'),
  ], { count: options.codes, codeLength: options.codeLength, alphabet: options.alphabet, oneTimeUse: true });
}

function aspnetMachineKey() {
  const validationKey = hex(64).toUpperCase();
  const decryptionKey = hex(32).toUpperCase();
  const xml = `<machineKey validationKey="${validationKey}" decryptionKey="${decryptionKey}" validation="HMACSHA256" decryption="AES" />`;
  return artifact([
    textPart('validation-key', 'validation-key.txt', validationKey, true),
    textPart('decryption-key', 'decryption-key.txt', decryptionKey, true),
    textPart('web-config', 'machine-key.xml', xml, true, 'application/xml'),
  ], { validation: 'HMACSHA256', decryption: 'AES' });
}

function publicMaterial(bytes, filename, encoding = 'base64url') {
  const raw = secureBytes(bytes);
  const encoded = encoding === 'hex' ? Buffer.from(raw).toString('hex') : Buffer.from(raw).toString(encoding);
  return artifact([
    textPart('encoded', `${filename}.txt`, encoded, false),
    binaryPart('raw', `${filename}.bin`, raw, false),
  ], { bytes, encoding, secret: false, uniquePerOperation: true });
}

function nodeKeyPair(options) {
  if (options.algorithm === 'rsa') {
    return generateKeyPairSync('rsa', { modulusLength: options.bits, publicExponent: 0x10001 });
  }
  if (options.algorithm === 'ec') {
    const namedCurves = { 'P-256': 'prime256v1', 'P-384': 'secp384r1', 'P-521': 'secp521r1' };
    return generateKeyPairSync('ec', { namedCurve: namedCurves[options.curve] });
  }
  return generateKeyPairSync(options.algorithm);
}

function defaultAlgorithmMetadata(options) {
  if (options.algorithm === 'rsa') return { alg: 'RS256', use: options.use === 'auto' ? 'sig' : options.use };
  if (options.algorithm === 'ec') {
    const algorithms = { 'P-256': 'ES256', 'P-384': 'ES384', 'P-521': 'ES512' };
    return { alg: algorithms[options.curve], use: options.use === 'auto' ? 'sig' : options.use };
  }
  if (options.algorithm === 'ed25519') return { alg: 'EdDSA', use: options.use === 'auto' ? 'sig' : options.use };
  return { alg: 'ECDH-ES', use: options.use === 'auto' ? 'enc' : options.use };
}

function jwkThumbprint(jwk) {
  let canonical;
  if (jwk.kty === 'RSA') canonical = { e: jwk.e, kty: jwk.kty, n: jwk.n };
  else if (jwk.kty === 'EC') canonical = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  else canonical = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  return createHash('sha256').update(JSON.stringify(canonical)).digest('base64url');
}

function createJwkPair(options) {
  const pair = nodeKeyPair(options);
  const privateJwk = pair.privateKey.export({ format: 'jwk' });
  const publicJwk = pair.publicKey.export({ format: 'jwk' });
  const metadata = defaultAlgorithmMetadata(options);
  const kid = jwkThumbprint(publicJwk);
  Object.assign(privateJwk, metadata, { kid });
  Object.assign(publicJwk, metadata, { kid });
  return { privateJwk, publicJwk, metadata: { ...metadata, kid, algorithm: options.algorithm } };
}

function pemKeyPair(options) {
  const pair = nodeKeyPair(options);
  const privateEncoding = {
    type: 'pkcs8',
    format: 'pem',
    ...(options.encryptPrivateKey ? { cipher: 'aes-256-cbc', passphrase: options.passphrase } : {}),
  };
  const privateKey = pair.privateKey.export(privateEncoding);
  const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' });
  return artifact([
    textPart('private-key', 'private-key.pem', privateKey, true, 'application/x-pem-file'),
    textPart('public-key', 'public-key.pem', publicKey, false, 'application/x-pem-file'),
  ], { algorithm: options.algorithm, encrypted: options.encryptPrivateKey, ...(options.bits ? { bits: options.bits } : {}), ...(options.curve ? { curve: options.curve } : {}) });
}

function jwkKeyPair(options) {
  const pair = createJwkPair(options);
  return artifact([
    textPart('private-jwk', 'private.jwk.json', JSON.stringify(pair.privateJwk, null, 2), true, 'application/json'),
    textPart('public-jwk', 'public.jwk.json', JSON.stringify(pair.publicJwk, null, 2), false, 'application/json'),
  ], pair.metadata);
}

function jwksKeyset(options) {
  const privateKeys = [];
  const publicKeys = [];
  for (let i = 0; i < options.keys; i += 1) {
    const pair = createJwkPair(options);
    privateKeys.push(pair.privateJwk);
    publicKeys.push(pair.publicJwk);
  }
  return artifact([
    textPart('private-jwks', 'private.jwks.json', JSON.stringify({ keys: privateKeys }, null, 2), true, 'application/jwk-set+json'),
    textPart('public-jwks', 'jwks.json', JSON.stringify({ keys: publicKeys }, null, 2), false, 'application/jwk-set+json'),
  ], { algorithm: options.algorithm, keys: options.keys });
}

async function opensshKeyPair(options) {
  const module = await import('sshpk');
  const sshpk = module.default ?? module;
  let privateKey;
  if (options.algorithm === 'ed25519') {
    privateKey = sshpk.generatePrivateKey('ed25519');
  } else if (options.algorithm === 'ecdsa') {
    privateKey = sshpk.generatePrivateKey('ecdsa', { curve: options.curve });
  } else {
    const pair = generateKeyPairSync('rsa', {
      modulusLength: options.bits,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    privateKey = sshpk.parsePrivateKey(pair.privateKey, 'pem');
  }
  const privateText = privateKey.toString('openssh', options.encryptPrivateKey ? { passphrase: options.passphrase } : undefined);
  const publicText = `${privateKey.toPublic().toString('ssh')} ${options.comment}`;
  const names = options.algorithm === 'ed25519'
    ? ['id_ed25519', 'id_ed25519.pub']
    : options.algorithm === 'ecdsa'
      ? ['id_ecdsa', 'id_ecdsa.pub']
      : ['id_rsa', 'id_rsa.pub'];
  return artifact([
    textPart('private-key', names[0], privateText, true, 'application/x-openssh-private-key'),
    textPart('public-key', names[1], publicText, false),
  ], { algorithm: options.algorithm, encrypted: options.encryptPrivateKey });
}

async function sodiumReady() {
  const module = await import('libsodium-wrappers');
  const sodium = module.default ?? module;
  await sodium.ready;
  return sodium;
}

async function wireguardKeyPair() {
  const sodium = await sodiumReady();
  const privateKey = sodium.randombytes_buf(32);
  privateKey[0] &= 248;
  privateKey[31] &= 127;
  privateKey[31] |= 64;
  const publicKey = sodium.crypto_scalarmult_base(privateKey);
  return artifact([
    textPart('private-key', 'privatekey', Buffer.from(privateKey).toString('base64'), true),
    textPart('public-key', 'publickey', Buffer.from(publicKey).toString('base64'), false),
  ], { algorithm: 'WireGuard X25519' });
}

async function ageKeyPair() {
  const age = await import('age-encryption');
  const identity = await age.generateIdentity();
  const recipient = await age.identityToRecipient(identity);
  return artifact([
    textPart('identity', 'identity.txt', identity, true),
    textPart('recipient', 'recipient.txt', recipient, false),
  ], { algorithm: 'age X25519' });
}

async function pasetoPublicKeyPair() {
  const { generateKeys } = await import('paseto-ts/v4');
  const getRandomValues = (target) => {
    target.set(randomBytes(target.length));
    return target;
  };
  const { secretKey, publicKey } = generateKeys('public', { format: 'paserk', getRandomValues });
  return artifact([
    textPart('secret-key', 'k4.secret', secretKey, true),
    textPart('public-key', 'k4.public', publicKey, false),
  ], { version: 4, purpose: 'public', format: 'PASERK' });
}

async function sodiumBoxKeyPair() {
  const sodium = await sodiumReady();
  const pair = sodium.crypto_box_keypair();
  return artifact([
    binaryPart('private-key', 'box.private', pair.privateKey, true),
    binaryPart('public-key', 'box.public', pair.publicKey, false),
  ], { algorithm: 'crypto_box', privateBytes: pair.privateKey.length, publicBytes: pair.publicKey.length });
}

async function sodiumSignKeyPair() {
  const sodium = await sodiumReady();
  const pair = sodium.crypto_sign_keypair();
  return artifact([
    binaryPart('secret-key', 'sign.secret', pair.privateKey, true),
    binaryPart('public-key', 'sign.public', pair.publicKey, false),
  ], { algorithm: 'crypto_sign', secretBytes: pair.privateKey.length, publicBytes: pair.publicKey.length });
}

function dkimKeyPair(options) {
  const pair = options.algorithm === 'rsa'
    ? generateKeyPairSync('rsa', { modulusLength: options.bits, publicExponent: 0x10001 })
    : generateKeyPairSync('ed25519');
  const privateKey = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  let publicValue;
  let record;
  if (options.algorithm === 'rsa') {
    publicValue = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    record = `v=DKIM1; k=rsa; p=${publicValue}`;
  } else {
    const jwk = pair.publicKey.export({ format: 'jwk' });
    publicValue = Buffer.from(jwk.x, 'base64url').toString('base64');
    record = `v=DKIM1; k=ed25519; p=${publicValue}`;
  }
  const owner = options.domain ? `${options.selector}._domainkey.${options.domain}` : `${options.selector}._domainkey`;
  return artifact([
    textPart('private-key', 'dkim-private-key.pem', privateKey, true, 'application/x-pem-file'),
    textPart('public-key', 'dkim-public-key.txt', publicValue, false),
    textPart('dns-record', 'dkim-dns-record.txt', `${owner} TXT "${record}"`, false),
  ], { algorithm: options.algorithm, selector: options.selector, ...(options.domain ? { domain: options.domain } : {}) });
}

const keyAlgorithmOptions = () => [
  enumOption('algorithm', 'rsa', ['rsa', 'ec', 'ed25519', 'x25519']),
  integerOption('bits', 3072, 2048, 4096, 'bits', { algorithm: 'rsa' }),
  enumOption('curve', 'P-256', ['P-256', 'P-384', 'P-521'], { algorithm: 'ec' }),
];

const privateEncryptionOptions = () => [
  booleanOption('encryptPrivateKey', false),
  stringOption('passphrase', undefined, { required: true, secret: true, when: { encryptPrivateKey: true }, cliName: null, maxLength: 4096 }),
];

const keyCountLimit = (options) => options.algorithm === 'rsa' ? 10 : 100;

export const ARTIFACT_PRESETS = [
  {
    id: 'hotp:provisioning', aliases: ['hotp-uri'], category: 'Provisioning', kind: 'artifact',
    label: 'HOTP provisioning bundle', description: 'HOTP secret, counter metadata and otpauth URI.', env: null,
    options: [bytesOption(20, 16, 128), integerOption('counter', 0, 0, Number.MAX_SAFE_INTEGER), integerOption('digits', 6, 6, 8), stringOption('issuer', 'secretgen'), stringOption('account', 'account', { required: true })],
    countLimit: 100, generate: (o) => otpParts('hotp', { ...o, secretBytes: o.bytes }),
  },
  {
    id: 'totp:provisioning', aliases: ['totp-uri'], category: 'Provisioning', kind: 'artifact',
    label: 'TOTP provisioning bundle', description: 'TOTP secret, parameters and otpauth URI.', env: null,
    options: [bytesOption(20, 16, 128), enumOption('algorithm', 'SHA1', ['SHA1', 'SHA256', 'SHA512']), integerOption('digits', 6, 6, 8, 'digits'), integerOption('period', 30, 1, 300, 'seconds'), stringOption('issuer', 'secretgen'), stringOption('account', 'account', { required: true })],
    countLimit: 100, generate: (o) => otpParts('totp', { ...o, secretBytes: o.bytes }),
  },
  {
    id: 'mfa:recovery-codes', aliases: ['recovery-codes', 'backup-codes'], category: 'Provisioning', kind: 'artifact',
    label: 'MFA recovery codes', description: 'Application-policy one-time recovery-code bundle.', env: null,
    options: [integerOption('codes', 10, 5, 50, 'codes'), integerOption('codeLength', 10, 8, 32, 'characters'), enumOption('alphabet', 'numeric', ['numeric', 'alphanumeric'])],
    countLimit: 100, generate: randomCodes,
  },
  {
    id: 'aspnet:machine-key', aliases: ['aspnet-machinekey', 'machinekey'], category: 'Java / .NET', kind: 'artifact',
    label: 'ASP.NET machineKey bundle', description: 'Strong HMACSHA256/AES web-farm machineKey configuration.', env: null,
    options: [], countLimit: 100, generate: aspnetMachineKey,
  },
  {
    id: 'salt:argon2', aliases: ['argon2-salt'], category: 'Security Material', kind: 'artifact',
    label: 'Argon2 salt', description: 'Public unique salt material; not a secret.', env: null,
    options: [bytesOption(16, 8, 1024), enumOption('encoding', 'base64', ['base64', 'base64url', 'hex'])], countLimit: 100,
    generate: (o) => publicMaterial(o.bytes, 'argon2-salt', o.encoding),
  },
  {
    id: 'nonce:aes-gcm', aliases: ['aes-gcm-nonce'], category: 'Security Material', kind: 'artifact',
    label: 'AES-GCM nonce', description: 'Public 96-bit nonce that must be unique for every operation.', env: null,
    options: [], countLimit: 100, generate: () => publicMaterial(12, 'aes-gcm-nonce'),
  },
  {
    id: 'nonce:chacha20-poly1305', aliases: ['chacha20-nonce'], category: 'Security Material', kind: 'artifact',
    label: 'ChaCha20-Poly1305 nonce', description: 'Public 96-bit nonce that must be unique for every operation.', env: null,
    options: [], countLimit: 100, generate: () => publicMaterial(12, 'chacha20-poly1305-nonce'),
  },
  {
    id: 'nonce:xchacha20-poly1305', aliases: ['xchacha20-nonce'], category: 'Security Material', kind: 'artifact',
    label: 'XChaCha20-Poly1305 nonce', description: 'Public 192-bit nonce that must be unique for every operation.', env: null,
    options: [], countLimit: 100, generate: () => publicMaterial(24, 'xchacha20-poly1305-nonce'),
  },
  {
    id: 'iv:aes-cbc', aliases: ['aes-cbc-iv'], category: 'Security Material', kind: 'artifact',
    label: 'AES-CBC IV', description: 'Public 128-bit IV that must be unique for every encryption.', env: null,
    options: [], countLimit: 100, generate: () => publicMaterial(16, 'aes-cbc-iv'),
  },
  {
    id: 'pem:keypair', aliases: ['pem-keypair'], category: 'Key Artifacts', kind: 'artifact',
    label: 'PEM keypair', description: 'PKCS#8 private key and SPKI public key in PEM.', env: null,
    options: [...keyAlgorithmOptions(), ...privateEncryptionOptions()], countLimit: keyCountLimit,
    validateOptions: (o) => { if (o.algorithm === 'x25519' && o.encryptPrivateKey === false) return; },
    generate: pemKeyPair,
  },
  {
    id: 'jwk:keypair', aliases: ['jwk-keypair'], category: 'Key Artifacts', kind: 'artifact',
    label: 'JWK keypair', description: 'Private and public JSON Web Keys with RFC 7638 kid.', env: null,
    options: [...keyAlgorithmOptions(), enumOption('use', 'auto', ['auto', 'sig', 'enc'])], countLimit: keyCountLimit,
    validateOptions: (o) => {
      if (o.algorithm === 'x25519' && o.use === 'sig') throw new Error('X25519 JWKs cannot be signing keys.');
      if (o.algorithm === 'ed25519' && o.use === 'enc') throw new Error('Ed25519 JWKs cannot be encryption keys.');
    },
    generate: jwkKeyPair,
  },
  {
    id: 'jwks:keyset', aliases: ['jwks'], category: 'Key Artifacts', kind: 'artifact',
    label: 'JWKS keyset', description: 'Private and public JSON Web Key Sets.', env: null,
    options: [...keyAlgorithmOptions(), enumOption('use', 'auto', ['auto', 'sig', 'enc']), integerOption('keys', 1, 1, 20, 'keys')], countLimit: keyCountLimit,
    validateOptions: (o) => {
      if (o.algorithm === 'x25519' && o.use === 'sig') throw new Error('X25519 JWKs cannot be signing keys.');
      if (o.algorithm === 'ed25519' && o.use === 'enc') throw new Error('Ed25519 JWKs cannot be encryption keys.');
    },
    generate: jwksKeyset,
  },
  {
    id: 'openssh:keypair', aliases: ['ssh-keypair', 'openssh'], category: 'Key Artifacts', kind: 'artifact',
    label: 'OpenSSH keypair', description: 'Native OpenSSH private key and authorized_keys public line.', env: null,
    options: [enumOption('algorithm', 'ed25519', ['ed25519', 'ecdsa', 'rsa']), integerOption('bits', 3072, 3072, 4096, 'bits', { algorithm: 'rsa' }), enumOption('curve', 'nistp256', ['nistp256', 'nistp384', 'nistp521'], { algorithm: 'ecdsa' }), stringOption('comment', 'secretgen'), ...privateEncryptionOptions()],
    countLimit: keyCountLimit, generate: opensshKeyPair,
  },
  {
    id: 'wireguard:keypair', aliases: ['wg-keypair'], category: 'Key Artifacts', kind: 'artifact',
    label: 'WireGuard keypair', description: 'WireGuard-compatible Base64 private and public keys.', env: null,
    options: [], countLimit: 100, generate: wireguardKeyPair,
  },
  {
    id: 'age:keypair', aliases: ['age-identity'], category: 'Key Artifacts', kind: 'artifact',
    label: 'age identity and recipient', description: 'Native age X25519 identity and recipient strings.', env: null,
    options: [], countLimit: 100, generate: ageKeyPair,
  },
  {
    id: 'paseto:v4-public-keypair', aliases: ['paseto-public', 'k4-public'], category: 'Key Artifacts', kind: 'artifact',
    label: 'PASETO v4.public keypair', description: 'Ed25519 PASETO v4.public keys serialized as PASERK.', env: null,
    options: [], countLimit: 100, generate: pasetoPublicKeyPair,
  },
  {
    id: 'sodium:box-keypair', aliases: ['sodium-box'], category: 'Key Artifacts', kind: 'artifact',
    label: 'libsodium box keypair', description: 'Raw crypto_box Curve25519 public/private keypair.', env: null,
    options: [], countLimit: 100, generate: sodiumBoxKeyPair,
  },
  {
    id: 'sodium:sign-keypair', aliases: ['sodium-sign'], category: 'Key Artifacts', kind: 'artifact',
    label: 'libsodium signing keypair', description: 'Raw crypto_sign Ed25519 public/secret keypair.', env: null,
    options: [], countLimit: 100, generate: sodiumSignKeyPair,
  },
  {
    id: 'dkim:keypair', aliases: ['dkim'], category: 'Key Artifacts', kind: 'artifact',
    label: 'DKIM keypair and DNS record', description: 'DKIM private key, public material and DNS TXT record.', env: null,
    options: [enumOption('algorithm', 'rsa', ['rsa', 'ed25519']), integerOption('bits', 2048, 2048, 4096, 'bits', { algorithm: 'rsa' }), stringOption('selector', 'default', { required: true }), stringOption('domain', '')],
    countLimit: keyCountLimit, generate: dkimKeyPair,
  },
];
