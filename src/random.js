import { randomBytes as nodeRandomBytes, randomInt, randomUUID } from 'node:crypto';

export const ALPHANUMERIC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
export const URLSAFE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
export const URL_UNRESERVED = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
export const DIGITS = '0123456789';
export const PRINTABLE_ASCII = Array.from({ length: 94 }, (_, i) => String.fromCharCode(i + 33)).join('');
export const DJANGO_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)';
export const WORDPRESS_SECRET_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_ []{}<>~`+=,.;:/?|';

export function secureBytes(size) {
  assertInteger('bytes', size, 1, 4096);
  return nodeRandomBytes(size);
}

export function randomString(length, alphabet = ALPHANUMERIC) {
  assertInteger('length', length, 1, 16384);
  if (typeof alphabet !== 'string' || alphabet.length < 2) {
    throw new TypeError('alphabet must contain at least 2 characters');
  }

  let output = '';
  for (let i = 0; i < length; i += 1) {
    output += alphabet[randomInt(0, alphabet.length)];
  }
  return output;
}

export function randomIndex(upperBound) {
  assertInteger('upperBound', upperBound, 2, 0x7fffffff);
  return randomInt(0, upperBound);
}

export function hex(bytes) {
  return secureBytes(bytes).toString('hex');
}

export function base64(bytes) {
  return secureBytes(bytes).toString('base64');
}

export function base64url(bytes) {
  return secureBytes(bytes).toString('base64url');
}

export function fernetBase64url(bytes = 32) {
  // Fernet uses URL-safe Base64 *with* padding.
  return secureBytes(bytes)
    .toString('base64')
    .replaceAll('+', '-')
    .replaceAll('/', '_');
}

export function encodeBase32(input, padding = false) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
      value &= bits === 0 ? 0 : (1 << bits) - 1;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  if (padding) output += '='.repeat((8 - (output.length % 8)) % 8);

  return output;
}

export function base32(bytes, padding = false) {
  return encodeBase32(secureBytes(bytes), padding);
}

export function uuidV4() {
  return randomUUID();
}

export function uuidV7(now = Date.now()) {
  if (!Number.isInteger(now) || now < 0 || now > 0xffffffffffff) {
    throw new RangeError('UUIDv7 timestamp must be an integer in the 48-bit Unix millisecond range');
  }
  const bytes = secureBytes(16);
  let timestamp = BigInt(now);
  for (let i = 5; i >= 0; i -= 1) {
    bytes[i] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  bytes[6] = 0x70 | (bytes[6] & 0x0f);
  bytes[8] = 0x80 | (bytes[8] & 0x3f);
  const value = bytes.toString('hex');
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}

export function assertInteger(name, value, min, max) {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new RangeError(`${name} must be an integer between ${min} and ${max}`);
  }
}
