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

export function uuidV4() {
  return randomUUID();
}

export function assertInteger(name, value, min, max) {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new RangeError(`${name} must be an integer between ${min} and ${max}`);
  }
}
