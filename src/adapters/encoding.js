import {
  base32,
  base32crockford,
  base32hex,
  base32hexnopad,
  base32nopad,
  base58,
} from '@scure/base';

function requireBytes(value) {
  if (!(value instanceof Uint8Array)) throw new TypeError('encoding input must be a Uint8Array');
  return value;
}

export function encodeBase32(value, padding = false) {
  return (padding ? base32 : base32nopad).encode(requireBytes(value));
}

export function encodeBase32Hex(value, padding = false) {
  return (padding ? base32hex : base32hexnopad).encode(requireBytes(value));
}

export function encodeBase32Crockford(value) {
  return base32crockford.encode(requireBytes(value));
}

export function encodeBase58(value) {
  return base58.encode(requireBytes(value));
}
