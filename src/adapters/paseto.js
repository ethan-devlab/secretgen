import { randomBytes } from 'node:crypto';
import { generateKeys } from 'paseto-ts/v4';

function nodeRandomValues(target) {
  target.set(randomBytes(target.length));
  return target;
}

export function generatePasetoV4LocalKey() {
  return generateKeys('local', { format: 'paserk', getRandomValues: nodeRandomValues });
}

export function generatePasetoV4PublicKeyPair() {
  return generateKeys('public', { format: 'paserk', getRandomValues: nodeRandomValues });
}

export { nodeRandomValues };
