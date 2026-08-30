import { calculateJwkThumbprint, exportJWK } from 'jose';

export async function exportJwkPair(pair, metadata, algorithm) {
  const [privateJwk, publicJwk] = await Promise.all([
    exportJWK(pair.privateKey),
    exportJWK(pair.publicKey),
  ]);
  const kid = await calculateJwkThumbprint(publicJwk);
  Object.assign(privateJwk, metadata, { kid });
  Object.assign(publicJwk, metadata, { kid });
  return { privateJwk, publicJwk, metadata: { ...metadata, kid, algorithm } };
}
