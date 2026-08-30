import { randomBytes } from 'node:crypto';
import { generateHOTP, generateTOTP, parseURI } from '@otplib/uri';
import { encodeBase32 } from './encoding.js';

export function generateOtpSecret(bytes) {
  return encodeBase32(randomBytes(bytes));
}

function otpUri(strategy, options, secret) {
  const shared = {
    issuer: options.issuer || 'secretgen',
    label: options.account,
    secret,
    digits: options.digits,
  };
  const uri = strategy === 'hotp' ? generateHOTP({ ...shared, counter: options.counter }) : generateTOTP({
    ...shared,
    algorithm: options.algorithm.toLowerCase(),
    period: options.period,
  });
  parseURI(uri);
  return uri;
}

export function generateHotpUri(options, secret) {
  return otpUri('hotp', options, secret);
}

export function generateTotpUri(options, secret) {
  return otpUri('totp', options, secret);
}
