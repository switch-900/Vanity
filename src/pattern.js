import { BECH32_CHARSET } from './constants.js';

export function norm(s) {
  return (s || '').trim().toLowerCase();
}

export function validatePattern(pattern) {
  const bad = Array.from(new Set(pattern.split('').filter((c) => !BECH32_CHARSET.includes(c)))).sort();
  if (bad.length) throw new Error('Invalid characters: ' + bad.join(''));
}
