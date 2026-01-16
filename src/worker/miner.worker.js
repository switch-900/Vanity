// Worker module: generates Taproot addresses and optionally mnemonics.

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

const SECP_P = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
const SECP_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
const Gy = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

function sha256(msg) {
  const l = msg.length;
  const bitLenHi = Math.floor((l * 8) / 0x100000000);
  const bitLenLo = (l * 8) >>> 0;

  const withOne = l + 1;
  const padLen = withOne % 64 <= 56 ? 56 - (withOne % 64) : 56 + (64 - (withOne % 64));
  const totalLen = withOne + padLen + 8;
  const m = new Uint8Array(totalLen);
  m.set(msg, 0);
  m[l] = 0x80;
  m[totalLen - 8] = (bitLenHi >>> 24) & 0xff;
  m[totalLen - 7] = (bitLenHi >>> 16) & 0xff;
  m[totalLen - 6] = (bitLenHi >>> 8) & 0xff;
  m[totalLen - 5] = bitLenHi & 0xff;
  m[totalLen - 4] = (bitLenLo >>> 24) & 0xff;
  m[totalLen - 3] = (bitLenLo >>> 16) & 0xff;
  m[totalLen - 2] = (bitLenLo >>> 8) & 0xff;
  m[totalLen - 1] = bitLenLo & 0xff;

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);
  for (let i = 0; i < m.length; i += 64) {
    for (let t = 0; t < 16; t++) {
      const j = i + t * 4;
      w[t] = ((m[j] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3]) >>> 0;
    }
    for (let t = 16; t < 64; t++) {
      const s0 = (rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3)) >>> 0;
      const s1 = (rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10)) >>> 0;
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }

    let a = h0,
      b = h1,
      c = h2,
      d = h3,
      e = h4,
      f = h5,
      g = h6,
      h = h7;

    for (let t = 0; t < 64; t++) {
      const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const temp1 = (h + S1 + ch + SHA256_K[t] + w[t]) >>> 0;
      const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const hs = [h0, h1, h2, h3, h4, h5, h6, h7];
  for (let i = 0; i < hs.length; i++) {
    out[i * 4] = (hs[i] >>> 24) & 0xff;
    out[i * 4 + 1] = (hs[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (hs[i] >>> 8) & 0xff;
    out[i * 4 + 3] = hs[i] & 0xff;
  }
  return out;
}

const TAPTWEAK_TAG = sha256(new TextEncoder().encode('TapTweak'));

function concat3(a, b, c) {
  const len = a.length + b.length + (c ? c.length : 0);
  const out = new Uint8Array(len);
  out.set(a, 0);
  out.set(b, a.length);
  if (c) out.set(c, a.length + b.length);
  return out;
}

function tapTweakHash(xOnlyPubkey32) {
  return sha256(concat3(TAPTWEAK_TAG, TAPTWEAK_TAG, xOnlyPubkey32));
}

function mod(a, m) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function invMod(a, m) {
  let lm = 1n,
    hm = 0n;
  let low = mod(a, m),
    high = m;
  while (low > 1n) {
    const r = high / low;
    const nm = hm - lm * r;
    const nw = high - low * r;
    hm = lm;
    lm = nm;
    high = low;
    low = nw;
  }
  return mod(lm, m);
}

function bytesToBigInt(bytes) {
  let x = 0n;
  for (const b of bytes) x = (x << 8n) + BigInt(b);
  return x;
}

function bigIntToBytes32(x) {
  let v = x;
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function isOdd(x) {
  return (x & 1n) === 1n;
}

function jacobianInfinity() {
  return { X: 0n, Y: 1n, Z: 0n };
}

function isInfinity(P) {
  return P.Z === 0n;
}

function jacobianDouble(P) {
  if (isInfinity(P)) return P;
  const X1 = P.X,
    Y1 = P.Y,
    Z1 = P.Z;
  const A = mod(X1 * X1, SECP_P);
  const B = mod(Y1 * Y1, SECP_P);
  const C = mod(B * B, SECP_P);
  const X1plusB = mod(X1 + B, SECP_P);
  const D = mod(2n * (mod(X1plusB * X1plusB, SECP_P) - A - C), SECP_P);
  const E = mod(3n * A, SECP_P);
  const F = mod(E * E, SECP_P);
  const X3 = mod(F - 2n * D, SECP_P);
  const Y3 = mod(E * (D - X3) - 8n * C, SECP_P);
  const Z3 = mod(2n * Y1 * Z1, SECP_P);
  return { X: X3, Y: Y3, Z: Z3 };
}

function jacobianAddMixed(P, Q) {
  if (isInfinity(P)) return { X: Q.x, Y: Q.y, Z: 1n };
  const X1 = P.X,
    Y1 = P.Y,
    Z1 = P.Z;
  const x2 = Q.x,
    y2 = Q.y;

  const Z1Z1 = mod(Z1 * Z1, SECP_P);
  const U2 = mod(x2 * Z1Z1, SECP_P);
  const S2 = mod(y2 * Z1 * Z1Z1, SECP_P);
  const H = mod(U2 - X1, SECP_P);
  const r = mod(2n * (S2 - Y1), SECP_P);

  if (H === 0n) {
    if (r === 0n) return jacobianDouble(P);
    return jacobianInfinity();
  }

  const HH = mod(H * H, SECP_P);
  const I = mod(4n * HH, SECP_P);
  const J = mod(H * I, SECP_P);
  const V = mod(X1 * I, SECP_P);
  const X3 = mod(r * r - J - 2n * V, SECP_P);
  const Y3 = mod(r * (V - X3) - 2n * Y1 * J, SECP_P);
  const Z3 = mod((Z1 + H) * (Z1 + H) - Z1Z1 - HH, SECP_P);
  return { X: X3, Y: Y3, Z: Z3 };
}

function jacobianToAffine(P) {
  if (isInfinity(P)) return null;
  const zInv = invMod(P.Z, SECP_P);
  const zInv2 = mod(zInv * zInv, SECP_P);
  const x = mod(P.X * zInv2, SECP_P);
  const y = mod(P.Y * zInv2 * zInv, SECP_P);
  return { x, y };
}

const G_AFFINE = { x: Gx, y: Gy };

function scalarMulG(k) {
  const n = k;
  let R = jacobianInfinity();
  for (let i = 255; i >= 0; i--) {
    R = jacobianDouble(R);
    if (((n >> BigInt(i)) & 1n) === 1n) R = jacobianAddMixed(R, G_AFFINE);
  }
  return jacobianToAffine(R);
}

function convertBits(data, fromBits, toBits, pad) {
  let acc = 0;
  let bits = 0;
  const ret = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    if (value < 0 || (value >> fromBits) !== 0) return null;
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
    return null;
  }
  return ret;
}

function bech32Polymod(values) {
  const GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GENERATORS[i];
  }
  return chk >>> 0;
}

function bech32HrpExpand(hrp) {
  const ret = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >>> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function bech32CreateChecksum(hrp, data, specConstant) {
  const values = bech32HrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const polymod = bech32Polymod(values) ^ specConstant;
  const ret = [];
  for (let p = 0; p < 6; p++) ret.push((polymod >>> (5 * (5 - p))) & 31);
  return ret;
}

function bech32Encode(hrp, data, specConstant) {
  const combined = data.concat(bech32CreateChecksum(hrp, data, specConstant));
  let ret = hrp + '1';
  for (const d of combined) ret += BECH32_CHARSET[d];
  return ret;
}

function encodeSegwitAddressV1(hrp, program) {
  const BECH32M = 0x2bc830a3;
  const data = [1].concat(convertBits(program, 8, 5, true));
  return bech32Encode(hrp, data, BECH32M);
}

function getTaprootAddressFromPrivkey(privBytes, hrp = 'bc') {
  let k = bytesToBigInt(privBytes);
  if (k === 0n || k >= SECP_N) return null;

  let P = scalarMulG(k);
  if (!P) return null;

  if (isOdd(P.y)) {
    k = mod(SECP_N - k, SECP_N);
    P = { x: P.x, y: mod(SECP_P - P.y, SECP_P) };
  }

  const xOnly = bigIntToBytes32(P.x);
  const tweakBytes = tapTweakHash(xOnly);
  const tweak = mod(bytesToBigInt(tweakBytes), SECP_N);
  const k2 = mod(k + tweak, SECP_N);
  if (k2 === 0n) return null;

  const Q = scalarMulG(k2);
  if (!Q) return null;
  const outX = bigIntToBytes32(Q.x);
  return encodeSegwitAddressV1(hrp, outX);
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function u32be(n) {
  const out = new Uint8Array(4);
  out[0] = (n >>> 24) & 0xff;
  out[1] = (n >>> 16) & 0xff;
  out[2] = (n >>> 8) & 0xff;
  out[3] = n & 0xff;
  return out;
}

function concatBytes(...arrs) {
  const len = arrs.reduce((n, a) => n + (a?.length || 0), 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

async function hmacSha512(keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, dataBytes);
  return new Uint8Array(sig);
}

async function pbkdf2Sha512(passwordBytes, saltBytes, iterations, outLenBytes) {
  const key = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-512' },
    key,
    outLenBytes * 8,
  );
  return new Uint8Array(bits);
}

function utf8Bytes(s) {
  return new TextEncoder().encode(s);
}

function modN(x) {
  const r = x % SECP_N;
  return r >= 0n ? r : r + SECP_N;
}

function getCompressedPubkeyFromPrivkey(privBytes) {
  let k = bytesToBigInt(privBytes);
  if (k === 0n || k >= SECP_N) return null;
  const P = scalarMulG(k);
  if (!P) return null;
  const prefix = isOdd(P.y) ? 0x03 : 0x02;
  const xBytes = bigIntToBytes32(P.x);
  const out = new Uint8Array(33);
  out[0] = prefix;
  out.set(xBytes, 1);
  return out;
}

async function bip32MasterFromSeed(seedBytes) {
  const I = await hmacSha512(utf8Bytes('Bitcoin seed'), seedBytes);
  const IL = I.slice(0, 32);
  const IR = I.slice(32);
  const k = bytesToBigInt(IL);
  if (k === 0n || k >= SECP_N) throw new Error('Invalid BIP32 master key');
  return { k, c: IR };
}

async function bip32CkdPriv(node, index, hardened) {
  const base = Number(index);
  if (!Number.isInteger(base) || base < 0 || base > 0x7fffffff) throw new Error('Invalid index');
  const idx = hardened ? ((base + 0x80000000) >>> 0) : base >>> 0;

  let data;
  if (hardened) {
    data = concatBytes(new Uint8Array([0]), bigIntToBytes32(node.k), u32be(idx));
  } else {
    const pub = getCompressedPubkeyFromPrivkey(bigIntToBytes32(node.k));
    if (!pub) throw new Error('Pubkey derivation failed');
    data = concatBytes(pub, u32be(idx));
  }

  const I = await hmacSha512(node.c, data);
  const IL = I.slice(0, 32);
  const IR = I.slice(32);
  const ILi = bytesToBigInt(IL);
  if (ILi >= SECP_N) throw new Error('Invalid BIP32 child (IL >= n)');
  const childK = modN(ILi + node.k);
  if (childK === 0n) throw new Error('Invalid BIP32 child (k == 0)');
  return { k: childK, c: IR };
}

async function deriveBip86FirstPrivkeyFromMnemonic(mnemonic) {
  const normalized = (mnemonic || '').trim().toLowerCase().replace(/\s+/g, ' ');
  if (!normalized) throw new Error('Missing mnemonic');
  const seed = await pbkdf2Sha512(utf8Bytes(normalized), utf8Bytes('mnemonic'), 2048, 64);
  let node = await bip32MasterFromSeed(seed);
  node = await bip32CkdPriv(node, 86, true);
  node = await bip32CkdPriv(node, 0, true);
  node = await bip32CkdPriv(node, 0, true);
  node = await bip32CkdPriv(node, 0, false);
  node = await bip32CkdPriv(node, 0, false);
  return bigIntToBytes32(node.k);
}

function getBit(bytes, bitIndex) {
  const byteIndex = Math.floor(bitIndex / 8);
  const offset = 7 - (bitIndex % 8);
  return (bytes[byteIndex] >> offset) & 1;
}

function bitsToInt(bits, start, length) {
  let v = 0;
  for (let i = 0; i < length; i++) v = (v << 1) | bits[start + i];
  return v;
}

function validateBip39MnemonicChecksum(mnemonic, wordlist) {
  if (!Array.isArray(wordlist) || wordlist.length !== 2048) {
    throw new Error('Missing BIP39 wordlist');
  }

  const words = String(mnemonic || '')
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);

  const wc = words.length;
  if (wc !== 12 && wc !== 24) {
    throw new Error('Mnemonic must be 12 or 24 words to validate');
  }

  const wordToIndex = new Map();
  for (let i = 0; i < wordlist.length; i++) wordToIndex.set(wordlist[i], i);

  const totalBits = wc * 11;
  const bits = new Array(totalBits);
  let bitPos = 0;

  for (const w of words) {
    const idx = wordToIndex.get(w);
    if (typeof idx !== 'number') throw new Error(`Invalid BIP39 word: ${JSON.stringify(w)}`);
    for (let b = 10; b >= 0; b--) bits[bitPos++] = (idx >> b) & 1;
  }

  const entBits = wc === 12 ? 128 : 256;
  const checksumBits = entBits / 32;

  const entBytes = entBits / 8;
  const entropy = new Uint8Array(entBytes);
  for (let i = 0; i < entBytes; i++) {
    let v = 0;
    for (let b = 0; b < 8; b++) v = (v << 1) | bits[i * 8 + b];
    entropy[i] = v;
  }

  const hash = sha256(entropy);
  for (let i = 0; i < checksumBits; i++) {
    const want = getBit(hash, i);
    const have = bits[entBits + i];
    if (want !== have) throw new Error('BIP39 checksum mismatch');
  }
}

function computeBip39LastWordCandidates(prefixWords, wordCount, wordlist) {
  if (!Array.isArray(prefixWords)) throw new Error('Missing prefixWords');
  if (!Array.isArray(wordlist) || wordlist.length !== 2048) throw new Error('Missing BIP39 wordlist');
  if (wordCount !== 12 && wordCount !== 24) throw new Error('Word count must be 12 or 24');
  if (prefixWords.length !== wordCount - 1) throw new Error(`Need exactly ${wordCount - 1} words to compute last-word candidates`);

  const wordToIndex = new Map();
  for (let i = 0; i < wordlist.length; i++) wordToIndex.set(wordlist[i], i);

  const prefixBits = [];
  for (const w of prefixWords) {
    const idx = wordToIndex.get(String(w || '').trim().toLowerCase());
    if (typeof idx !== 'number') throw new Error(`Invalid BIP39 word: ${JSON.stringify(w)}`);
    for (let b = 10; b >= 0; b--) prefixBits.push((idx >> b) & 1);
  }

  const entBits = wordCount === 12 ? 128 : 256;
  const checksumBits = entBits / 32;
  const remainingEntBits = entBits - prefixBits.length;

  if (remainingEntBits <= 0 || remainingEntBits >= 11) {
    throw new Error('Unexpected prefix length for BIP39');
  }

  const candidates = new Set();

  const max = 1 << remainingEntBits;
  for (let suffixEnt = 0; suffixEnt < max; suffixEnt++) {
    const entropyBits = prefixBits.slice();
    for (let b = remainingEntBits - 1; b >= 0; b--) entropyBits.push((suffixEnt >> b) & 1);

    const entBytes = entBits / 8;
    const entropy = new Uint8Array(entBytes);
    for (let i = 0; i < entBytes; i++) {
      let v = 0;
      for (let b = 0; b < 8; b++) v = (v << 1) | entropyBits[i * 8 + b];
      entropy[i] = v;
    }

    const hash = sha256(entropy);
    let checksumVal = 0;
    for (let i = 0; i < checksumBits; i++) checksumVal = (checksumVal << 1) | getBit(hash, i);

    const lastIndex = (suffixEnt << checksumBits) | checksumVal;
    candidates.add(wordlist[lastIndex]);
  }

  return Array.from(candidates);
}

function generateMnemonic(wordCount, wordlist) {
  const entBits = wordCount === 12 ? 128 : 256;
  const entBytes = entBits / 8;
  const checksumBits = entBits / 32;

  const entropy = new Uint8Array(entBytes);
  crypto.getRandomValues(entropy);
  const hash = sha256(entropy);

  const totalBits = entBits + checksumBits;
  const bits = new Array(totalBits);
  for (let i = 0; i < entBits; i++) bits[i] = getBit(entropy, i);
  for (let i = 0; i < checksumBits; i++) bits[entBits + i] = getBit(hash, i);

  const words = [];
  for (let i = 0; i < totalBits; i += 11) {
    const idx = bitsToInt(bits, i, 11);
    words.push(wordlist[idx]);
  }
  return words.join(' ');
}

function validatePattern(pattern) {
  const bad = Array.from(new Set(pattern.split('').filter((c) => !BECH32_CHARSET.includes(c)))).sort();
  if (bad.length) throw new Error('Invalid chars: ' + bad.join(''));
}

let running = false;

self.onmessage = async (ev) => {
  const { type, runId, prefix, suffix, outputKind, wordCount, wordlist, mnemonic, prefixWords } = ev.data || {};

  try {
    if (type === 'checksumCandidates') {
      const candidates = computeBip39LastWordCandidates(prefixWords, wordCount, wordlist);
      self.postMessage({ type: 'checksumCandidates', candidates });
      return;
    }

    if (type === 'derive') {
      if (!mnemonic) {
        self.postMessage({ type: 'error', error: 'Missing mnemonic' });
        return;
      }

      // Safety: when deriving from a user-picked mnemonic, validate that the
      // phrase is a real BIP39 mnemonic (checksum) if we were given a wordlist.
      // This prevents users from generating a phrase that common wallets reject.
      if (Array.isArray(wordlist) && wordlist.length === 2048) {
        validateBip39MnemonicChecksum(mnemonic, wordlist);
      }

      const priv = await deriveBip86FirstPrivkeyFromMnemonic(mnemonic);
      const address = getTaprootAddressFromPrivkey(priv, 'bc');
      if (!address) {
        self.postMessage({ type: 'error', error: 'Failed to derive address' });
        return;
      }
      self.postMessage({ type: 'derived', address });
      return;
    }

    running = true;

    if (prefix) validatePattern(prefix);
    if (suffix) validatePattern(suffix);

    const wantPrefix = prefix ? 'bc1p' + prefix : null;
    const wantSuffix = suffix || null;

    let attempts = 0;
    let lastProgress = performance.now();

    while (running) {
      let address = null;
      let secret = null;
      let secretLabel = null;

      if (outputKind === 'mnemonic') {
        const wc = wordCount === 24 ? 24 : 12;
        if (!Array.isArray(wordlist) || wordlist.length !== 2048) throw new Error('Missing BIP39 wordlist');
        const mnem = generateMnemonic(wc, wordlist);
        const priv = await deriveBip86FirstPrivkeyFromMnemonic(mnem);
        address = getTaprootAddressFromPrivkey(priv, 'bc');
        if (!address) continue;
        secret = mnem;
        secretLabel = wc === 24 ? 'Seed phrase (24 words)' : 'Seed phrase (12 words)';
      } else {
        const priv = new Uint8Array(32);
        crypto.getRandomValues(priv);
        address = getTaprootAddressFromPrivkey(priv, 'bc');
        if (!address) continue;
        secret = bytesToHex(priv);
        secretLabel = 'Private key (hex)';
      }

      const okPrefix = wantPrefix ? address.startsWith(wantPrefix) : true;
      const okSuffix = wantSuffix ? address.endsWith(wantSuffix) : true;
      attempts++;

      if (okPrefix && okSuffix) {
        self.postMessage({ type: 'found', runId, address, secret, secretLabel, attempts });
        return;
      }

      const now = performance.now();
      if (now - lastProgress > 250) {
        self.postMessage({ type: 'progress', runId, attempts });
        attempts = 0;
        lastProgress = now;
      }
    }
  } catch (e) {
    self.postMessage({ type: 'error', runId, error: String(e?.message || e) });
  }
};
