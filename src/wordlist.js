import { BIP39_WORDLIST_INSCRIPTION_ID } from './constants.js';

function parseWordsTextOrThrow(text, label) {
  const words = String(text || '')
    .split(/\r?\n/)
    .map((w) => w.trim())
    .filter(Boolean);

  if (words.length !== 2048) {
    throw new Error(`${label} must be 2048 words (got ${words.length}).`);
  }

  // Treat remote content as untrusted: enforce the expected shape.
  // BIP39 English list is lowercase a-z words.
  for (const w of words) {
    if (!/^[a-z]+$/.test(w)) {
      throw new Error(`${label} contains an invalid word: ${JSON.stringify(w)}`);
    }
  }

  return words;
}

function parseEmbeddedWordlistOrNull() {
  const el = document.getElementById('embeddedBip39Wordlist');
  const text = (el?.textContent || '').trim();
  if (!text) return null;
  return parseWordsTextOrThrow(text, 'Embedded BIP39 wordlist');
}

async function fetchText(url) {
  const res = await fetch(url, {
    cache: 'force-cache',
    redirect: 'follow',
    referrerPolicy: 'no-referrer',
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return await res.text();
}

let wordlistPromise = null;
export async function getBip39Wordlist() {
  if (wordlistPromise) return wordlistPromise;

  wordlistPromise = (async () => {
    const relUrl = `/content/${BIP39_WORDLIST_INSCRIPTION_ID}`;
    const absUrl = `https://ordinals.com/content/${BIP39_WORDLIST_INSCRIPTION_ID}`;

    try {
      return parseWordsTextOrThrow(await fetchText(relUrl), 'BIP39 wordlist');
    } catch {
      try {
        return parseWordsTextOrThrow(await fetchText(absUrl), 'BIP39 wordlist');
      } catch {
        const embedded = parseEmbeddedWordlistOrNull();
        if (embedded) return embedded;
        throw new Error(
          'Failed to load BIP39 wordlist from inscription and none embedded. ' +
            `Tried ${relUrl} and ${absUrl}.`,
        );
      }
    }
  })();

  return wordlistPromise;
}
