import { norm, validatePattern } from './pattern.js';
import { getBip39Wordlist } from './wordlist.js';
import { createMinerWorker } from './worker/createMinerWorker.js';

const $ = (id) => document.getElementById(id);

let currentRun = null;
let activeDeriveWorker = null;
let modalMode = 'status';
let currentSecret = null;
let currentSecretLabel = 'Secret';
let isSecretRevealed = false;

let isAddrQrVisible = false;
let lastQrAddress = '';

let isSecretQrPanelVisible = false;
let secretQrScanStream = null;
let isSecretQrScanActive = false;

function b64url(bytes) {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromB64url(s) {
  const str = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
  const bin = atob(str + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function clearSecretQr() {
  isSecretQrPanelVisible = false;
  const panel = $('secretQrPanel');
  const wrap = $('secretQrWrap');
  const holder = $('secretQr');
  const pass = $('secretQrPass');
  const ct = $('secretQrCiphertext');
  const plain = $('secretQrPlain');
  const btn = $('toggleSecretQr');
  const scanWrap = $('secretQrScanWrap');
  const video = $('secretQrVideo');
  const scanBtn = $('btnSecretQrScan');

  if (panel) panel.classList.add('hidden');
  if (wrap) wrap.classList.add('hidden');
  if (holder) holder.replaceChildren();
  if (pass) pass.value = '';
  if (ct) ct.value = '';
  if (plain) {
    plain.textContent = '';
    plain.classList.add('hidden');
  }
  stopSecretQrScan();
  if (scanWrap) scanWrap.classList.add('hidden');
  if (video) video.srcObject = null;
  if (scanBtn) scanBtn.textContent = 'Scan';
  if (btn) btn.textContent = 'QR';
}

function getSelfInscriptionId() {
  const parts = String(window.location.pathname || '').split('/').filter(Boolean);
  const last = parts[parts.length - 1] || '';

  // Ordinals content is typically /content/<id>
  if (parts.length >= 2 && parts[parts.length - 2] === 'content' && last) return last;

  // Some hosts might serve as /<id>
  if (last && last.includes('i0')) return last;

  return '';
}

function getAppShareUrl() {
  // Prefer the canonical ordinals URL when we can self-identify.
  const id = getSelfInscriptionId();
  if (id) return `https://ordinals.com/content/${id}`;
  return window.location.href.split('#')[0];
}

function toUtf8Bytes(s) {
  return new TextEncoder().encode(String(s ?? ''));
}

function makeDeepLinkWithCiphertext(ciphertextText) {
  // Put ciphertext in the URL fragment so it is not sent to servers via HTTP.
  // Example: https://ordinals.com/content/<id>#venc=<b64url(utf8(VANITY_ENC_V1\n{json}))>
  const base = getAppShareUrl();
  const enc = b64url(toUtf8Bytes(String(ciphertextText || '').trim()));
  return `${base}#venc=${enc}`;
}

function extractCiphertextFromScannedString(raw) {
  const s = String(raw || '').trim();
  if (!s) return '';
  if (s.startsWith('VANITY_ENC_V1')) return s;

  // Deep-link form: https://...#venc=<b64url(utf8(payload))>
  try {
    const u = new URL(s);
    const hash = String(u.hash || '');
    const search = String(u.search || '');
    const fromHash = new URLSearchParams(hash.startsWith('#') ? hash.slice(1) : hash).get('venc');
    const fromQuery = new URLSearchParams(search.startsWith('?') ? search.slice(1) : search).get('venc');
    const venc = fromHash || fromQuery || '';
    if (!venc) return '';
    return new TextDecoder().decode(fromB64url(venc));
  } catch {
    return '';
  }
}

function showDecryptOnlyWithCiphertext(ciphertextText) {
  // Show the existing modal result UI, but focus on decrypting an imported payload.
  setStatusHeader({ title: 'Decrypt', spinner: false });
  setModalMode('result');

  $('statusCard').classList.remove('hidden');
  $('statusBackdrop').classList.remove('hidden');

  // No in-memory secret in this mode.
  currentSecret = null;
  currentSecretLabel = 'Secret';
  setSecretRevealState(false);

  $('addr').textContent = '';
  clearAddressQr();

  $('secLabel').textContent = 'Decrypt';
  $('secret').textContent = '';
  if ($('copySec')) $('copySec').disabled = true;
  if ($('toggleSecret')) $('toggleSecret').disabled = true;

  // Open the QR panel directly so the user only needs to enter a password.
  isSecretQrPanelVisible = true;
  $('secretQrPanel')?.classList.remove('hidden');
  $('toggleSecretQr') && ($('toggleSecretQr').textContent = 'Hide QR');

  // Disable encrypt-generation controls since there is no secret in this mode.
  if ($('btnSecretQr')) $('btnSecretQr').disabled = true;

  const ct = $('secretQrCiphertext');
  if (ct) ct.value = String(ciphertextText || '').trim();

  const pass = $('secretQrPass');
  if (pass) pass.focus();

  setResultNote('✓ Payload loaded — enter password to decrypt');
  clearResultNoteSoon();

  updateStatusActions();
}

function tryImportCiphertextFromUrl() {
  const rawHash = String(window.location.hash || '');
  if (!rawHash || rawHash.length < 2) return false;

  const params = new URLSearchParams(rawHash.startsWith('#') ? rawHash.slice(1) : rawHash);
  const venc = params.get('venc');
  if (!venc) return false;

  let text = '';
  try {
    text = new TextDecoder().decode(fromB64url(venc));
  } catch {
    show('❌ Invalid payload in URL', { mode: 'status' });
    return true;
  }

  // Clear the fragment so the ciphertext isn't left sitting in the URL bar/history.
  try {
    history.replaceState(null, '', window.location.href.split('#')[0]);
  } catch {
    // no-op
  }

  showDecryptOnlyWithCiphertext(text);
  return true;
}

function stopSecretQrScan() {
  isSecretQrScanActive = false;
  if (secretQrScanStream) {
    try {
      for (const track of secretQrScanStream.getTracks()) track.stop();
    } catch {
      // no-op
    }
    secretQrScanStream = null;
  }
}

async function startSecretQrScan() {
  const scanWrap = $('secretQrScanWrap');
  const video = $('secretQrVideo');
  const scanBtn = $('btnSecretQrScan');
  const ct = $('secretQrCiphertext');
  if (!scanWrap || !video || !ct) return;
  if (isSecretQrScanActive) return;

  if (!navigator.mediaDevices?.getUserMedia) throw new Error('Camera not supported in this browser.');
  if (!('BarcodeDetector' in window)) throw new Error('QR scanning not supported in this browser.');

  secretQrScanStream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: { ideal: 'environment' } },
    audio: false,
  });

  video.srcObject = secretQrScanStream;
  video.setAttribute('playsinline', 'true');
  await video.play();

  isSecretQrScanActive = true;
  scanWrap.classList.remove('hidden');
  if (scanBtn) scanBtn.textContent = 'Stop';

  const detector = new window.BarcodeDetector({ formats: ['qr_code'] });

  const tick = async () => {
    if (!isSecretQrScanActive) return;
    try {
      const barcodes = await detector.detect(video);
      const value = barcodes?.[0]?.rawValue;
      if (typeof value === 'string' && value.trim()) {
        const extracted = extractCiphertextFromScannedString(value);
        ct.value = (extracted || value).trim();
        stopSecretQrScan();
        scanWrap.classList.add('hidden');
        if (scanBtn) scanBtn.textContent = 'Scan';
        return;
      }
    } catch {
      // ignore transient detector errors
    }
    window.requestAnimationFrame(tick);
  };

  window.requestAnimationFrame(tick);
}

function toggleSecretQrScan() {
  const scanWrap = $('secretQrScanWrap');
  const scanBtn = $('btnSecretQrScan');
  const video = $('secretQrVideo');
  if (!scanWrap) return;

  if (isSecretQrScanActive) {
    stopSecretQrScan();
    scanWrap.classList.add('hidden');
    if (video) video.srcObject = null;
    if (scanBtn) scanBtn.textContent = 'Scan';
    return;
  }

  startSecretQrScan().catch((e) => {
    stopSecretQrScan();
    scanWrap.classList.add('hidden');
    if (video) video.srcObject = null;
    if (scanBtn) scanBtn.textContent = 'Scan';
    showModal('Scan error', String(e?.message || e), 'error');
  });
}

async function encryptSecretForQr({ password, secret }) {
  if (!globalThis.crypto?.subtle) throw new Error('WebCrypto is not available in this environment.');
  const pass = String(password || '');
  if (!pass) throw new Error('Password required.');

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const iterations = 200000;

  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, [
    'deriveKey',
  ]);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );

  const pt = new TextEncoder().encode(String(secret || ''));
  const ctBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);
  const ct = new Uint8Array(ctBuf);

  const payload = {
    v: 1,
    kdf: 'PBKDF2-SHA256',
    iter: iterations,
    cipher: 'AES-256-GCM',
    salt: b64url(salt),
    iv: b64url(iv),
    ct: b64url(ct),
  };

  // IMPORTANT (mobile-friendly): do NOT use a custom scheme like "vanity-enc:..."
  // Many phone camera scanners treat "<scheme>:" as a URL/deeplink and then show
  // "no app can open this". Plain text makes scanners show "Copy text".
  return `VANITY_ENC_V1\n${JSON.stringify(payload)}`;
}

async function decryptSecretFromQrText({ password, text }) {
  if (!globalThis.crypto?.subtle) throw new Error('WebCrypto is not available in this environment.');
  const pass = String(password || '');
  if (!pass) throw new Error('Password required.');

  const raw = String(text || '').trim();
  if (!raw) throw new Error('Paste the scanned text first.');

  // Expect format:
  // VANITY_ENC_V1\n{json}
  const idx = raw.indexOf('\n');
  const header = (idx >= 0 ? raw.slice(0, idx) : raw).trim();
  if (header !== 'VANITY_ENC_V1') {
    throw new Error('Not a VANITY_ENC_V1 payload.');
  }
  const jsonText = (idx >= 0 ? raw.slice(idx + 1) : '').trim();
  if (!jsonText) throw new Error('Missing payload JSON.');

  let payload;
  try {
    payload = JSON.parse(jsonText);
  } catch {
    throw new Error('Invalid payload JSON.');
  }

  if (!payload || payload.v !== 1) throw new Error('Unsupported payload version.');
  if (payload.kdf !== 'PBKDF2-SHA256') throw new Error('Unsupported KDF.');
  if (payload.cipher !== 'AES-256-GCM') throw new Error('Unsupported cipher.');

  const iterations = Number(payload.iter);
  if (!Number.isFinite(iterations) || iterations < 1) throw new Error('Invalid iteration count.');

  const salt = fromB64url(payload.salt);
  const iv = fromB64url(payload.iv);
  const ct = fromB64url(payload.ct);

  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, [
    'deriveKey',
  ]);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );

  let ptBuf;
  try {
    ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  } catch {
    throw new Error('Decrypt failed (wrong password or corrupted data).');
  }

  return new TextDecoder().decode(new Uint8Array(ptBuf));
}

async function generateSecretEncryptedQr() {
  const secret = String(currentSecret || '');
  if (!secret) return;

  const passEl = $('secretQrPass');
  const password = String(passEl?.value || '');
  const holder = $('secretQr');
  const wrap = $('secretQrWrap');
  if (!holder || !wrap) return;

  try {
    setResultNote('');
    const ciphertextText = await encryptSecretForQr({ password, secret });
    const text = makeDeepLinkWithCiphertext(ciphertextText);

    const QrCreator = globalThis.QrCreator;
    if (!QrCreator || typeof QrCreator.render !== 'function') {
      throw new Error('QR library not available in this environment.');
    }

    holder.replaceChildren();
    const canvas = document.createElement('canvas');
    QrCreator.render(
      {
        text,
        size: 240,
        ecLevel: 'M',
        radius: 0,
        quiet: 2,
        fill: '#000',
        background: '#fff',
      },
      canvas,
    );
    holder.appendChild(canvas);
    wrap.classList.remove('hidden');
    setResultNote('✓ Encrypted QR generated');
    clearResultNoteSoon();
  } catch (e) {
    setResultNote('❌ ' + String(e?.message || e));
  }
}

async function decryptSecretEncryptedText() {
  const pass = String($('secretQrPass')?.value || '');
  const ct = String($('secretQrCiphertext')?.value || '');
  const out = $('secretQrPlain');
  if (!out) return;

  try {
    setResultNote('');
    const secret = await decryptSecretFromQrText({ password: pass, text: ct });
    out.textContent = secret;
    out.classList.remove('hidden');
    setResultNote('✓ Decrypted locally');
    clearResultNoteSoon();
  } catch (e) {
    out.textContent = '';
    out.classList.add('hidden');
    setResultNote('❌ ' + String(e?.message || e));
  }
}

function clearAddressQr() {
  isAddrQrVisible = false;
  lastQrAddress = '';
  const wrap = $('addrQrWrap');
  const holder = $('addrQr');
  const btn = $('toggleAddrQr');

  if (wrap) wrap.classList.add('hidden');
  if (holder) holder.replaceChildren();
  if (btn) btn.textContent = 'QR';
}

function renderAddressQr(address) {
  const holder = $('addrQr');
  if (!holder) return;
  holder.replaceChildren();

  const QrCreator = globalThis.QrCreator;
  if (!QrCreator || typeof QrCreator.render !== 'function') {
    setResultNote('⚠️ QR library not available in this environment.');
    clearAddressQr();
    return;
  }

  const canvas = document.createElement('canvas');
  // QrCreator can render into a canvas element directly.
  QrCreator.render(
    {
      text: address,
      size: 240,
      ecLevel: 'M',
      radius: 0,
      quiet: 2,
      fill: '#000',
      background: '#fff',
    },
    canvas,
  );
  holder.appendChild(canvas);
}

function setAddressQrVisible(visible) {
  const v = Boolean(visible);
  const wrap = $('addrQrWrap');
  const btn = $('toggleAddrQr');
  if (wrap) wrap.classList.toggle('hidden', !v);
  if (btn) btn.textContent = v ? 'Hide QR' : 'QR';

  isAddrQrVisible = v;
  if (!v) return;

  const addr = String($('addr')?.textContent || '').trim();
  if (!addr) {
    clearAddressQr();
    return;
  }

  if (addr !== lastQrAddress) {
    lastQrAddress = addr;
    renderAddressQr(addr);
  }
}

function setSecretRevealState(revealed) {
  isSecretRevealed = Boolean(revealed);
  const toggle = $('toggleSecret');
  const copyBtn = $('copySec');

  if (toggle) toggle.textContent = isSecretRevealed ? 'Hide' : 'Reveal';
  if (copyBtn) copyBtn.disabled = !isSecretRevealed;

  if (isSecretRevealed) {
    $('secret').textContent = currentSecret || '';
  } else {
    $('secret').textContent = currentSecret ? 'Hidden — tap Reveal' : '';
  }
}

function wipeSensitiveData() {
  // Stop any work first.
  if (activeDeriveWorker) {
    try {
      activeDeriveWorker.terminate();
    } finally {
      activeDeriveWorker = null;
    }
  }
  stopCurrentRun();

  // Clear in-memory sensitive data.
  currentSecret = null;
  currentSecretLabel = 'Secret';
  isSecretRevealed = false;

  // Clear UI fields (also covers copy targets).
  $('addr').textContent = '';
  clearAddressQr();
  clearSecretQr();
  $('secLabel').textContent = 'Secret';
  if ($('copySec')) $('copySec').disabled = true;
  if ($('toggleSecret')) $('toggleSecret').textContent = 'Reveal';
  $('secret').textContent = '';
  $('status').textContent = '';
  setResultNote('');

  // Hide modal/backdrop so no stale content remains visible.
  $('statusCard').classList.add('hidden');
  $('statusBackdrop').classList.add('hidden');
  setModalMode('status');

  // Pick-words mode: clear selected words so the seed isn't left on screen.
  selectedWords = [];
  lastDuplicateWord = null;
  lastDuplicateAt = 0;
  renderSelectedWords();
  updateWordCount();
}

function updateStatusActions() {
  const canCancel = Boolean(currentRun || activeDeriveWorker);
  const btn = $('btnCancel');
  if (btn) btn.disabled = !canCancel;

  const actions = $('statusActions');
  if (actions) actions.classList.toggle('hidden', !canCancel);
}

function setModalMode(mode) {
  // mode: 'status' | 'result'
  modalMode = mode;
  $('statusView').classList.toggle('hidden', mode !== 'status');
  $('resultView').classList.toggle('hidden', mode !== 'result');
}

function setResultNote(text) {
  const el = $('resultNote');
  if (!el) return;
  const msg = String(text || '').trim();
  el.textContent = msg;
  el.classList.toggle('hidden', !msg);
}

function clearResultNoteSoon() {
  window.clearTimeout(clearResultNoteSoon._t);
  clearResultNoteSoon._t = window.setTimeout(() => setResultNote(''), 1800);
}

function setStatusHeader({ title, spinner }) {
  $('statusTitle').textContent = title;
  $('statusSpinner').classList.toggle('hidden', !spinner);
}

function show(text, { mode } = {}) {
  $('statusCard').classList.remove('hidden');
  $('statusBackdrop').classList.remove('hidden');

  if (mode) setModalMode(mode);
  $('status').textContent = text;

  const running = Boolean(currentRun || activeDeriveWorker);
  if (modalMode === 'status') {
    if (running) {
      setStatusHeader({ title: 'Working…', spinner: true });
    } else if (String(text || '').startsWith('❌')) {
      setStatusHeader({ title: 'Error', spinner: false });
    } else if (String(text || '').startsWith('✓')) {
      setStatusHeader({ title: 'Done', spinner: false });
    } else {
      setStatusHeader({ title: 'Status', spinner: false });
    }
  }

  updateStatusActions();
}

function hideStatusSoon() {
  window.clearTimeout(hideStatusSoon._t);
  hideStatusSoon._t = window.setTimeout(() => {
    // Don't auto-hide while work is active.
    if (currentRun || activeDeriveWorker) return;
    if (modalMode !== 'status') return;
    $('statusCard').classList.add('hidden');
    $('statusBackdrop').classList.add('hidden');
  }, 1800);
}

function clearResultFields() {
  $('addr').textContent = '';
  clearAddressQr();
  clearSecretQr();
  $('secret').textContent = '';
  setResultNote('');

  currentSecret = null;
  currentSecretLabel = 'Secret';
  setSecretRevealState(false);
}

function hideResult() {
  setModalMode('status');
  clearResultFields();
}

function showResult({ address, secret, secretLabel }) {
  $('addr').textContent = address;
  clearAddressQr();
  clearSecretQr();
  currentSecret = secret;
  currentSecretLabel = secretLabel;
  $('secLabel').textContent = secretLabel;
  setSecretRevealState(false);
  setResultNote('');

  setStatusHeader({ title: '✓ Success!', spinner: false });
  setModalMode('result');

  $('statusCard').classList.remove('hidden');
  $('statusBackdrop').classList.remove('hidden');

  updateStatusActions();
}

async function copyToClipboard(label, text) {
  if (!text) return;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      if (modalMode === 'result') {
        setResultNote(`✓ ${label} copied`);
        clearResultNoteSoon();
      } else {
        show(`✓ ${label} copied`, { mode: 'status' });
        hideStatusSoon();
      }
      return;
    }

    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);

    if (modalMode === 'result') {
      setResultNote(`✓ ${label} copied`);
      clearResultNoteSoon();
    } else {
      show(`✓ ${label} copied`, { mode: 'status' });
      hideStatusSoon();
    }
  } catch (e) {
    show(String(e?.message || e), { mode: 'status' });
  }
}

function formatNumberShort(n) {
  if (!Number.isFinite(n)) return String(n);
  if (n < 1000) return Math.round(n).toLocaleString();
  const units = ['K', 'M', 'B', 'T'];
  let v = n;
  let u = -1;
  while (v >= 1000 && u < units.length - 1) {
    v /= 1000;
    u++;
  }
  return v.toFixed(v >= 10 ? 1 : 2) + units[u];
}

function formatDuration(sec) {
  if (!Number.isFinite(sec) || sec < 0) return 'unknown';
  if (sec < 60) return sec.toFixed(1) + 's';
  const min = sec / 60;
  if (min < 60) return min.toFixed(1) + 'm';
  const hr = min / 60;
  if (hr < 48) return hr.toFixed(2) + 'h';
  const day = hr / 24;
  return day.toFixed(2) + 'd';
}

function expectedAttemptsApprox(k) {
  if (k <= 20) return Math.pow(32, k);
  return null;
}

function updatePreviewAndDifficulty() {
  const pre = norm($('prefix').value);
  const suf = norm($('suffix').value);

  $('prevPre').textContent = pre;
  $('prevSuf').textContent = suf;

  const k = pre.length + suf.length;
  if (k <= 0) {
    $('difficulty').classList.add('hidden');
    return;
  }

  $('difficulty').classList.remove('hidden');

  let text = '';
  let icon = '';
  if (k <= 2) {
    text = 'Very Easy · few seconds';
    icon = '⚡';
  } else if (k <= 4) {
    text = 'Easy · minutes';
    icon = '🕐';
  } else if (k <= 6) {
    text = 'Moderate · could take hours';
    icon = '⏰';
  } else if (k <= 8) {
    text = 'Hard · could take days';
    icon = '⚠️';
  } else {
    text = 'Very Hard · could take weeks';
    icon = '🔴';
  }

  const attempts = expectedAttemptsApprox(k);
  if (attempts && attempts < 1e9) {
    text += ` (~${formatNumberShort(attempts)} tries)`;
  }

  $('diffIcon').textContent = icon;
  $('diffText').textContent = text;
}

// Word picker state
let allWords = [];
let selectedWords = [];
let targetWordCount = 12;
let wordlistState = 'loading'; // 'loading' | 'ready' | 'error'

let lastDuplicateWord = null;
let lastDuplicateAt = 0;

let lastWordCandidatesState = 'idle'; // 'idle' | 'loading' | 'ready' | 'error'
let lastWordCandidates = [];
let lastWordCandidatesKey = '';

function getWordGridBaseList(filter) {
  if (selectedWords.length === targetWordCount - 1) {
    if (lastWordCandidatesState === 'ready' && lastWordCandidates.length) {
      const q = (filter || '').trim().toLowerCase();
      return q ? lastWordCandidates.filter((w) => w.includes(q)) : lastWordCandidates;
    }
    return null;
  }

  const q = (filter || '').trim().toLowerCase();
  return q ? allWords.filter((w) => w.includes(q)) : allWords;
}

async function ensureLastWordCandidates() {
  if (wordlistState !== 'ready') return;
  if (!Array.isArray(allWords) || allWords.length !== 2048) return;
  if (selectedWords.length !== targetWordCount - 1) return;
  if (targetWordCount !== 12 && targetWordCount !== 24) return;

  const key = `${targetWordCount}:${selectedWords.join(' ')}`;
  if (lastWordCandidatesState === 'ready' && lastWordCandidatesKey === key) return;
  if (lastWordCandidatesState === 'loading' && lastWordCandidatesKey === key) return;

  lastWordCandidatesKey = key;
  lastWordCandidatesState = 'loading';
  lastWordCandidates = [];
  renderWordGrid($('wordSearch').value);

  const worker = createMinerWorker();
  let result;
  try {
    result = await new Promise((resolve, reject) => {
    const timeout = window.setTimeout(() => reject(new Error('Timeout computing checksum candidates')), 8000);
    worker.onmessage = (ev) => {
      const msg = ev.data;
      if (msg?.type === 'checksumCandidates') {
        window.clearTimeout(timeout);
        resolve(msg.candidates || []);
      } else if (msg?.type === 'error') {
        window.clearTimeout(timeout);
        reject(new Error(msg.error || 'Worker error'));
      }
    };
    worker.onerror = () => {
      window.clearTimeout(timeout);
      reject(new Error('Worker error'));
    };
    worker.postMessage({ type: 'checksumCandidates', prefixWords: selectedWords, wordCount: targetWordCount, wordlist: allWords });
    });
  } catch {
    // Only apply if selection hasn't changed.
    if (lastWordCandidatesKey === key) {
      lastWordCandidatesState = 'error';
      lastWordCandidates = [];
      renderWordGrid($('wordSearch').value);
    }
    try {
      worker.terminate();
    } catch {
      // ignore
    }
    return;
  }

  try {
    worker.terminate();
  } catch {
    // ignore
  }

  // Only apply if selection hasn't changed.
  if (lastWordCandidatesKey !== key) return;
  lastWordCandidatesState = 'ready';
  lastWordCandidates = Array.from(new Set(result || [])).sort();
  renderWordGrid($('wordSearch').value);
}

function renderSelectedWords() {
  const container = $('selectedWords');
  container.replaceChildren();

  if (selectedWords.length === 0) {
    container.className = 'word-selected empty';
    return;
  }

  container.className = 'word-selected';

  selectedWords.forEach((word, idx) => {
    const chip = document.createElement('div');
    chip.className = 'word-chip';

    const left = document.createElement('span');
    left.textContent = `${idx + 1}. ${word}`;

    const x = document.createElement('span');
    x.className = 'x';
    x.textContent = '×';

    chip.appendChild(left);
    chip.appendChild(x);

    chip.onclick = () => {
      selectedWords.splice(idx, 1);
      lastDuplicateWord = null;
      lastDuplicateAt = 0;
      lastWordCandidatesState = 'idle';
      lastWordCandidates = [];
      lastWordCandidatesKey = '';
      renderSelectedWords();
      updateWordCount();
      renderWordGrid($('wordSearch').value);
      ensureLastWordCandidates();
    };

    container.appendChild(chip);
  });
}

function updateWordCount() {
  const el = $('wordCount');
  el.textContent = `${selectedWords.length} / ${targetWordCount} words selected`;
  el.className = selectedWords.length === targetWordCount ? 'word-count complete' : 'word-count';
  $('btnDeriveAddress').disabled = selectedWords.length !== targetWordCount;
}

function renderWordGrid(filter) {
  const grid = $('wordGrid');
  grid.replaceChildren();

  if (wordlistState === 'loading') {
    const div = document.createElement('div');
    div.style.color = 'rgba(255,255,255,0.55)';
    div.style.fontSize = '12px';
    div.style.padding = '6px';
    div.textContent = 'Loading wordlist from inscription…';
    grid.appendChild(div);
    return;
  }

  if (wordlistState === 'error') {
    const div = document.createElement('div');
    div.style.color = 'rgba(255,255,255,0.55)';
    div.style.fontSize = '12px';
    div.style.padding = '6px';
    div.textContent = 'Wordlist failed to load.';
    grid.appendChild(div);
    return;
  }

  if (!allWords.length) return;

  // If the user has picked the first 11/23 words, only show checksum-valid last words.
  if (selectedWords.length === targetWordCount - 1) {
    if (lastWordCandidatesState === 'loading') {
      const div = document.createElement('div');
      div.style.color = 'rgba(255,255,255,0.55)';
      div.style.fontSize = '12px';
      div.style.padding = '6px';
      div.textContent = 'Computing valid last words (checksum)…';
      grid.appendChild(div);
      return;
    }
    if (lastWordCandidatesState === 'error') {
      const div = document.createElement('div');
      div.style.color = 'rgba(255,255,255,0.55)';
      div.style.fontSize = '12px';
      div.style.padding = '6px';
      div.textContent = 'Could not compute checksum-valid last words.';
      grid.appendChild(div);
      return;
    }
  }

  const filtered = getWordGridBaseList(filter);
  if (!filtered) return;

  const frag = document.createDocumentFragment();
  filtered.forEach((word) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'word-btn';
    btn.textContent = word;
    btn.onclick = () => {
      if (selectedWords.length >= targetWordCount) {
        show(`⚠️ You already have ${targetWordCount} words selected.`, { mode: 'status' });
        return;
      }
      if (selectedWords.includes(word)) {
        const now = performance.now();
        if (lastDuplicateWord === word && now - lastDuplicateAt < 1200) {
          // Allow duplicates (BIP39 permits repeated words), but require a
          // deliberate second tap to avoid accidental double-taps.
          lastDuplicateWord = null;
          lastDuplicateAt = 0;
        } else {
          lastDuplicateWord = word;
          lastDuplicateAt = now;
          show('⚠️ Duplicate word. Tap again to add anyway.', { mode: 'status' });
          return;
        }
      } else {
        lastDuplicateWord = null;
        lastDuplicateAt = 0;
      }
      selectedWords.push(word);
      renderSelectedWords();
      updateWordCount();
      renderWordGrid($('wordSearch').value);
      ensureLastWordCandidates();
    };
    frag.appendChild(btn);
  });
  grid.appendChild(frag);
}

async function initWordPicker() {
  wordlistState = 'loading';
  allWords = [];
  renderWordGrid('');
  renderSelectedWords();
  updateWordCount();

  try {
    allWords = await getBip39Wordlist();
    wordlistState = 'ready';
  } catch (e) {
    wordlistState = 'error';
    show('❌ ' + String(e?.message || e), { mode: 'status' });
  }

  renderWordGrid($('wordSearch').value);
  ensureLastWordCandidates();
}

async function deriveAddressFromPickedWords() {
  if (selectedWords.length !== targetWordCount) {
    show(`⚠️ Need exactly ${targetWordCount} words.`, { mode: 'status' });
    hideStatusSoon();
    return;
  }

  // Safety: duplicates are allowed in BIP39, but a phrase where every word is
  // identical is dangerously guessable and almost certainly not what the user
  // intended.
  if (new Set(selectedWords).size === 1) {
    show('⚠️ Please use at least 2 different words.', { mode: 'status' });
    hideStatusSoon();
    return;
  }

  try {
    hideResult();
    $('btnDeriveAddress').disabled = true;
    show('Deriving address…', { mode: 'status' });

    if (!Array.isArray(allWords) || allWords.length !== 2048) {
      throw new Error('BIP39 wordlist is not loaded yet.');
    }

    const mnemonic = selectedWords.join(' ');
    const worker = createMinerWorker();
    activeDeriveWorker = worker;
    updateStatusActions();

    worker.onmessage = (ev) => {
      const msg = ev.data;
      if (msg?.type === 'derived') {
        showResult({
          address: msg.address,
          secret: mnemonic,
          secretLabel: `Seed phrase (${targetWordCount} words)`,
        });
        setResultNote('✓ Derived');
        clearResultNoteSoon();
        $('btnDeriveAddress').disabled = false;
        activeDeriveWorker = null;
        updateStatusActions();
        worker.terminate();
      } else if (msg?.type === 'error') {
        const err = String(msg.error || 'Unknown error');
        if (err.includes('BIP39 checksum mismatch')) {
          // Guide the user into picking a valid checksum last word.
          selectedWords = selectedWords.slice(0, targetWordCount - 1);
          lastWordCandidatesState = 'idle';
          lastWordCandidates = [];
          lastWordCandidatesKey = '';
          renderSelectedWords();
          updateWordCount();
          show('⚠️ Checksum mismatch — pick a valid last word.', { mode: 'status' });
          renderWordGrid($('wordSearch').value);
          ensureLastWordCandidates();
        } else {
          show('❌ Error: ' + err, { mode: 'status' });
        }
        $('btnDeriveAddress').disabled = false;
        activeDeriveWorker = null;
        updateStatusActions();
        worker.terminate();
      }
    };

    worker.onerror = () => {
      show('❌ Error: worker failed', { mode: 'status' });
      $('btnDeriveAddress').disabled = false;
      activeDeriveWorker = null;
      updateStatusActions();
      worker.terminate();
    };

    worker.postMessage({ type: 'derive', mnemonic, wordlist: allWords });
  } catch (e) {
    show('❌ ' + String(e?.message || e), { mode: 'status' });
    $('btnDeriveAddress').disabled = false;
  }
}

function stopCurrentRun() {
  if (!currentRun) return;
  for (const w of currentRun.workers) w.terminate();
  currentRun = null;
  updateStatusActions();
}

function cancelAllWorkAndHideStatus() {
  if (activeDeriveWorker) {
    try {
      activeDeriveWorker.terminate();
    } finally {
      activeDeriveWorker = null;
    }
  }

  stopCurrentRun();

  $('statusCard').classList.add('hidden');
  $('statusBackdrop').classList.add('hidden');

  // Reset primary action buttons to a sane state.
  $('btnGenerate').disabled = false;
  $('btnGenerate').textContent = 'Start Generation';

  setStatusHeader({ title: 'Status', spinner: false });
  clearResultFields();
  setModalMode('status');

  updateWordCount();
}

function setModeControls() {
  const kind = String($('outputKind').value || 'priv');
  const showSeedLen = kind === 'mnemonic' || kind === 'pickWords';
  $('seedLenWrap').classList.toggle('hidden', !showSeedLen);
  $('wordPickerWrap').classList.toggle('hidden', kind !== 'pickWords');
  $('btnGenerate').classList.toggle('hidden', kind === 'pickWords');

  const isPickWords = kind === 'pickWords';

  const charsetStep = $('patternCharsetStep');
  if (charsetStep) charsetStep.classList.toggle('hidden', isPickWords);

  // Hide prefix/suffix controls in Pick Words mode to avoid implying vanity
  // matching is possible with a user-chosen mnemonic.
  const prefixWrap = $('prefix')?.closest('.input-wrap');
  const suffixWrap = $('suffix')?.closest('.input-wrap');
  if (prefixWrap) prefixWrap.classList.toggle('hidden', isPickWords);
  if (suffixWrap) suffixWrap.classList.toggle('hidden', isPickWords);

  $('prefix').disabled = isPickWords;
  $('suffix').disabled = isPickWords;

  // Prefix/suffix matching doesn't apply to user-picked seeds; hide the
  // difficulty widget so it doesn't imply vanity search still works.
  if (isPickWords) {
    $('difficulty').classList.add('hidden');
    $('prevPre').textContent = '';
    $('prevSuf').textContent = '';
  } else {
    updatePreviewAndDifficulty();
  }

  if (kind === 'pickWords') {
    targetWordCount = Number($('seedLen').value || 12);
    updateWordCount();
  }
}

$('prefix').addEventListener('input', updatePreviewAndDifficulty);
$('suffix').addEventListener('input', updatePreviewAndDifficulty);

$('outputKind').addEventListener('change', () => {
  setModeControls();
});

$('seedLen').addEventListener('change', () => {
  if (String($('outputKind').value) === 'pickWords') {
    targetWordCount = Number($('seedLen').value || 12);
    updateWordCount();
  }
});

$('wordSearch').addEventListener('input', (e) => {
  renderWordGrid(e.target.value);
});

$('btnClearWords').addEventListener('click', () => {
  selectedWords = [];
    lastDuplicateWord = null;
    lastDuplicateAt = 0;
    lastWordCandidatesState = 'idle';
    lastWordCandidates = [];
    lastWordCandidatesKey = '';
  renderSelectedWords();
  updateWordCount();
    renderWordGrid($('wordSearch').value);
});

$('btnDeriveAddress').addEventListener('click', deriveAddressFromPickedWords);

$('closeStatus').addEventListener('click', () => {
  // If work is running, treat close as cancel so the user can always stop.
  if (currentRun || activeDeriveWorker) {
    cancelAllWorkAndHideStatus();
    return;
  }
  $('statusCard').classList.add('hidden');
  $('statusBackdrop').classList.add('hidden');
});

$('btnCancel').addEventListener('click', () => {
  cancelAllWorkAndHideStatus();
});

$('copyAddr').addEventListener('click', () => copyToClipboard('Address', $('addr').textContent));
$('toggleAddrQr')?.addEventListener('click', () => {
  const addr = String($('addr')?.textContent || '').trim();
  if (!addr) return;
  setResultNote('');
  setAddressQrVisible(!isAddrQrVisible);
});
$('toggleSecretQr')?.addEventListener('click', () => {
  isSecretQrPanelVisible = !isSecretQrPanelVisible;
  const panel = $('secretQrPanel');
  const wrap = $('secretQrWrap');
  const holder = $('secretQr');
  const btn = $('toggleSecretQr');
  const pass = $('secretQrPass');
  const scanWrap = $('secretQrScanWrap');
  const video = $('secretQrVideo');
  const scanBtn = $('btnSecretQrScan');
  const genBtn = $('btnSecretQr');

  if (panel) panel.classList.toggle('hidden', !isSecretQrPanelVisible);
  if (btn) btn.textContent = isSecretQrPanelVisible ? 'Hide QR' : 'QR';

  if (!isSecretQrPanelVisible) {
    stopSecretQrScan();
    if (scanWrap) scanWrap.classList.add('hidden');
    if (video) video.srcObject = null;
    if (scanBtn) scanBtn.textContent = 'Scan';
    if (wrap) wrap.classList.add('hidden');
    if (holder) holder.replaceChildren();
    if (pass) pass.value = '';
    return;
  }

  if (wrap) wrap.classList.add('hidden');
  if (holder) holder.replaceChildren();
  if (genBtn) genBtn.disabled = !currentSecret;
  if (pass) {
    pass.value = '';
    pass.focus();
  }
});
$('btnSecretQr')?.addEventListener('click', () => {
  if (!currentSecret) return;
  generateSecretEncryptedQr();
});
$('btnSecretQrScan')?.addEventListener('click', () => {
  toggleSecretQrScan();
});
$('btnSecretQrDecrypt')?.addEventListener('click', () => {
  decryptSecretEncryptedText();
});
$('toggleSecret').addEventListener('click', () => {
  if (!currentSecret) return;
  setSecretRevealState(!isSecretRevealed);
});

$('copySec').addEventListener('click', () => {
  if (!isSecretRevealed) return;
  copyToClipboard(currentSecretLabel || 'Secret', currentSecret || '');
});

// Wipe secrets when user leaves/hides the page.
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'hidden') wipeSensitiveData();
});
window.addEventListener('pagehide', () => wipeSensitiveData());
window.addEventListener('beforeunload', () => wipeSensitiveData());

$('btnGenerate').addEventListener('click', async () => {
  try {
    stopCurrentRun();
    hideResult();

    const outputKind = String($('outputKind').value || 'priv');
    if (outputKind === 'pickWords') return;

    const prefix = norm($('prefix').value);
    const suffix = norm($('suffix').value);

    if (!prefix && !suffix) {
      show('⚠️ Enter a prefix or suffix first', { mode: 'status' });
      hideStatusSoon();
      return;
    }

    if (prefix) validatePattern(prefix);
    if (suffix) validatePattern(suffix);

    const wordCount = Number($('seedLen').value || 12);
    const wordlist = outputKind === 'mnemonic' ? await getBip39Wordlist() : null;

    $('btnGenerate').disabled = true;
    $('btnGenerate').textContent = 'Generating…';

    setStatusHeader({ title: 'Working…', spinner: true });

    const runId = Math.random().toString(16).slice(2);
    const startedAt = performance.now();
    let totalAttempts = 0;

    const k = prefix.length + suffix.length;
    const expected = expectedAttemptsApprox(k);

    const workerCount =
      outputKind === 'mnemonic'
        ? 1
        : Math.max(1, Math.min(4, (navigator.hardwareConcurrency || 2) - 1 || 1));

    const workers = [];
    currentRun = { runId, startedAt, workers, outputKind };
    updateStatusActions();

    const renderProgress = () => {
      const elapsedSec = (performance.now() - startedAt) / 1000;
      const rate = totalAttempts / Math.max(elapsedSec, 0.001);
      const etaSec = expected ? expected / Math.max(rate, 0.001) : null;

      const lines = [];
      lines.push('Searching…');
      lines.push('');
      lines.push(`Attempts: ${formatNumberShort(totalAttempts)}`);
      lines.push(`Rate: ~${formatNumberShort(rate)}/${outputKind === 'mnemonic' ? 'sec (mnemonics)' : 'sec (keys)'}`);
      lines.push(`Time: ${elapsedSec.toFixed(1)}s`);
      if (k > 0) {
        lines.push(`Estimated: ${etaSec ? formatDuration(etaSec) : `~(32^${k} / rate)`}`);
      }
      show(lines.join('\n'), { mode: 'status' });
    };

    $('statusCard').classList.remove('hidden');
    show('Starting…', { mode: 'status' });

    for (let i = 0; i < workerCount; i++) {
      const w = createMinerWorker();

      w.onmessage = (ev) => {
        const msg = ev.data;
        if (!currentRun || msg?.runId !== currentRun.runId) return;

        if (msg.type === 'progress') {
          totalAttempts += msg.attempts;
          renderProgress();
        } else if (msg.type === 'found') {
          totalAttempts += msg.attempts || 0;
          stopCurrentRun();
          renderProgress();
          showResult({ address: msg.address, secret: msg.secret, secretLabel: msg.secretLabel });
          setResultNote(`Found in ${formatNumberShort(totalAttempts)} attempts`);
          $('btnGenerate').disabled = false;
          $('btnGenerate').textContent = 'Generate Again';
        } else if (msg.type === 'error') {
          stopCurrentRun();
          show('❌ Error: ' + msg.error, { mode: 'status' });
          $('btnGenerate').disabled = false;
          $('btnGenerate').textContent = 'Try Again';
        }
      };

      w.onerror = () => {
        if (!currentRun) return;
        stopCurrentRun();
        show('❌ Error: worker failed.', { mode: 'status' });
        $('btnGenerate').disabled = false;
        $('btnGenerate').textContent = 'Try Again';
      };

      workers.push(w);
      w.postMessage({ runId, prefix, suffix, outputKind, wordCount, wordlist });
    }
  } catch (e) {
    stopCurrentRun();
    show('❌ ' + String(e?.message || e), { mode: 'status' });
    $('btnGenerate').disabled = false;
    $('btnGenerate').textContent = 'Try Again';
  }
});

// If opened from a QR deep-link containing an encrypted payload, auto-fill the decrypt UI.
tryImportCiphertextFromUrl();

// Init
setModeControls();
void initWordPicker();
updatePreviewAndDifficulty();
