// SecurePass Studio
// - Cryptographically secure password generator
// - Live strength check (zxcvbn): score, entropy, crack time, feedback
// - Optional breach check via HIBP k‑Anonymity (privacy-preserving)

const els = {
  pwd: document.getElementById('password-input'),
  btnGen: document.getElementById('btn-generate'),
  btnCopy: document.getElementById('btn-copy'),
  btnToggle: document.getElementById('btn-toggle'),
  length: document.getElementById('length'),
  lengthVal: document.getElementById('length-val'),
  optLower: document.getElementById('opt-lower'),
  optUpper: document.getElementById('opt-upper'),
  optDigits: document.getElementById('opt-digits'),
  optSymbols: document.getElementById('opt-symbols'),
  optAmbig: document.getElementById('opt-ambiguous'),
  bar: document.getElementById('strength-bar'),
  scoreLabel: document.getElementById('score-label'),
  entropy: document.getElementById('entropy'),
  crackTime: document.getElementById('crack-time'),
  feedback: document.getElementById('feedback'),
  optHIBP: document.getElementById('opt-hibp'),
  breachStatus: document.getElementById('breach-status'),
};

const CHARSETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: `!@#$%^&*()_+-=[]{};:'",.<>/?\\|~\``,
};
const AMBIGUOUS = new Set('0Ool1I|`\'"{}[]()/\\;:,.<>' .split('')); // typical confusing glyphs

function buildPool(opts) {
  let pool = '';
  if (opts.lower) pool += CHARSETS.lower;
  if (opts.upper) pool += CHARSETS.upper;
  if (opts.digits) pool += CHARSETS.digits;
  if (opts.symbols) pool += CHARSETS.symbols;
  if (opts.excludeAmbiguous) {
    pool = [...pool].filter(ch => !AMBIGUOUS.has(ch)).join('');
  }
  return pool;
}

function secureRandomInt(maxExclusive) {
  if (maxExclusive <= 0) throw new Error('maxExclusive must be > 0');
  const maxUint = 0xFFFFFFFF;
  const limit = Math.floor((maxUint + 1) / maxExclusive) * maxExclusive;
  const buf = new Uint32Array(1);
  while (true) {
    crypto.getRandomValues(buf);
    const x = buf[0];
    if (x < limit) return x % maxExclusive;
  }
}

function secureSample(array) {
  return array[secureRandomInt(array.length)];
}

function secureShuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function generatePassword(len, opts) {
  const groups = [];
  if (opts.lower) groups.push([...CHARSETS.lower]);
  if (opts.upper) groups.push([...CHARSETS.upper]);
  if (opts.digits) groups.push([...CHARSETS.digits]);
  if (opts.symbols) groups.push([...CHARSETS.symbols]);

  // Apply ambiguous filter inside groups too
  const filteredGroups = opts.excludeAmbiguous
    ? groups.map(g => g.filter(ch => !AMBIGUOUS.has(ch)))
    : groups;

  // Build unified pool
  const pool = [...new Set(filteredGroups.flat())];
  if (pool.length === 0) throw new Error('Select at least one character set');

  // Ensure at least one from each selected group
  const result = [];
  filteredGroups.forEach(g => {
    if (g.length > 0) result.push(secureSample(g));
  });

  // Fill the rest from the pool
  while (result.length < len) {
    result.push(pool[secureRandomInt(pool.length)]);
  }

  // Shuffle to avoid predictable placement of required characters
  return secureShuffle(result).join('');
}

function fmtBits(bits) {
  return bits < 1000 ? `${bits.toFixed(1)} bits` : `${Math.round(bits)} bits`;
}

function scoreLabel(score) {
  return ['Very weak','Weak','Fair','Strong','Very strong'][score] || '—';
}

function updateStrengthUI(pass) {
  if (!pass) {
    els.bar.style.width = '0%';
    els.bar.className = 'bar score-0';
    els.scoreLabel.textContent = '—';
    els.entropy.textContent = '—';
    els.crackTime.textContent = '—';
    els.feedback.innerHTML = '';
    setBreachStatus('—', null);
    return;
  }
  const res = window.zxcvbn ? window.zxcvbn(pass) : null;

  const score = res ? res.score : 0;
  els.bar.style.width = `${(score + 1) * 20}%`;
  els.bar.className = `bar score-${score}`;
  els.scoreLabel.textContent = scoreLabel(score);

  if (res) {
    const bits = Math.log2(res.guesses);
    els.entropy.textContent = fmtBits(bits);
    els.crackTime.textContent = res.crack_times_display.offline_slow_hashing_1e4_per_second;
    const suggestions = (res.feedback.suggestions || []);
    const warning = res.feedback.warning ? [res.feedback.warning] : [];
    const items = [...warning, ...suggestions];
    els.feedback.innerHTML = items.length
      ? items.map(s => `<div class="suggestion">• ${escapeHtml(s)}</div>`).join('')
      : '<span class="muted">Looks good. Consider using a password manager and making it even longer.</span>';
  } else {
    els.entropy.textContent = '—';
    els.crackTime.textContent = '—';
    els.feedback.innerHTML = '';
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}

function copyToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  // Fallback
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  try { document.execCommand('copy'); } finally { document.body.removeChild(ta); }
  return Promise.resolve();
}

function setBreachStatus(msg, statusClass) {
  els.breachStatus.className = `breach-status ${statusClass || ''}`;
  els.breachStatus.textContent = msg;
}

function debounce(fn, ms) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

async function sha1Hex(str) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest('SHA-1', enc.encode(str));
  const view = new DataView(buf);
  let hex = '';
  for (let i = 0; i < view.byteLength; i++) {
    const h = view.getUint8(i).toString(16).padStart(2, '0');
    hex += h;
  }
  return hex.toUpperCase();
}

async function checkHIBP(password) {
  if (!els.optHIBP.checked || !password || password.length < 8) {
    setBreachStatus(password ? 'Breach check skipped' : '—', null);
    return;
  }
  try {
    setBreachStatus('Checking breaches…', 'breach-spin');
    const hash = await sha1Hex(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' }
    });
    const text = await res.text();
    const lines = text.trim().split('\n');
    let count = 0;
    for (const line of lines) {
      const [suf, c] = line.split(':');
      if (suf === suffix) {
        count = parseInt(c, 10) || 0;
        break;
      }
    }
    if (count > 0) {
      setBreachStatus(`Compromised in ${count.toLocaleString()} breaches — do NOT use.`, 'breach-bad');
    } else {
      setBreachStatus('Not found in known breaches (good sign).', 'breach-ok');
    }
  } catch (e) {
    setBreachStatus('Breach check unavailable (offline or blocked).', 'breach-warn');
    console.error(e);
  }
}

const debouncedHIBP = debounce(checkHIBP, 450);

// Events
els.length.addEventListener('input', () => {
  els.lengthVal.textContent = els.length.value;
});

function getOpts() {
  return {
    lower: els.optLower.checked,
    upper: els.optUpper.checked,
    digits: els.optDigits.checked,
    symbols: els.optSymbols.checked,
    excludeAmbiguous: els.optAmbig.checked,
  };
}

els.btnGen.addEventListener('click', () => {
  try {
    const len = parseInt(els.length.value, 10);
    const opts = getOpts();
    const pwd = generatePassword(len, opts);
    els.pwd.value = pwd;
    // If input type is password (hidden), briefly show for visual confirmation
    updateStrengthUI(pwd);
    debouncedHIBP(pwd);
  } catch (e) {
    alert(e.message || String(e));
  }
});

els.btnCopy.addEventListener('click', async () => {
  const val = els.pwd.value || '';
  if (!val) return;
  await copyToClipboard(val);
  const old = els.btnCopy.textContent;
  els.btnCopy.textContent = 'Copied ✔';
  setTimeout(() => { els.btnCopy.textContent = old; }, 900);
});

els.btnToggle.addEventListener('click', () => {
  const isPw = els.pwd.type === 'password';
  els.pwd.type = isPw ? 'text' : 'password';
  els.btnToggle.textContent = isPw ? 'Hide' : 'Show';
});

els.pwd.addEventListener('input', () => {
  const val = els.pwd.value || '';
  updateStrengthUI(val);
  debouncedHIBP(val);
});

// Initialize defaults
(function init(){
  els.lengthVal.textContent = els.length.value;
  updateStrengthUI('');
})();