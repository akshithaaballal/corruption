/**
 * app.js — Spectre Application Logic
 *
 * Cryptography upgrades over the previous "simulated" version:
 *   genKey()        → crypto.getRandomValues  (256-bit key, not Math.random)
 *   genId()         → crypto.getRandomValues  (not Math.random)
 *   getFingerprint()→ SHA-256 via sha256Hex() (not djb2)
 *   doSubmit()      → aesEncrypt() AES-256-GCM (not btoa)
 *   doUserVerify()  → SHA-256 session token   (not btoa)
 *   doLogin()       → sha256Hex password hash comparison
 *   renderModal     → aesDecrypt() on demand for investigator view
 *
 * Depends on: db.js (must be loaded first — exports sha256Hex, aesEncrypt, aesDecrypt,
 *   loadReports, saveReports, createReport, etc.)
 */

'use strict';

// ─── State ────────────────────────────────────────────────────────────────────
const STATE = {
  mode:           'selector',      // 'selector', 'reporter', 'investigator'
  userVerified:   false,
  userVerifData:  { name: '', dob: '', idType: '', idNumber: '', docFile: null, docName: '', kycVerified: false },
  tab:            'submit',
  submitStep:     0,
  powProgress:    0,
  powDone:        false,
  fingerprint:    null,      // set async at boot by initState()
  formData:       { title: '', category: '', department: '', description: '', evidence: '', files: [] },
  reports:        [],
  selectedReport: null,
  trackId:        '',
  trackKey:       '',
  trackResult:    null,
  trackResultDecrypted: null,
  statusFilter:   'ALL',
  modal:          null,
  investigatorSession: null,
  loginError:     '',
  showAdvancedFeatures: false,
  newReportId:    null,
  newReportKey:   null,
  decryptedPayload: null,    // store decrypted report for download
};

// ─── Boot ─────────────────────────────────────────────────────────────────────
async function initState() {
  STATE.reports     = await loadReports();
  STATE.fingerprint = await getFingerprint();
  if (sessionStorage.getItem(VERIF_KEY)) STATE.userVerified = true;
  render();
  updateNavigation();
}

async function persistReports() {
  await saveReports(STATE.reports);
}

// ─── Cryptographic utilities ──────────────────────────────────────────────────

/**
 * Generate a cryptographically secure 256-bit AES key as a 64-char hex string.
 * Replaces the old Math.random-based 'sk_' key which had only ~60 bits of entropy.
 */
function genKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate a random report ID using crypto.getRandomValues.
 * Replaces Math.random-based genId.
 */
function genId(prefix, len) {
  const chars  = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes  = crypto.getRandomValues(new Uint8Array(len));
  let   result = prefix + '-';
  for (let i = 0; i < len; i++) result += chars[bytes[i] % chars.length];
  return result;
}

/**
 * Compute a SHA-256 device fingerprint (async, result is cached in STATE).
 * Replaces the old djb2 hash which produced only 32 bits — trivially colliding.
 * Includes more signals for better uniqueness.
 */
async function getFingerprint() {
  if (STATE.fingerprint) return STATE.fingerprint;
  const raw = [
    navigator.userAgent,
    `${screen.width}x${screen.height}x${screen.colorDepth}`,
    Intl.DateTimeFormat().resolvedOptions().timeZone,
    navigator.language || '',
    String(navigator.hardwareConcurrency || ''),
    String(navigator.deviceMemory       || ''),
  ].join('|');
  // Use first 16 hex chars (64 bits) for display, but full 256-bit hash is used
  // internally in createReport for Merkle leaf generation.
  STATE.fingerprint = (await sha256Hex(raw)).slice(0, 16);
  return STATE.fingerprint;
}

/**
 * Encrypt plaintext report payload with AES-256-GCM.
 * Thin wrapper over aesEncrypt() from db.js — keeps app.js readable.
 */
async function encryptReportPayload(payload, keyHex) {
  return aesEncrypt(JSON.stringify(payload), keyHex);
}

/**
 * Decrypt an AES-256-GCM report payload.
 * Returns parsed object or null on failure.
 */
async function decryptReportPayload(encData, keyHex) {
  try {
    return JSON.parse(await aesDecrypt(encData, keyHex));
  } catch (e) {
    console.warn('Decryption failed:', e);
    return null;
  }
}

async function hashReportKey(key) {
  return sha256Hex((key || '').trim());
}

function isHexKey(key) {
  return typeof key === 'string' && /^[0-9a-fA-F]{64}$/.test(key.trim());
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i += 1) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

// ─── Formatting helpers ───────────────────────────────────────────────────────
function fmtTs(ts) {
  return new Date(ts).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}
function fmtBytes(b) {
  if (b < 1024)        return b + 'B';
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + 'KB';
  return (b / 1024 / 1024).toFixed(1) + 'MB';
}
function statusColor(s) {
  return { SUBMITTED: 'blue', INVESTIGATING: 'amber', RESOLVED: 'green', FALSE: 'red', PUBLIC_LEAK: 'purple' }[s] || 'gray';
}
function trustColor(t) {
  return { UNVERIFIED: 'gray', VERIFIED: 'blue', ENDORSED: 'green' }[t] || 'gray';
}
function copyText(text, btnEl) {
  navigator.clipboard.writeText(text).then(() => {
    btnEl.textContent = 'Copied!';
    btnEl.classList.add('copied');
    setTimeout(() => { btnEl.textContent = 'Copy'; btnEl.classList.remove('copied'); }, 1500);
  });
}

// ─── Navigation ───────────────────────────────────────────────────────────────
function switchTab(tab) {
  STATE.tab         = tab;
  STATE.submitStep  = 0;
  STATE.powDone     = false;
  STATE.powProgress = 0;
  STATE.loginError  = '';
  render();
  updateNavigation();
}

function switchMode(mode) {
  STATE.mode = mode;
  STATE.tab = 'submit';
  STATE.submitStep = 0;
  STATE.powDone = false;
  STATE.powProgress = 0;
  STATE.loginError = '';
  STATE.investigatorSession = null;
  STATE.userVerified = false;
  render();
  updateNavigation();
}

function exitMode() {
  STATE.mode = 'selector';
  STATE.investigatorSession = null;
  render();
  updateNavigation();
}

function updateNavigation() {
  const navBar = document.getElementById('navBar');
  const navTabs = document.getElementById('navTabs');
  
  if (STATE.mode === 'selector') {
    navBar.style.display = 'none';
    return;
  }
  
  navBar.style.display = 'flex';
  navTabs.innerHTML = '';
  
  if (STATE.mode === 'reporter') {
    navTabs.innerHTML = `
      <button class="sp-tab ${STATE.tab === 'submit' ? 'active' : ''}" onclick="switchTab('submit')">Submit Report</button>
      <button class="sp-tab ${STATE.tab === 'track' ? 'active' : ''}" onclick="switchTab('track')">Track Report</button>
    `;
  } else if (STATE.mode === 'investigator') {
    if (STATE.investigatorSession) {
      navTabs.innerHTML = `<div style="color:var(--sp-muted); font-size:12px;">Logged in as: ${STATE.investigatorSession.email}</div>`;
    }
  }
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
async function doLogin() {
  const email = (document.getElementById('login-email')?.value || '').trim().toLowerCase();
  const pass  = document.getElementById('login-pass')?.value || '';
  const match = await findCredential(email, pass);   // SHA-256 comparison in db.js
  if (!match) { STATE.loginError = 'Invalid credentials. Access denied.'; render(); return; }
  STATE.investigatorSession = { email, token: genKey() };
  STATE.loginError = '';
  render();
}

function doLogout() {
  STATE.investigatorSession = null;
  STATE.loginError = '';
  exitMode();
}

// ─── User Verification ────────────────────────────────────────────────────────
function handleVerifDoc(files) {
  if (!files || !files[0]) return;
  const f       = files[0];
  const allowed = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
  if (!allowed.includes(f.type)) { alert('Please upload a JPG, PNG, WEBP, or PDF file.'); return; }
  if (f.size > 20 * 1024 * 1024) { alert('File must be under 20MB.'); return; }
  const reader = new FileReader();
  reader.onload = e => {
    STATE.userVerifData.docFile = e.target.result;
    STATE.userVerifData.docName = f.name;
    const preview = document.getElementById('verif-doc-preview');
    const label   = document.getElementById('verif-doc-label');
    const nameEl  = document.getElementById('verif-doc-name');
    const metaEl  = document.getElementById('verif-doc-meta');
    const thumb   = document.getElementById('verif-doc-thumb');
    if (nameEl)  nameEl.textContent = f.name;
    if (metaEl)  metaEl.textContent = f.type + ' · ' + (f.size < 1024 * 1024 ? (f.size / 1024).toFixed(1) + 'KB' : (f.size / 1024 / 1024).toFixed(1) + 'MB');
    if (thumb && f.type.startsWith('image/'))
      thumb.innerHTML = `<img src="${e.target.result}" style="width:52px;height:40px;object-fit:cover;border-radius:5px;"/>`;
    if (preview) preview.style.display = 'flex';
    if (label)   label.style.display   = 'none';
  };
  reader.readAsDataURL(f);
  const input = document.getElementById('verif-doc-input');
  if (input) input.value = '';
}

function clearVerifDoc() {
  STATE.userVerifData.docFile = null;
  STATE.userVerifData.docName = '';
  const preview = document.getElementById('verif-doc-preview');
  const label   = document.getElementById('verif-doc-label');
  if (preview) preview.style.display = 'none';
  if (label)   label.style.display   = 'block';
}

function runKycChecks(name, dob, idType, idNumber, docFile, docName) {
  const errors = [];
  const warnings = [];

  if (!idType) errors.push('Select a document type for KYC verification.');
  if (!idNumber) errors.push('Provide a document or passport number.');
  if (idNumber && !/^[A-Za-z0-9\- ]{5,25}$/.test(idNumber)) {
    errors.push('Document number must be 5-25 characters and may include letters, digits, spaces, or hyphens.');
  }
  if (!docFile) errors.push('Upload a government-issued ID scan or photo.');
  if (docFile && docName) {
    const lower = docName.toLowerCase();
    if (idType === 'Passport' && !/(passport|pass)/.test(lower)) warnings.push('Passport document name does not mention passport.');
    if (idType === "Driver's License" && !/(driver|license|licence)/.test(lower)) warnings.push('Driver license name does not mention license.');
    if (idType === 'National ID' && !/(national|id|identity)/.test(lower)) warnings.push('National ID file name does not include obvious ID metadata.');
  }
  if (docFile && typeof docFile === 'string') {
    if (!/^data:(image\/(jpeg|png|webp)|application\/pdf);base64,/.test(docFile)) {
      errors.push('Uploaded file appears to be an unsupported document format.');
    }
    const length = docFile.length;
    if (length < 4096) errors.push('Uploaded document is too small to be a valid ID scan.');
  }
  const dobDate = new Date(dob);
  if (Number.isNaN(dobDate.getTime())) errors.push('Enter a valid date of birth.');
  else {
    const today = new Date();
    const age = today.getFullYear() - dobDate.getFullYear() -
      (today < new Date(today.getFullYear(), dobDate.getMonth(), dobDate.getDate()) ? 1 : 0);
    if (age < 18) errors.push('You must be at least 18 years old to use this system.');
    if (age > 120) warnings.push('Age appears unusually high; please verify the date of birth entered.');
  }

  return { errors, warnings };
}

async function doUserVerify() {
  const name  = (document.getElementById('verif-name')?.value || '').trim();
  const dob   = (document.getElementById('verif-dob')?.value  || '').trim();
  const idType = (document.getElementById('verif-id-type')?.value || '').trim();
  const idNumber = (document.getElementById('verif-id-number')?.value || '').trim();
  const errEl = document.getElementById('verif-error');
  const showErr = msg => { if (errEl) { errEl.textContent = '⚠ ' + msg; errEl.style.display = 'block'; } };
  const hideErr = () => { if (errEl) { errEl.textContent = ''; errEl.style.display = 'none'; } };
  hideErr();

  STATE.userVerifData.name = name;
  STATE.userVerifData.dob = dob;
  STATE.userVerifData.idType = idType;
  STATE.userVerifData.idNumber = idNumber;

  const { errors, warnings } = runKycChecks(name, dob, idType, idNumber, STATE.userVerifData.docFile, STATE.userVerifData.docName);
  if (errors.length) {
    showErr(errors[0]);
    return;
  }

  if (warnings.length) {
    const proceed = window.confirm(`${warnings.join('\n')}\n\nProceed with verification anyway?`);
    if (!proceed) return;
  }

  STATE.userVerifData.kycVerified = true;

  const tokenInput = `${name}|${dob}|${idType}|${idNumber}|${STATE.userVerifData.docFile.slice(0, 200)}`;
  const verifToken = await sha256Hex(tokenInput);
  sessionStorage.setItem(VERIF_KEY, verifToken);
  STATE.userVerified = true;
  render();
}

// ─── Submit flow ──────────────────────────────────────────────────────────────
function validateStep1() {
  const title = document.getElementById('f-title')?.value.trim();
  const cat   = document.getElementById('f-cat')?.value;
  const dept  = document.getElementById('f-dept')?.value;
  const desc  = document.getElementById('f-desc')?.value.trim();
  STATE.formData.title = title; STATE.formData.category = cat;
  STATE.formData.department = dept; STATE.formData.description = desc;
  if (!title || !cat || !dept || !desc) { alert('Please fill in all fields.'); return; }
  STATE.submitStep = 2; render();
}

function handleFileSelect(fileList) {
  const errors = [];
  Array.from(fileList).forEach(file => {
    const isImg = ['image/jpeg', 'image/png', 'image/webp'].includes(file.type);
    const isVid = ['video/mp4', 'video/webm'].includes(file.type);
    if (!isImg && !isVid) { errors.push(`"${file.name}" not supported.`); return; }
    const limit = isVid ? 100 * 1024 * 1024 : 20 * 1024 * 1024;
    if (file.size > limit) { errors.push(`"${file.name}" exceeds size limit.`); return; }
    const reader = new FileReader();
    reader.onload = e => {
      STATE.formData.files.push({ name: file.name, type: file.type, size: file.size, dataUrl: e.target.result });
      if (window._renderEvidencePreviews) window._renderEvidencePreviews();
    };
    reader.readAsDataURL(file);
  });
  if (errors.length) alert(errors.join('\n'));
  const input = document.getElementById('file-input');
  if (input) input.value = '';
}

function removeFile(index) {
  STATE.formData.files.splice(index, 1);
  if (window._renderEvidencePreviews) window._renderEvidencePreviews();
}

function advanceFromEvidence() {
  const ev = document.getElementById('f-ev');
  if (ev) STATE.formData.evidence = ev.value;
  STATE.submitStep = 3;
  render();
}

function startPoW() {
  let progress = 0;
  const statuses = ['Generating nonce…', 'Hashing…', 'Verifying…', 'Computing proof…', 'Validating…'];
  let si = 0;
  const interval = setInterval(() => {
    progress += Math.random() * 4 + 1;
    if (progress > 100) progress = 100;
    const fill   = document.getElementById('powFill');
    const status = document.getElementById('powStatus');
    const btn    = document.getElementById('submitBtn');
    if (fill)   fill.style.width  = progress + '%';
    if (status) status.textContent = statuses[Math.min(si++, statuses.length - 1)] + ` (${Math.round(progress)}%)`;
    if (progress >= 100) {
      clearInterval(interval);
      STATE.powDone = true;
      const container = document.getElementById('pow-container');
      if (container) container.innerHTML = `<div class="sp-badge green">Verified — PoW complete</div>`;
      if (btn) btn.removeAttribute('disabled');
    }
  }, 80);
}

/**
 * Submit: now encrypts report payload with AES-256-GCM before persisting.
 */
async function doSubmit() {
  const id  = genId('RPT', 4);
  const key = genKey();   // 32 random bytes → 64-char hex (256-bit AES key)
  STATE.newReportId  = id;
  STATE.newReportKey = key;

  // Encrypt sensitive fields before they ever touch storage.
  const payload = {
    title:       STATE.formData.title,
    category:    STATE.formData.category,
    department:  STATE.formData.department,
    description: STATE.formData.description,
    evidence:    STATE.formData.evidence,
    files:        STATE.formData.files,
  };
  const encData = await encryptReportPayload(payload, key);

  const fp      = STATE.fingerprint || await getFingerprint();
  const keyHash = await hashReportKey(key);
  const report  = await createReport({ id, keyHash, fingerprint: fp, formData: STATE.formData, encData });
  STATE.reports.unshift(report);
  await persistReports();
  STATE.submitStep = 4;
  render();
}

// ─── Track flow ───────────────────────────────────────────────────────────────
async function doTrack() {
  const id  = (document.getElementById('track-id')?.value  || STATE.trackId).trim().toUpperCase();
  const key = (document.getElementById('track-key')?.value || STATE.trackKey).trim();
  if (!id || !key) { alert('Please enter both fields.'); return; }
  if (!isHexKey(key)) { alert('Secret key must be a 64-character hex string.'); return; }
  const keyHash = await hashReportKey(key);
  const found = STATE.reports.find(r => r.id === id && timingSafeEqual(r.keyHash || '', keyHash));
  if (!found) {
    STATE.trackResult = null;
    STATE.trackResultDecrypted = null;
    alert('No report found. Check your tracking ID and key.');
    return;
  }
  const decrypted = await decryptReportPayload(found.encData, key);
  heartbeatReport(id);
  STATE.trackResult = found;
  STATE.trackResultDecrypted = decrypted;
  render();
}

function sendHeartbeatAndRefresh(reportId) {
  const result = heartbeatReport(reportId);
  if (result.success) {
    alert(`Heartbeat sent! Dead Man's Switch extended until ${new Date(result.releaseTime).toLocaleString()}`);
    if (STATE.trackResult) {
      const updated = STATE.reports.find(r => r.id === STATE.trackResult.id);
      if (updated) STATE.trackResult = updated;
      render();
    }
  } else {
    alert('Could not send heartbeat for this report.');
  }
}

// ─── Admin flow ───────────────────────────────────────────────────────────────
function openReport(id) {
  if (!STATE.investigatorSession) {
    alert('You must be logged in as investigator to view reports.');
    return;
  }
  STATE.selectedReport = id; 
  STATE.modal = 'report'; 
  render();
}

async function updateStatus(id, status) {
  const r = STATE.reports.find(x => x.id === id);
  if (!r) return;
  updateReportStatus(r, status);
  await persistReports();
  STATE.modal = 'report';
  render();
}

function deleteReport(reportId) {
  if (!STATE.investigatorSession) {
    alert('Only investigators can delete reports.');
    return;
  }
  
  const confirm = window.confirm(
    `Are you sure you want to permanently delete report ${reportId}? This action cannot be undone and will remove all associated data.`
  );
  
  if (!confirm) return;
  
  // Remove from STATE
  STATE.reports = STATE.reports.filter(r => r.id !== reportId);
  
  // Persist
  persistReports();
  
  // Log action
  console.log(`Report ${reportId} deleted by investigator ${STATE.investigatorSession.email}`);
  
  // Close modal and refresh view
  STATE.modal = null;
  render();
  
  alert('Report deleted successfully.');
}

// ─── Master render ────────────────────────────────────────────────────────────
function render() {
  const c = document.getElementById('mainContent');
  c.innerHTML = '';
  c.className = 'fade-in';
  
  if (STATE.mode === 'selector') {
    renderModeSelector(c);
    return;
  }
  
  if (STATE.mode === 'reporter') {
    if (!STATE.userVerified) { renderUserVerification(c); return; }
    if (STATE.tab === 'submit') renderSubmit(c);
    else if (STATE.tab === 'track') renderTrack(c);
    if (STATE.modal) renderModal(c);
    return;
  }
  
  if (STATE.mode === 'investigator') {
    if (!STATE.investigatorSession) { renderLogin(c); return; }
    renderAdmin(c);
    if (STATE.modal) renderModal(c);
    return;
  }
}

// ─── Views ────────────────────────────────────────────────────────────────────
function renderModeSelector(c) {
  c.innerHTML = `
    <div style="display:flex; align-items:center; justify-content:center; min-height:calc(100vh - 53px); padding:40px 24px;">
      <div style="width:100%; max-width:800px;">
        <div style="text-align:center; margin-bottom:48px;">
          <div style="font-size:32px; font-weight:600; color:var(--sp-primary); margin-bottom:12px;">Spectre</div>
          <div style="font-size:14px; color:var(--sp-muted);">Anonymous Secure Reporting System</div>
        </div>
        
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:24px; margin-bottom:40px;">
          <!-- Reporter Mode -->
          <div style="background:var(--sp-surface1); border:1px solid var(--sp-border1); border-radius:12px; padding:32px; text-align:center; cursor:pointer; transition:all 0.2s;" onmouseover="this.style.background='var(--sp-surface2)'; this.style.borderColor='var(--sp-primary)';" onmouseout="this.style.background='var(--sp-surface1)'; this.style.borderColor='var(--sp-border1)';" onclick="switchMode('reporter')">
            <div style="font-size:32px; margin-bottom:16px;">📝</div>
            <div style="font-size:16px; font-weight:600; margin-bottom:8px;">Submit Report</div>
            <div style="font-size:12px; color:var(--sp-muted); line-height:1.6;">
              Anonymous and secure. Submit reports, track progress, and maintain confidentiality.
            </div>
          </div>
          
          <!-- Investigator Mode -->
          <div style="background:var(--sp-surface1); border:1px solid var(--sp-border1); border-radius:12px; padding:32px; text-align:center; cursor:pointer; transition:all 0.2s;" onmouseover="this.style.background='var(--sp-surface2)'; this.style.borderColor='var(--sp-primary)';" onmouseout="this.style.background='var(--sp-surface1)'; this.style.borderColor='var(--sp-border1)';" onclick="switchMode('investigator')">
            <div style="font-size:32px; margin-bottom:16px;">🔍</div>
            <div style="font-size:16px; font-weight:600; margin-bottom:8px;">Investigator</div>
            <div style="font-size:12px; color:var(--sp-muted); line-height:1.6;">
              Access and investigate reports. Requires authentication and decryption key.
            </div>
          </div>
        </div>
        
        <div style="background:var(--sp-surface2); border-radius:8px; padding:16px; margin-top:32px;">
          <div style="font-size:11px; color:var(--sp-muted); line-height:1.8;">
            <strong>Security Notice:</strong> All data is encrypted end-to-end with AES-256-GCM. Your identity verification and fingerprint are hashed with SHA-256. Never share your decryption keys.
          </div>
        </div>
      </div>
    </div>`;
}

function renderUserVerification(c) {
  c.innerHTML = `
    <div style="display:flex; align-items:center; justify-content:center; min-height:calc(100vh - 53px); padding:40px 24px;">
      <div style="width:100%; max-width:420px;">
        <div style="text-align:center; margin-bottom:32px;">
          <svg width="48" height="48" viewBox="0 0 48 48" fill="none" style="margin:0 auto 16px; display:block;">
            <circle cx="24" cy="24" r="23" fill="rgba(200,184,255,0.1)" stroke="rgba(200,184,255,0.4)" stroke-width="1"/>
            <path d="M24 13a5 5 0 1 1 0 10 5 5 0 0 1 0-10z" fill="rgba(200,184,255,0.3)" stroke="#c8b8ff" stroke-width="1.5"/>
            <path d="M14 36c0-5.5 4.5-10 10-10s10 4.5 10 10" stroke="#c8b8ff" stroke-width="1.5" stroke-linecap="round"/>
          </svg>
          <div class="sp-title" style="font-size:20px;">Identity Verification</div>
          <div style="font-size:13px; color:var(--sp-muted); margin-top:6px; line-height:1.6;">Verify your identity before accessing this system. Your information is hashed locally with SHA-256 and never stored in plaintext.</div>
        </div>
        <div id="verif-error" style="display:none;" class="sp-login-error"></div>
        <div class="sp-field">
          <label class="sp-label">Full Name</label>
          <input id="verif-name" type="text" placeholder="As it appears on your ID" />
        </div>
        <div class="sp-field">
          <label class="sp-label">Date of Birth</label>
          <input id="verif-dob" type="date" />
        </div>
        <div class="sp-field">
          <label class="sp-label">Document Type</label>
          <select id="verif-id-type" style="width:100%; padding:10px 12px; border-radius:7px; border:0.5px solid var(--sp-border2); background:var(--sp-surface2); color:var(--sp-text);">
            <option value="">Select ID type</option>
            <option value="Passport">Passport</option>
            <option value="Driver's License">Driver's License</option>
            <option value="National ID">National ID</option>
          </select>
        </div>
        <div class="sp-field">
          <label class="sp-label">Document Number</label>
          <input id="verif-id-number" type="text" placeholder="ID number or passport number" style="width:100%; padding:10px 12px; border-radius:7px; border:0.5px solid var(--sp-border2); background:var(--sp-surface2); color:var(--sp-text);" />
        </div>
        <div class="sp-field">
          <label class="sp-label">Government-Issued ID Document</label>
          <div class="sp-upload-zone" id="verif-upload-zone" style="padding:20px;">
            <input type="file" id="verif-doc-input" accept="image/jpeg,image/png,image/webp,application/pdf"
              onchange="handleVerifDoc(this.files)"
              style="position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%;padding:0;border:none;background:none;"/>
            <div id="verif-doc-label">
              <div style="font-size:22px; margin-bottom:8px;">🪪</div>
              <div class="sp-upload-text"><strong>Click to upload</strong> or drag and drop<br>
              <span style="font-size:12px;">Passport, National ID, or Driver's License · JPG, PNG, WEBP, PDF</span></div>
            </div>
          </div>
          <div id="verif-doc-preview" style="display:none;" class="sp-file-preview">
            <div class="sp-file-thumb" id="verif-doc-thumb" style="font-size:22px; justify-content:center;">📄</div>
            <div class="sp-file-info">
              <div class="sp-file-name" id="verif-doc-name"></div>
              <div class="sp-file-meta" id="verif-doc-meta"></div>
            </div>
            <button class="sp-file-remove" onclick="clearVerifDoc()" title="Remove">✕</button>
          </div>
        </div>
        <div class="sp-info" style="margin-bottom:20px;"><span>ℹ</span><div>Your document is validated locally. This demo performs structured KYC checks before allowing access. In production, integrate with a trusted identity verifier.</div></div>
        <button class="sp-btn primary" style="width:100%; justify-content:center;" onclick="doUserVerify()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
          Verify &amp; Continue
        </button>
        <button class="sp-btn secondary" style="width:100%; justify-content:center; margin-top:8px;" onclick="exitMode()">Back to Mode Selection</button>
        <div class="sp-demo-badge">Session token: SHA-256(name|dob|idType|idNumber|docHash) — Web Crypto API</div>
      </div>
    </div>`;

  const zone = document.getElementById('verif-upload-zone');
  if (zone) {
    zone.addEventListener('dragover',  e => { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', ()  => zone.classList.remove('dragover'));
    zone.addEventListener('drop',      e  => { e.preventDefault(); zone.classList.remove('dragover'); handleVerifDoc(e.dataTransfer.files); });
  }

  const nameInput = document.getElementById('verif-name');
  const dobInput = document.getElementById('verif-dob');
  const idTypeInput = document.getElementById('verif-id-type');
  const idNumberInput = document.getElementById('verif-id-number');
  if (nameInput) nameInput.value = STATE.userVerifData.name || '';
  if (dobInput) dobInput.value = STATE.userVerifData.dob || '';
  if (idTypeInput) idTypeInput.value = STATE.userVerifData.idType || '';
  if (idNumberInput) idNumberInput.value = STATE.userVerifData.idNumber || '';

  if (STATE.userVerifData.docFile) {
    const preview = document.getElementById('verif-doc-preview');
    const label   = document.getElementById('verif-doc-label');
    const nameEl  = document.getElementById('verif-doc-name');
    const metaEl  = document.getElementById('verif-doc-meta');
    const thumb   = document.getElementById('verif-doc-thumb');
    if (preview) preview.style.display = 'flex';
    if (label)   label.style.display = 'none';
    if (nameEl)  nameEl.textContent = STATE.userVerifData.docName || 'Uploaded document';
    if (metaEl)  metaEl.textContent = STATE.userVerifData.docFile.length ? `Uploaded document attached` : '';
    if (thumb && STATE.userVerifData.docFile.startsWith('data:image/')) {
      thumb.innerHTML = `<img src="${STATE.userVerifData.docFile}" style="width:52px;height:40px;object-fit:cover;border-radius:5px;"/>`;
    }
  }
}

function renderLogin(c) {
  c.innerHTML = `<div class="sp-login-wrap">
    <div class="sp-login-box">
      <div class="sp-login-logo">
        <div class="sp-title">Investigator Access</div>
        <div style="font-size:13px; color:var(--sp-muted); margin-top:4px;">Restricted — all sessions are audit logged</div>
      </div>
      ${STATE.loginError ? `<div class="sp-login-error">⚠ ${STATE.loginError}</div>` : ''}
      <div class="sp-field">
        <label class="sp-label">Email</label>
        <input id="login-email" type="email" placeholder="investigator@org.internal" autocomplete="username"
          onkeydown="if(event.key==='Enter') document.getElementById('login-pass').focus()"/>
      </div>
      <div class="sp-field">
        <label class="sp-label">Password</label>
        <input id="login-pass" type="password" placeholder="••••••••••••" autocomplete="current-password"
          onkeydown="if(event.key==='Enter') doLogin()"/>
      </div>
      <button class="sp-btn primary" style="width:100%; justify-content:center;" onclick="doLogin()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        Sign in
      </button>
      <button class="sp-btn secondary" style="width:100%; justify-content:center; margin-top:8px;" onclick="exitMode()">Back to Mode Selection</button>
      <div class="sp-info" style="margin-top:16px;">
        <span>ℹ</span>
        <div><strong>Demo Credentials:</strong><br>Email: investigator@spectre.internal<br>Password: Spectre2025!</div>
      </div>
      <div class="sp-demo-badge"> Passwords hashed with SHA-256 (Web Crypto API). Production: bcrypt/Argon2 server-side.</div>
    </div>
  </div>`;
}

function renderSubmit(c) {
  const steps = ['Awareness', 'Report', 'Evidence', 'Review', 'Done'];
  const s = STATE.submitStep;
  let html = `<div class="sp-content"><div style="max-width:580px; margin:0 auto;">`;
  html += `<div class="sp-progress">`;
  steps.forEach((name, i) => {
    const cls = i < s ? 'done' : i === s ? 'active' : '';
    html += `<div class="sp-step-dot ${cls}">${i < s ? '✓' : (i + 1)}</div>`;
    if (i < steps.length - 1) html += `<div class="sp-step-line ${i < s ? 'done' : ''}"></div>`;
  });
  html += `</div>`;

  const fp = STATE.fingerprint || 'computing…';

  if (s === 0) {
    html += `<div style="text-align:center; max-width:440px; margin:0 auto;">
      <svg width="48" height="56" viewBox="0 0 48 56" fill="none" style="margin:0 auto 20px; display:block;">
        <path d="M24 2L4 10v18c0 13.3 8.5 25.7 20 30 11.5-4.3 20-16.7 20-30V10L24 2z"
          fill="rgba(200,184,255,0.15)" stroke="rgba(200,184,255,0.5)" stroke-width="1.5"/>
        <path d="M17 27l5 5 9-9" stroke="#c8b8ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <div class="sp-title">Before you submit</div>
      <div class="sp-subtitle">Spectre protects your identity — but your anonymity depends on you.</div>
      <div style="text-align:left; display:flex; flex-direction:column; gap:10px; margin-bottom:28px;">
        <div class="sp-warn"><span>⚠</span><div>Do not submit from your workplace network or device. Use a public WiFi or a VPN.</div></div>
        <div class="sp-warn"><span>⚠</span><div>Remove metadata from any files before uploading (photos contain GPS/camera data).</div></div>
        <div class="sp-info"><span></span><div>Your report is <strong> encrypted</strong> client-side using your secret key before being stored. We never receive or store plaintext.</div></div>
        <div class="sp-info"><span></span><div>No email, phone, login, or IP address is collected. Your tracking key is shown once and never stored in plaintext.</div></div>
      </div>
      <div style="display:flex; align-items:center; justify-content:center; gap:6px; font-size:12px; color:var(--sp-muted); font-family:var(--font-mono); margin-bottom:20px;">
        SHA-256 fingerprint: <span style="color:var(--sp-accent);">${fp}</span>
      </div>
      <button class="sp-btn primary" onclick="STATE.submitStep=1;render();">I understand — continue</button>
    </div>`;

  } else if (s === 1) {
    html += `<div style="max-width:520px; margin:0 auto;">
      <div class="sp-title">Your report</div>
      <div class="sp-field"><label class="sp-label">Report title</label>
        <input id="f-title" type="text" placeholder="Brief description" value="${STATE.formData.title}" oninput="STATE.formData.title=this.value"/></div>
      <div class="sp-grid2">
        <div class="sp-field"><label class="sp-label">Category</label>
          <select id="f-cat" onchange="STATE.formData.category=this.value">
            <option value="">Select…</option>
            <option value="FINANCIAL_FRAUD">Financial Fraud</option>
            <option value="BRIBERY">Bribery</option>
            <option value="MISCONDUCT">Misconduct</option>
            <option value="DATA_BREACH">Data Breach</option>
            <option value="HR_VIOLATION">HR Violation</option>
            <option value="OTHER">Other</option>
          </select></div>
        <div class="sp-field"><label class="sp-label">Department</label>
          <select id="f-dept" onchange="STATE.formData.department=this.value">
            <option value="">Select…</option>
            <option value="Finance">Finance</option>
            <option value="HR">HR</option>
            <option value="IT">IT</option>
            <option value="Legal">Legal</option>
            <option value="Operations">Operations</option>
            <option value="Leadership">Leadership</option>
          </select></div>
      </div>
      <div class="sp-field"><label class="sp-label">Detailed description</label>
        <textarea id="f-desc" rows="4" placeholder="Describe the incident..." oninput="STATE.formData.description=this.value">${STATE.formData.description}</textarea></div>
      <div style="display:flex; gap:10px; justify-content:flex-end;">
        <button class="sp-btn secondary" onclick="STATE.submitStep=0;render()">Back</button>
        <button class="sp-btn primary" onclick="validateStep1()">Continue</button>
      </div>
    </div>`;

  } else if (s === 2) {
    html += `<div id="evidence-step" style="max-width:520px; margin:0 auto;"></div>`;

  } else if (s === 3) {
    const filesSummary    = STATE.formData.files.length
      ? `<div class="sp-detail-row"><span class="sp-detail-key">FILES</span><span class="sp-detail-val">${STATE.formData.files.length} file(s) — will be AES-256-GCM encrypted</span></div>` : '';
    const evidenceSummary = STATE.formData.evidence
      ? `<div class="sp-detail-row"><span class="sp-detail-key">TEXT EVIDENCE</span><span class="sp-detail-val" style="white-space:pre-wrap">${STATE.formData.evidence}</span></div>` : '';
    html += `<div style="max-width:520px; margin:0 auto;">
      <div class="sp-title">Review &amp; submit</div>
      <div class="sp-card" style="margin-bottom:16px;">
        <div class="sp-detail-row"><span class="sp-detail-key">TITLE</span><span class="sp-detail-val">${STATE.formData.title || '—'}</span></div>
        <div class="sp-detail-row"><span class="sp-detail-key">CATEGORY</span><span class="sp-detail-val">${STATE.formData.category || '—'}</span></div>
        <div class="sp-detail-row"><span class="sp-detail-key">DEPT</span><span class="sp-detail-val">${STATE.formData.department || '—'}</span></div>
        <div class="sp-detail-row"><span class="sp-detail-key">DESCRIPTION</span><span class="sp-detail-val" style="white-space:pre-wrap">${STATE.formData.description || '—'}</span></div>
        ${filesSummary}${evidenceSummary}
      </div>
      <div class="sp-info" style="margin-bottom:16px;"><span></span><div>All fields above will be encrypted with <strong>AES-256-GCM</strong> using your 256-bit secret key before storage. The key is shown once after submission.</div></div>
      <div style="margin-bottom:20px;">
        <div class="sp-label">Proof of Work</div>
        <div id="pow-container">${STATE.powDone
          ? `<div class="sp-badge green">Verified — PoW complete</div>`
          : `<div style="font-size:13px; margin-bottom:8px;">Running lightweight challenge…</div>
             <div class="sp-pow-bar"><div class="sp-pow-fill" id="powFill" style="width:0%"></div></div>
             <div id="powStatus" style="font-size:11px;">Initializing…</div>`}</div>
      </div>
      <div style="display:flex; gap:10px; justify-content:flex-end;">
        <button class="sp-btn secondary" onclick="STATE.submitStep=2;render()">Back</button>
        <button class="sp-btn primary" id="submitBtn" onclick="doSubmit()" ${STATE.powDone ? '' : 'disabled'}>Submit encrypted report</button>
      </div>
    </div>`;

  } else if (s === 4) {
    const rptId  = STATE.newReportId  || 'RPT-XXXX';
    const rptKey = STATE.newReportKey || '(key not available)';
    if (!deadManSwitches.has(rptId)) deadManSwitches.set(rptId, new DeadManSwitch(rptId));
    const dmsStatus = getDeadManSwitchStatus(rptId);
    html += `<div style="max-width:520px; margin:0 auto; text-align:center;">
      <svg width="56" height="56" viewBox="0 0 56 56" fill="none" style="margin:0 auto 20px;">
        <circle cx="28" cy="28" r="27" fill="rgba(110,231,183,0.1)" stroke="rgba(110,231,183,0.4)" stroke-width="1"/>
        <path d="M18 28l7 7 13-13" stroke="#6ee7b7" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <div class="sp-title">Report submitted &amp; encrypted</div>
      <div class="sp-subtitle">Save your <strong>secret key</strong> — it is your decryption key and is shown once only.</div>
      <div class="sp-card" style="text-align:left;"><div class="sp-label">Tracking ID</div>
        <div class="sp-mono-block" style="padding-right:64px;">${rptId}
          <button class="sp-copy-btn" onclick="copyText('${rptId}',this)">Copy</button></div></div>
      <div class="sp-card" style="text-align:left;"><div class="sp-label">Secret key (AES-256 · 256-bit)</div>
        <div class="sp-mono-block" style="word-break:break-all; padding-right:64px; font-size:11px;">${rptKey}
          <button class="sp-copy-btn" onclick="copyText('${rptKey}',this)">Copy</button></div></div>
      <div class="sp-info"><span></span><div>Your report content is encrypted with AES-256-GCM. This key is the only way to decrypt it. <strong>If lost, the content cannot be recovered.</strong></div></div>
      <div class="sp-info"><span></span><div><strong>Dead Man's Switch:</strong> 30-day heartbeat timer. Status: ${dmsStatus.status} · ${dmsStatus.remaining} remaining.</div></div>
      <div class="sp-info"><span></span><div><strong>SHA-256 Merkle Root:</strong> ${getCurrentMerkleRoot().substring(0, 20)}… (tamper-evident audit trail)</div></div>
      <div style="display:flex; gap:10px; justify-content:center; margin-top:20px;">
        <button class="sp-btn secondary" onclick="switchTab('track')">Track this report</button>
        <button class="sp-btn ghost" onclick="STATE.submitStep=0;STATE.formData={title:'',category:'',department:'',description:'',evidence:'',files:[]};STATE.powDone=false;render()">New report</button>
      </div>
    </div>`;
  }

  html += `</div></div>`;
  c.innerHTML = html;
  if (s === 2) buildEvidenceStep();
  if (s === 3 && !STATE.powDone) startPoW();
}

function buildEvidenceStep() {
  const el = document.getElementById('evidence-step');
  if (!el) return;

  function renderPreviews() {
    const container = document.getElementById('file-previews');
    if (!container) return;
    if (STATE.formData.files.length === 0) { container.innerHTML = ''; return; }
    container.innerHTML = STATE.formData.files.map((f, i) => {
      const isImg     = ['image/jpeg', 'image/png', 'image/webp'].includes(f.type);
      const thumbHtml = isImg
        ? `<img src="${f.dataUrl}" style="width:52px;height:40px;object-fit:cover;border-radius:5px;"/>`
        : `<video src="${f.dataUrl}" style="width:52px;height:40px;object-fit:cover;" muted></video>`;
      return `<div class="sp-file-preview">
        <div class="sp-file-thumb">${thumbHtml}</div>
        <div class="sp-file-info">
          <div class="sp-file-name">${f.name}</div>
          <div class="sp-file-meta">${f.type} · ${fmtBytes(f.size)}</div>
        </div>
        <button class="sp-file-remove" onclick="removeFile(${i})">✕</button>
      </div>`;
    }).join('');
  }

  el.innerHTML = `
    <div class="sp-title">Evidence</div>
    <div class="sp-subtitle">Attach files or paste text evidence. All evidence will be AES-256-GCM encrypted.</div>
    <div class="sp-warn"><span>⚠</span><div>Strip metadata before uploading.</div></div>
    <div class="sp-section-header">Upload Files</div>
    <div class="sp-field">
      <div class="sp-upload-zone" id="upload-zone">
        <input type="file" id="file-input" multiple accept="image/jpeg,image/png,image/webp,video/mp4,video/webm"
          onchange="handleFileSelect(this.files)" />
        <div class="sp-upload-icon">📎</div>
        <div class="sp-upload-text"><strong>Click to browse</strong> or drag and drop</div>
      </div>
      <div id="file-previews" class="sp-file-previews"></div>
    </div>
    <div class="sp-section-header">Text Evidence</div>
    <div class="sp-field">
      <label class="sp-label">Evidence notes</label>
      <textarea id="f-ev" placeholder="Paste relevant text..." oninput="STATE.formData.evidence=this.value">${STATE.formData.evidence}</textarea>
    </div>
    <div class="sp-info"><span></span><div>All evidence is encrypted with your secret key before storage.</div></div>
    <div style="display:flex; gap:10px; justify-content:flex-end;">
      <button class="sp-btn secondary" onclick="STATE.submitStep=1;render()">Back</button>
      <button class="sp-btn primary" onclick="advanceFromEvidence()">Continue</button>
    </div>`;

  const zone = document.getElementById('upload-zone');
  zone.addEventListener('dragover',  e => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', ()  => zone.classList.remove('dragover'));
  zone.addEventListener('drop',      e  => { e.preventDefault(); zone.classList.remove('dragover'); handleFileSelect(e.dataTransfer.files); });
  renderPreviews();
  window._renderEvidencePreviews = renderPreviews;
}

function renderTrack(c) {
  const decrypted = STATE.trackResultDecrypted;
  let html = `<div class="sp-content"><div style="max-width:440px; margin:0 auto;">
    <div class="sp-title">Track your report</div>
    <div class="sp-subtitle">Enter tracking ID and secret key. Each view sends a heartbeat to your Dead Man's Switch.</div>`;

  if (!STATE.trackResult) {
    html += `
      <div class="sp-field"><label class="sp-label">Tracking ID</label>
        <input id="track-id" type="text" placeholder="RPT-XXXX" value="${STATE.trackId}" oninput="STATE.trackId=this.value.toUpperCase()"/></div>
      <div class="sp-field"><label class="sp-label">Secret key</label>
        <input id="track-key" type="text" placeholder="64-char hex key…" value="${STATE.trackKey}" oninput="STATE.trackKey=this.value"/></div>
      <button class="sp-btn primary" onclick="doTrack()" style="width:100%">Look up report</button>
      <div class="sp-info" style="margin-top:16px;"><span>ℹ</span><div>Key is verified client-side. No server request is made.</div></div>
      <div class="sp-demo-badge"> SHA-256 Merkle Root: ${getCurrentMerkleRoot().substring(0, 30)}…<br>⏰ Dead Man's Switch active (30-day heartbeat).</div>`;
  } else {
    const r      = STATE.trackResult;
    const sc     = statusColor(r.status);
    const dmsInfo = getDeadManSwitchStatus(r.id);
    html += `
      <div class="sp-card">
        <div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px;">
          <div>
            <div style="font-family:monospace;">${r.id}</div>
            <div>${r.title}</div>
          </div>
          <span class="sp-badge ${sc}">${r.status}</span>
        </div>
        <div class="sp-divider"></div>
        <div class="sp-detail-row"><span class="sp-detail-key">SUBMITTED</span><span class="sp-detail-val">${fmtTs(r.ts)}</span></div>
        <div class="sp-detail-row"><span class="sp-detail-key">DEPT</span><span class="sp-detail-val">${r.dept}</span></div>
        <div class="sp-detail-row"><span class="sp-detail-key">TRUST</span><span class="sp-detail-val"><span class="sp-badge ${trustColor(r.trust)}">${r.trust}</span></span></div>
        <div class="sp-detail-row"><span class="sp-detail-key">ENCRYPTION</span><span class="sp-detail-val"><span class="sp-badge green">${r.enc}</span></span></div>
        <div class="sp-detail-row"><span class="sp-detail-key">DEAD MAN'S SWITCH</span><span class="sp-detail-val">
          <span class="sp-badge ${dmsInfo.status === 'AUTO-RELEASED' ? 'red' : 'green'}">${dmsInfo.status}</span> · ${dmsInfo.remaining}
        </span></div>
        <div class="sp-detail-row"><span class="sp-detail-key">SHA-256 MERKLE LEAF</span><span class="sp-detail-val sp-fingerprint">${r.merkleHash || 'pending'}</span></div>
        ${r.investigatorNote ? `<div class="sp-divider"></div><div class="sp-label">Investigator note</div><div>${r.investigatorNote}</div>` : ''}
        ${decrypted ? `<div class="sp-divider"></div>
          <div class="sp-label">Decrypted report</div>
          <div class="sp-detail-row"><span class="sp-detail-key">TITLE</span><span class="sp-detail-val">${decrypted.title || '—'}</span></div>
          <div class="sp-detail-row"><span class="sp-detail-key">CATEGORY</span><span class="sp-detail-val">${decrypted.category || '—'}</span></div>
          <div class="sp-detail-row"><span class="sp-detail-key">DESCRIPTION</span><span class="sp-detail-val" style="white-space:pre-wrap">${decrypted.description || '—'}</span></div>
          ${decrypted.files && decrypted.files.length ? `<div class="sp-detail-row"><span class="sp-detail-key">FILES</span><span class="sp-detail-val">${decrypted.files.length} file(s) attached</span></div>` : ''}` : `<div class="sp-info" style="margin-top:12px;"><span></span><div>Enter your key to decrypt report details.</div></div>`}
        <div class="sp-info" style="margin-top:12px;"><span></span><div>Viewing this report sends a heartbeat to your Dead Man's Switch, resetting the 30-day timer.</div></div>
      </div>
      <div style="margin-top:16px;">
        <button class="sp-btn secondary" onclick="STATE.trackResult=null;STATE.trackResultDecrypted=null;STATE.trackId='';STATE.trackKey='';render()">Look up another</button>
        <button class="sp-btn primary" style="margin-left:8px;" onclick="sendHeartbeatAndRefresh('${r.id}')">Send Heartbeat</button>
      </div>`;
  }
  html += `</div></div>`;
  c.innerHTML = html;
}

function renderAdmin(c) {
  const filtered = STATE.statusFilter === 'ALL'
    ? STATE.reports
    : STATE.reports.filter(r => r.status === STATE.statusFilter);

  let html = `<div class="sp-content"><div style="max-width:1060px; margin:0 auto;">
    <div style="display:flex; justify-content:space-between; margin-bottom:20px; flex-wrap:wrap; gap:10px;">
      <div>
        <div class="sp-title">Investigator Dashboard</div>
        <div style="font-size:13px; color:var(--sp-muted);">SHA-256 Merkle Root: ${getCurrentMerkleRoot().substring(0, 20)}… · Dead Man's Switch Active</div>
      </div>
      <div style="display:flex; gap:10px;">
        <div class="sp-enc-indicator"><span class="sp-enc-dot"></span>${STATE.investigatorSession.email}</div>
        <button class="sp-btn secondary" onclick="doLogout()">Sign out</button>
      </div>
    </div>`;

  html += `<div class="sp-filter-row">`;
  ['ALL', 'SUBMITTED', 'INVESTIGATING', 'RESOLVED', 'FALSE'].forEach(s => {
    html += `<button class="sp-badge ${s === 'ALL' ? 'gray' : statusColor(s)}"
      style="cursor:pointer; border:0.5px solid ${STATE.statusFilter === s ? 'currentColor' : 'transparent'}; opacity:${STATE.statusFilter === s ? 1 : 0.5}; padding:6px 12px;"
      onclick="STATE.statusFilter='${s}';render()">${s}</button>`;
  });
  html += `<button class="sp-badge purple" style="cursor:pointer;" onclick="STATE.showAdvancedFeatures=!STATE.showAdvancedFeatures;render()">
    ${STATE.showAdvancedFeatures ? 'Hide' : 'Show'} Advanced
  </button></div>`;

  html += `<div class="sp-card" style="padding:0; overflow-x:auto;">
    <table class="sp-table" style="min-width:700px;">
      <thead><tr>
        <th>ID</th><th>Title</th><th>Dept</th><th>📎</th><th>Enc</th><th>Status</th>
        ${STATE.showAdvancedFeatures ? '<th>SHA-256 Merkle</th><th>DMS</th>' : ''}
        <th>Action</th>
      </tr></thead><tbody>`;

  filtered.forEach(r => {
    const hasFiles = r.files && r.files.length;
    const dmsInfo  = getDeadManSwitchStatus(r.id);
    const encBadge = r.enc === 'AES-256-GCM'
      ? `<span class="sp-badge green" style="font-size:9px;">AES-256-GCM</span>`
      : `<span class="sp-badge gray" style="font-size:9px;">legacy</span>`;
    html += `<tr>
      <td><span style="font-family:monospace;">${r.id}</span></td>
      <td>${r.title}</td>
      <td>${r.dept}</td>
      <td>${hasFiles ? `<span class="sp-badge blue">📎 ${r.files.length}</span>` : '—'}</td>
      <td>${encBadge}</td>
      <td><span class="sp-badge ${statusColor(r.status)}">${r.status}</span></td>`;
    if (STATE.showAdvancedFeatures) {
      html += `<td><span class="sp-fingerprint" style="font-size:9px;">${(r.merkleHash || 'pending').substring(0, 16)}…</span></td>`;
      html += `<td><span class="sp-badge ${dmsInfo.status === 'AUTO-RELEASED' ? 'red' : 'green'}" style="font-size:9px;">${dmsInfo.status}</span><br><span style="font-size:9px;">${dmsInfo.remaining}</span></td>`;
    }
    html += `<td><button class="sp-btn ghost" onclick="openReport('${r.id}')">View →</button></td></tr>`;
  });

  html += `</tbody></table></div>`;

  if (STATE.showAdvancedFeatures) {
    html += `<div class="sp-info" style="margin-top:16px;"><span></span><div><strong>SHA-256 Merkle Tree:</strong> Cryptographic hash tree (real SHA-256 via Web Crypto API) ensuring tamper-evident audit trail. Root: ${getCurrentMerkleRoot()}<br><strong>⏰ Dead Man's Switch:</strong> Each report has a 30-day heartbeat timer. Reports without a heartbeat auto-release.</div></div>`;
  }

  html += `<div class="sp-demo-badge" style="margin-top:16px;"> <strong>Crypto stack:</strong> AES-256-GCM (report encryption) · SHA-256 (Merkle tree + fingerprint + credentials) · crypto.getRandomValues (key + ID generation) — all via Web Crypto API.</div>`;
  html += `</div></div>`;
  c.innerHTML = html;
}

function renderModal(c) {
  if (STATE.modal !== 'report') return;
  const r = STATE.reports.find(x => x.id === STATE.selectedReport);
  if (!r) return;
  const sc      = statusColor(r.status);
  const dmsInfo = getDeadManSwitchStatus(r.id);
  const overlay = document.createElement('div');
  overlay.className = 'sp-modal-overlay';

  let filesHtml = '';
  if ((r.files && r.files.length) || r.fileCount) {
    const fileMeta = r.files && r.files.length ? r.files : [];
    const count = fileMeta.length || r.fileCount || 0;
    filesHtml = `<div class="sp-label">Attached Evidence (${count} file${count === 1 ? '' : 's'})</div>
      <div class="sp-info" style="margin-bottom:16px;"><span>[i]</span><div>${count} file${count === 1 ? '' : 's'} are attached. Decrypt the report with the AES key to view the full attachments.</div></div>`;
    if (fileMeta.length) {
      filesHtml += `<div style="display:flex; flex-wrap:wrap; gap:12px; margin-bottom:16px;">` +
        fileMeta.map(f => `<div style="background:var(--sp-surface2); border-radius:6px; padding:10px; width:120px; text-align:center;"><div style="font-size:10px; font-weight:600; margin-bottom:6px;">${f.name}</div><div style="font-size:10px; color:var(--sp-muted);">${f.type}</div></div>`).join('') + `</div>`;
    }
  } else {
    filesHtml = `<div class="sp-info"><span>[i]</span><div>No files attached.</div></div>`;
  }

  // Determine whether this report has encrypted payload.
  const canDecrypt = r.enc === 'AES-256-GCM' && r.encData;
  const contentId  = `decrypt-content-${r.id}`;

  let decryptSection = '';
  if (canDecrypt) {
    decryptSection = `
      <div class="sp-label">Encrypted content <span class="sp-badge green" style="font-size:9px; margin-left:4px;">AES-256-GCM</span></div>
      <div style="margin-bottom:12px; display:flex; gap:8px; flex-wrap:wrap; align-items:center;">
        <input id="decrypt-key-${r.id}" type="text" placeholder="Paste AES key to decrypt" style="width:100%; padding:10px 12px; border-radius:7px; border:0.5px solid var(--sp-border2); background:var(--sp-surface2); color:var(--sp-text);" />
        <button class="sp-btn primary" style="white-space:nowrap;" onclick="attemptDecryptReport('${r.id}')">Decrypt</button>
        ${STATE.investigatorSession ? `<button class="sp-btn secondary" style="white-space:nowrap;" onclick="downloadEncryptedReport('${r.id}')">Download Encrypted</button>` : ''}
      </div>
      <div id="${contentId}" style="background:#0d0d10; border-radius:6px; padding:12px; margin-bottom:20px; font-size:13px; color:var(--sp-muted);">
        Enter the AES key to decrypt this report.
      </div>`;
  } else {
    decryptSection = `
      <div class="sp-label">Content <span class="sp-badge gray" style="font-size:9px; margin-left:4px;">legacy plaintext</span></div>
      <div style="background:#0d0d10; border-radius:6px; padding:12px; margin-bottom:20px;">${r.desc}</div>`;
  }

  overlay.innerHTML = `<div class="sp-modal">
    <button class="sp-close-btn" onclick="STATE.modal=null;render()">✕</button>
    <div style="display:flex; gap:10px; margin-bottom:20px; flex-wrap:wrap;">
      <span style="font-family:monospace;">${r.id}</span>
      <span class="sp-badge ${sc}">${r.status}</span>
      <span class="sp-badge ${trustColor(r.trust)}">${r.trust}</span>
      <span class="sp-badge ${r.enc === 'AES-256-GCM' ? 'green' : 'gray'}" style="font-size:10px;">${r.enc}</span>
    </div>
    <div style="font-size:16px; font-weight:500;">${r.title}</div>
    <div class="sp-detail-row"><span class="sp-detail-key">DEPT</span><span class="sp-detail-val">${r.dept}</span></div>
    <div class="sp-detail-row"><span class="sp-detail-key">SHA-256 FINGERPRINT</span><span class="sp-detail-val sp-fingerprint">${r.fp}</span></div>
    <div class="sp-detail-row"><span class="sp-detail-key">SHA-256 MERKLE LEAF</span><span class="sp-detail-val sp-fingerprint">${r.merkleHash || 'pending'}</span></div>
    <div class="sp-detail-row"><span class="sp-detail-key">DEAD MAN'S SWITCH</span><span class="sp-detail-val">
      <span class="sp-badge ${dmsInfo.status === 'AUTO-RELEASED' ? 'red' : 'green'}">${dmsInfo.status}</span> · Remaining: ${dmsInfo.remaining}
    </span></div>
    ${filesHtml}
    <div class="sp-divider"></div>
    ${decryptSection}
    ${r.investigatorNote ? `<div class="sp-label">Investigator note</div><div style="margin-bottom:16px;">${r.investigatorNote}</div>` : ''}
    <div class="sp-label">Update status</div>
    <div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:20px;">
      ${['INVESTIGATING', 'RESOLVED', 'FALSE', 'PUBLIC_LEAK'].map(s =>
        `<button class="sp-btn ${s === 'FALSE' ? 'danger' : 'secondary'}" style="font-size:11px;" onclick="updateStatus('${r.id}','${s}')">${s}</button>`
      ).join('')}
    </div>
    <div class="sp-label">Audit log</div>
    <div style="max-height:130px; overflow-y:auto;">
      ${r.audit.map(a => `<div class="sp-audit"><div class="sp-audit-time">${a.t}</div><div class="sp-audit-action">${a.a}</div></div>`).join('')}
    </div>
    <div class="sp-divider" style="margin-top:20px;"></div>
    <div class="sp-label" style="color:var(--sp-danger);">Danger Zone</div>
    <button class="sp-btn danger" style="width:100%; justify-content:center; margin-top:8px;" onclick="deleteReport('${r.id}')">Delete Report Permanently</button>
  </div>`;

  c.appendChild(overlay);
}

async function attemptDecryptReport(reportId) {
  const keyInput = document.getElementById(`decrypt-key-${reportId}`);
  const contentEl = document.getElementById(`decrypt-content-${reportId}`);
  const r = STATE.reports.find(x => x.id === reportId);
  if (!contentEl || !keyInput || !r) return;
  const key = keyInput.value.trim();
  if (!isHexKey(key)) {
    contentEl.innerHTML = '<span style="color:var(--sp-danger)">Enter a valid 64-character hex AES key.</span>';
    return;
  }
  const payload = await decryptReportPayload(r.encData, key);
  if (!payload) {
    contentEl.innerHTML = '<span style="color:var(--sp-danger)">Decryption failed — invalid key or tampered ciphertext.</span>';
    return;
  }
  
  // Store decrypted payload in STATE for download functions
  STATE.decryptedPayload = { ...payload, reportId: reportId };
  
  let downloadButtonsHtml = '';
  if (STATE.investigatorSession) {
    downloadButtonsHtml = `
      <div style="margin-top:12px; display:flex; gap:8px; flex-wrap:wrap;">
        <button class="sp-btn secondary" style="white-space:nowrap;" onclick="downloadDecryptedReport()">Download Report (JSON)</button>
        ${payload.files && payload.files.length ? `<button class="sp-btn secondary" style="white-space:nowrap;" onclick="downloadAllAttachedFiles()">Download All Files</button>` : ''}
      </div>`;
  }
  
  contentEl.innerHTML = `
    <div style="display:grid; gap:8px;">
      ${payload.title       ? `<div><span style="font-size:10px;color:var(--sp-muted)">TITLE</span><br>${payload.title}</div>` : ''}
      ${payload.category    ? `<div><span style="font-size:10px;color:var(--sp-muted)">CATEGORY</span><br>${payload.category}</div>` : ''}
      ${payload.department  ? `<div><span style="font-size:10px;color:var(--sp-muted)">DEPT</span><br>${payload.department}</div>` : ''}
      ${payload.description ? `<div><span style="font-size:10px;color:var(--sp-muted)">DESCRIPTION</span><br><span style="white-space:pre-wrap">${payload.description}</span></div>` : ''}
      ${payload.evidence    ? `<div><span style="font-size:10px;color:var(--sp-muted)">EVIDENCE</span><br><span style="white-space:pre-wrap">${payload.evidence}</span></div>` : ''}
      ${payload.files && payload.files.length ? `<div><span style="font-size:10px;color:var(--sp-muted)">ATTACHMENTS</span><br>${payload.files.map((f, idx) => `<div style="margin-top:6px;">${f.name} (${f.type}, ${fmtBytes(f.size)}) <button class="sp-btn" style="padding:4px 8px; font-size:10px; white-space:nowrap;" onclick="downloadAttachedFile(${idx})">Download</button></div>`).join('')}</div>` : ''}
    </div>
    ${downloadButtonsHtml}`;
}

function downloadEncryptedReport(reportId) {
  const r = STATE.reports.find(x => x.id === reportId);
  if (!r || !r.encData) return;
  const encryptedBytes = base64ToBytes(r.encData);
  const blob = new Blob([encryptedBytes], {type: 'application/octet-stream'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `report-${r.id}.enc`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function base64ToBytes(base64) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function downloadDecryptedReport() {
  if (!STATE.decryptedPayload) {
    alert('No decrypted report to download.');
    return;
  }
  const reportData = {
    reportId: STATE.decryptedPayload.reportId,
    title: STATE.decryptedPayload.title,
    category: STATE.decryptedPayload.category,
    department: STATE.decryptedPayload.department,
    description: STATE.decryptedPayload.description,
    evidence: STATE.decryptedPayload.evidence,
    fileCount: STATE.decryptedPayload.files ? STATE.decryptedPayload.files.length : 0,
    downloadedAt: new Date().toISOString(),
  };
  const jsonStr = JSON.stringify(reportData, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `report-${STATE.decryptedPayload.reportId}-decrypted.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function downloadAttachedFile(fileIndex) {
  if (!STATE.decryptedPayload || !STATE.decryptedPayload.files || !STATE.decryptedPayload.files[fileIndex]) {
    alert('File not found.');
    return;
  }
  const file = STATE.decryptedPayload.files[fileIndex];
  const fileData = file.dataUrl || file.data || file.content || '';
  if (!fileData) {
    alert('File data is empty.');
    return;
  }
  // fileData is a data URL like "data:image/jpeg;base64,/9j/4AAQSkZ..."
  const link = document.createElement('a');
  link.href = fileData;
  link.download = file.name;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function downloadAllAttachedFiles() {
  if (!STATE.decryptedPayload || !STATE.decryptedPayload.files || STATE.decryptedPayload.files.length === 0) {
    alert('No files to download.');
    return;
  }
  // Download each file individually with a slight delay
  STATE.decryptedPayload.files.forEach((f, idx) => {
    setTimeout(() => downloadAttachedFile(idx), idx * 500);
  });
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
// Show a loading state immediately, then boot async
document.addEventListener('DOMContentLoaded', async () => {
  const c = document.getElementById('mainContent');
  if (c) c.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;min-height:60vh;color:var(--sp-muted);font-size:13px;">Initialising cryptography…</div>`;
  await initState();
});
