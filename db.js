/**
 * db.js — Spectre Database Layer
 *
 * Cryptography: Web Crypto API (SHA-256, AES-256-GCM)
 *   - All hashing: crypto.subtle.digest('SHA-256', …)
 *   - All encryption: AES-256-GCM via crypto.subtle.encrypt/decrypt
 *   - Key generation: crypto.getRandomValues (see app.js)
 *
 * In production replace the localStorage/sessionStorage calls here
 * with real persistence (IndexedDB, SQLite via sql.js, or remote API calls).
 * Credentials would be verified server-side (bcrypt/Argon2 + constant-time compare).
 */

'use strict';

const STORAGE_KEY = 'spectre_reports';
const VERIF_KEY   = 'spectre_verified';

// ─── Real SHA-256 ─────────────────────────────────────────────────────────────
/**
 * Returns a lowercase hex SHA-256 digest of the given string.
 * @param {string} str
 * @returns {Promise<string>} 64-char hex string
 */
async function sha256Hex(str) {
  const data   = new TextEncoder().encode(str);
  const buffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ─── AES-256-GCM helpers ──────────────────────────────────────────────────────
function _hexToBytes(hex) {
  return new Uint8Array((hex.match(/.{1,2}/g) || []).map(b => parseInt(b, 16)));
}
function _toBase64(bytes) {
  let s = '';
  bytes.forEach(b => s += String.fromCharCode(b));
  return btoa(s);
}
function _fromBase64(b64) {
  const s = atob(b64);
  return new Uint8Array([...s].map(c => c.charCodeAt(0)));
}

/**
 * AES-256-GCM encrypt.
 * @param {string} plaintext
 * @param {string} keyHex   64-char hex (32 bytes = 256-bit key)
 * @returns {Promise<string>} base64(12-byte IV || ciphertext+auth-tag)
 */
async function aesEncrypt(plaintext, keyHex) {
  const key = await crypto.subtle.importKey(
    'raw', _hexToBytes(keyHex), { name: 'AES-GCM' }, false, ['encrypt']
  );
  const iv         = crypto.getRandomValues(new Uint8Array(12));   // 96-bit IV — GCM spec
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext)
  );
  const combined = new Uint8Array(12 + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), 12);
  return _toBase64(combined);
}

/**
 * AES-256-GCM decrypt (authenticated — throws if tampered).
 * @param {string} encBase64   output of aesEncrypt
 * @param {string} keyHex      64-char hex
 * @returns {Promise<string>}  plaintext
 */
async function aesDecrypt(encBase64, keyHex) {
  const key = await crypto.subtle.importKey(
    'raw', _hexToBytes(keyHex), { name: 'AES-GCM' }, false, ['decrypt']
  );
  const combined   = _fromBase64(encBase64);
  const iv         = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const decrypted  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}

// ─── Merkle Tree (real SHA-256 pairs) ────────────────────────────────────────
class MerkleTreeSimulator {
  constructor(leaves) {
    this.leaves = leaves;   // SHA-256 hex strings
    this.root   = null;     // populated by MerkleTreeSimulator.create()
  }

  /** Async factory — required because tree construction hashes pairs. */
  static async create(dataHashes) {
    const tree = new MerkleTreeSimulator(dataHashes);
    tree.root  = await tree._calculateRoot();
    return tree;
  }

  async _calculateRoot() {
    if (!this.leaves.length) return '0x' + '0'.repeat(64);
    let level = [...this.leaves];
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        next.push(
          i + 1 < level.length
            ? await sha256Hex(level[i] + level[i + 1])   // hash pair
            : level[i]                                    // odd node promoted
        );
      }
      level = next;
    }
    return '0x' + level[0];
  }

  getRoot() { return this.root; }

  /** Real SHA-256 leaf hash (replaces old djb2 simulation). */
  static async generateReportHash(reportId, timestamp, fingerprint) {
    return sha256Hex(`${reportId}|${timestamp}|${fingerprint}`);
  }
}

// ─── Dead Man's Switch ────────────────────────────────────────────────────────
class DeadManSwitch {
  constructor(reportId, expiryHours = 720) {
    this.reportId      = reportId;
    this.lastHeartbeat = Date.now();
    this.expiryHours   = expiryHours;
    this.active        = true;
    this.releaseTime   = this.lastHeartbeat + expiryHours * 3_600_000;
  }

  heartbeat() {
    this.lastHeartbeat = Date.now();
    this.releaseTime   = this.lastHeartbeat + this.expiryHours * 3_600_000;
    return this.releaseTime;
  }

  isExpired()        { return Date.now() > this.releaseTime; }

  getTimeRemaining() {
    const remaining = this.releaseTime - Date.now();
    if (remaining <= 0) return 'Released';
    const days  = Math.floor(remaining / 86_400_000);
    const hours = Math.floor((remaining % 86_400_000) / 3_600_000);
    return `${days}d ${hours}h`;
  }

  getStatus() { return this.isExpired() ? 'AUTO-RELEASED' : 'PENDING HEARTBEAT'; }
}

// ─── In-memory stores ─────────────────────────────────────────────────────────
const deadManSwitches = new Map();
let   merkleLeaves    = [];

// ─── Merkle helpers ───────────────────────────────────────────────────────────
async function updateMerkleRoot(reports) {
  merkleLeaves = await Promise.all(
    reports.map(r => MerkleTreeSimulator.generateReportHash(r.id, r.ts, r.fp))
  );
  const tree = await MerkleTreeSimulator.create(merkleLeaves);
  sessionStorage.setItem('spectre_merkle_root', tree.getRoot());
  return tree.getRoot();
}

function getCurrentMerkleRoot() {
  return sessionStorage.getItem('spectre_merkle_root') || '0x' + '0'.repeat(64);
}

// ─── DMS helpers ─────────────────────────────────────────────────────────────
function getDeadManSwitchStatus(reportId) {
  const dms = deadManSwitches.get(reportId);
  if (!dms) return { status: 'NOT SETUP', remaining: 'N/A' };
  return { status: dms.getStatus(), remaining: dms.getTimeRemaining(), expired: dms.isExpired() };
}

function heartbeatReport(reportId) {
  const dms = deadManSwitches.get(reportId);
  if (!dms) return { success: false };
  return { success: true, releaseTime: new Date(dms.heartbeat()).toISOString() };
}

function initDmsForReport(report) {
  if (!deadManSwitches.has(report.id)) {
    deadManSwitches.set(report.id, new DeadManSwitch(report.id));
  }
}

// ─── Seed data ────────────────────────────────────────────────────────────────
async function getDefaultReports() {
  const defaults = [
    {
      id: 'RPT-8K2X', key: null, status: 'INVESTIGATING',
      dept: 'Finance', title: 'Procurement fraud in Q3 contracts',
      ts: '2025-12-01', trust: 'ENDORSED', fp: 'a3b7c9d1',
      enc: 'Plaintext (legacy seed)', encData: null,
      investigatorNote: 'Financial records subpoenaed.',
      audit: [
        { t: '2025-12-01 09:14', a: 'Report submitted' },
        { t: '2025-12-02 11:30', a: 'Status → INVESTIGATING' },
        { t: '2025-12-03 14:02', a: 'Trust upgraded to ENDORSED' },
      ],
      desc:  'Procurement division awarded contracts to a vendor with undisclosed executive ties.',
      files: [],
    },
    {
      id: 'RPT-5WQ9', key: null, status: 'SUBMITTED',
      dept: 'HR', title: 'Systematic retaliation against whistleblowers',
      ts: '2025-12-03', trust: 'UNVERIFIED', fp: 'f1e2a8c4',
      enc: 'Plaintext (legacy seed)', encData: null,
      investigatorNote: '',
      audit: [{ t: '2025-12-03 16:44', a: 'Report submitted' }],
      desc:  'Multiple employees who filed HR complaints were subsequently demoted.',
      files: [],
    },
    {
      id: 'RPT-2NM4', key: null, status: 'RESOLVED',
      dept: 'IT', title: 'Unauthorized data export to personal cloud',
      ts: '2025-11-28', trust: 'VERIFIED', fp: 'b9d4e7f2',
      enc: 'Plaintext (legacy seed)', encData: null,
      investigatorNote: 'Employee terminated.',
      audit: [
        { t: '2025-11-28 08:20', a: 'Report submitted' },
        { t: '2025-11-29 10:00', a: 'Status → INVESTIGATING' },
        { t: '2025-12-05 15:30', a: 'Status → RESOLVED' },
      ],
      desc:  'Senior IT admin exported 4.7GB of customer PII to personal Dropbox.',
      files: [],
    },
    {
      id: 'RPT-7YR1', key: null, status: 'FALSE',
      dept: 'Legal', title: 'Fabricated expense claims by director',
      ts: '2025-11-25', trust: 'UNVERIFIED', fp: 'c2a5f8b1',
      enc: 'Plaintext (legacy seed)', encData: null,
      investigatorNote: 'Expenses were pre-approved.',
      audit: [
        { t: '2025-11-25 14:10', a: 'Report submitted' },
        { t: '2025-11-26 09:00', a: 'Status → INVESTIGATING' },
        { t: '2025-11-27 11:00', a: 'Marked FALSE' },
      ],
      desc:  'Claims that Director X submitted fabricated expenses.',
      files: [],
    },
  ];

  for (const r of defaults) {
    initDmsForReport(r);
    const hash = await MerkleTreeSimulator.generateReportHash(r.id, r.ts, r.fp);
    if (!merkleLeaves.includes(hash)) merkleLeaves.push(hash);
  }
  await updateMerkleRoot(defaults);
  return defaults;
}

// ─── CRUD ─────────────────────────────────────────────────────────────────────

/** Load all reports from localStorage (or seed). */
async function loadReports() {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored) {
    try {
      const reports = JSON.parse(stored);
      for (const r of reports) {
        if (r.key && !r.keyHash) {
          r.keyHash = await sha256Hex(r.key);
          delete r.key;
        }
        initDmsForReport(r);
        const hash = await MerkleTreeSimulator.generateReportHash(r.id, r.ts, r.fp);
        if (!merkleLeaves.includes(hash)) merkleLeaves.push(hash);
      }
      await updateMerkleRoot(reports);
      return reports.map(r => ({ ...r, files: r.files || [] }));
    } catch (_) { /* fall through to seed */ }
  }
  return getDefaultReports();
}

/** Persist all reports and refresh Merkle root. */
async function saveReports(reports) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(reports));
  await updateMerkleRoot(reports);
}

/**
 * Create a new report record (does NOT persist — call saveReports afterwards).
 *
 * @param {object} opts
 * @param {string} opts.id
 * @param {string} opts.key        64-char hex AES-256 key shown to reporter
 * @param {string} opts.fingerprint
 * @param {object} opts.formData
 * @param {string} opts.encData    base64(IV || AES-GCM ciphertext+tag)
 */
async function createReport({ id, keyHash, fingerprint, formData, encData }) {
  const ts         = new Date().toISOString().split('T')[0];
  const merkleHash = await MerkleTreeSimulator.generateReportHash(id, ts, fingerprint);
  merkleLeaves.push(merkleHash);

  const dms = new DeadManSwitch(id);
  deadManSwitches.set(id, dms);

  const attachments = Array.isArray(formData.files)
    ? formData.files.map(f => ({ name: f.name, type: f.type, size: f.size }))
    : [];

  return {
    id,
    keyHash,
    status:           'SUBMITTED',
    dept:             formData.department || 'Unknown',
    title:            formData.title,
    ts,
    trust:            'UNVERIFIED',
    fp:               fingerprint,
    enc:              'AES-256-GCM',
    encData,                               // base64(IV || ciphertext+auth-tag)
    investigatorNote: '',
    desc:             '[AES-256-GCM encrypted — reporter key required]',
    fileCount:        attachments.length,
    files:            attachments,
    merkleHash,
    dmsStatus:        dms.getStatus(),
    dmsExpiry:        dms.releaseTime,
    audit: [{
      t: new Date().toISOString().replace('T', ' ').slice(0, 16),
      a: 'Report submitted (UNVERIFIED) — AES-256-GCM encrypted' +
         (attachments.length ? ` · ${attachments.length} file(s) included` : '') +
         ` · SHA-256 Merkle root: ${getCurrentMerkleRoot().substring(0, 18)}…`,
    }],
  };
}

/** Update a report's status in-place and append to audit log. */
function updateReportStatus(report, newStatus) {
  report.status = newStatus;
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 16);
  report.audit.push({ t: ts, a: `Status updated to ${newStatus} by investigator` });
  if (newStatus === 'FALSE') {
    report.audit.push({ t: ts, a: `Fingerprint ${report.fp} blacklisted 30d` });
    if (report.trust === 'ENDORSED') report.trust = 'UNVERIFIED';
  }
}

// ─── Auth (SHA-256 credential hashing) ────────────────────────────────────────
// Passwords are stored as SHA-256 hashes for this demo. In production use
// server-side bcrypt/Argon2 and constant-time comparison.
const _HASHED_CREDENTIALS = [
  { email: 'investigator@spectre.internal', passwordHash: '9ada3d6152eee02d7eecb3d256b160d9feb937bc63f8b8b0543943939c4926b1' },
  { email: 'admin@spectre.internal',        passwordHash: '3320ae044293e55b1483f9e780c4619486ccaf2a28ff767e1add80321a42ec70' },
];

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i += 1) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

async function findCredential(email, password) {
  const passHash = await sha256Hex(password);
  return _HASHED_CREDENTIALS.find(
    c => c.email === email.trim().toLowerCase() && timingSafeEqual(c.passwordHash, passHash)
  ) || null;
}
