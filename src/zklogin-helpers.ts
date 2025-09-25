import { groth16 } from 'snarkjs';
// Import and explicitly re-export circom runtime for witness calculation
import { WitnessCalculatorBuilder, createCircomRuntimeImports } from './circom-runtime';

// ---------------------------------------------------------------------------
// Shared security constants, helpers, and in-memory caches
// ---------------------------------------------------------------------------

const SESSION_PREFIX = 'galactic:zkLogin';
const IDENTITY_CACHE_KEY = `${SESSION_PREFIX}:identityCache`;
const ACTIVE_IDENTITY_KEY = `${SESSION_PREFIX}:activeIdentity`;
const IDLE_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes
const PBKDF2_ITERATIONS = 210_000;
const PBKDF2_DIGEST = 'SHA-256';
const IDENTITY_HASH_PEPPER = 'galactic::identity::v1';
const PBKDF2_SALT_PREFIX = 'galactic::pbkdf::v1::';
const PASSWORD_VERIFIER_PREFIX = 'galactic::verifier::v1';

type IdentityCacheEntry = {
  encryptedSalt: string;
  saltIv: string;
  encryptedProof?: string;
  proofIv?: string;
  passwordVerifier: string;
  metadata: {
    issHash: string;
    subHash: string;
    audHash: string;
    updatedAt: number;
  };
};

const passwordKeyCache = new Map<string, CryptoKey>();
let idleTimeoutHandle: number | null = null;
let idleListenersRegistered = false;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function normalizeAudienceClaim(aud: unknown): string {
  if (Array.isArray(aud)) {
    return aud.map(item => String(item)).sort().join(' ');
  }
  if (typeof aud === 'string') {
    return aud;
  }
  return '';
}

async function sha256Bytes(input: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(input));
  return new Uint8Array(digest);
}

function bytesToBase64(bytes: Uint8Array): string {
  return arrayBufferToBase64(bytes.buffer);
}

function base64ToBytes(base64: string): Uint8Array {
  return new Uint8Array(base64ToArrayBuffer(base64));
}

function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function loadIdentityCache(): Record<string, IdentityCacheEntry> {
  try {
    const raw = sessionStorage.getItem(IDENTITY_CACHE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Record<string, IdentityCacheEntry>;
    return parsed || {};
  } catch (error) {
    console.warn('Failed to parse identity cache. Resetting.', error);
    return {};
  }
}

function saveIdentityCache(cache: Record<string, IdentityCacheEntry>) {
  sessionStorage.setItem(IDENTITY_CACHE_KEY, JSON.stringify(cache));
}

function getActiveIdentityHash(): string | null {
  return sessionStorage.getItem(ACTIVE_IDENTITY_KEY);
}

function setActiveIdentityHash(identityHash: string) {
  sessionStorage.setItem(ACTIVE_IDENTITY_KEY, identityHash);
}

function clearSensitiveSessionData() {
  passwordKeyCache.clear();
  sessionStorage.removeItem(IDENTITY_CACHE_KEY);
  sessionStorage.removeItem(ACTIVE_IDENTITY_KEY);
}

function scheduleIdleTeardown() {
  if (idleTimeoutHandle) {
    window.clearTimeout(idleTimeoutHandle);
  }
  idleTimeoutHandle = window.setTimeout(() => {
    clearSensitiveSessionData();
  }, IDLE_TIMEOUT_MS);

  if (!idleListenersRegistered) {
    const reset = () => scheduleIdleTeardown();
    ['mousemove', 'keydown', 'click', 'scroll'].forEach(event => {
      window.addEventListener(event, reset);
    });
    if (typeof requestIdleCallback !== 'undefined') {
      requestIdleCallback(() => scheduleIdleTeardown());
    }
    idleListenersRegistered = true;
  }
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

async function computeIdentityHash(jwtPayload: { iss?: string; sub?: string; aud?: unknown }): Promise<string> {
  const iss = jwtPayload?.iss || '';
  const sub = jwtPayload?.sub || '';
  const aud = normalizeAudienceClaim(jwtPayload?.aud);
  const canonical = `${IDENTITY_HASH_PEPPER}|${iss}|${sub}|${aud}`;
  const digest = await sha256Bytes(canonical);
  return bytesToBase64Url(digest);
}

type PasswordMaterial = {
  identityHash: string;
  saltBytes: Uint8Array;
  encryptionKey: CryptoKey;
  encryptionKeyBytes: Uint8Array;
  passwordVerifier: string;
};

async function derivePasswordMaterial(password: string, jwtPayload: { iss?: string; sub?: string; aud?: unknown }): Promise<PasswordMaterial> {
  validatePassword(password);

  const identityHash = await computeIdentityHash(jwtPayload);
  const audience = normalizeAudienceClaim(jwtPayload?.aud);
  const saltSource = `${PBKDF2_SALT_PREFIX}${jwtPayload?.iss || ''}|${jwtPayload?.sub || ''}|${audience}`;
  const pbkdfSaltBytes = await sha256Bytes(saltSource);

  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: pbkdfSaltBytes.buffer,
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_DIGEST,
    },
    passwordKey,
    512
  );

  const derivedBytes = new Uint8Array(derivedBits);
  const saltBytes = derivedBytes.slice(0, 32);
  const encryptionKeyBytes = derivedBytes.slice(32, 64);

  const encryptionKey = await crypto.subtle.importKey(
    'raw',
    encryptionKeyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );

  const verifierBytes = await crypto.subtle.digest(
    'SHA-256',
    encoder.encode(`${PASSWORD_VERIFIER_PREFIX}|${bytesToBase64(encryptionKeyBytes)}`)
  );

  return {
    identityHash,
    saltBytes,
    encryptionKey,
    encryptionKeyBytes,
    passwordVerifier: bytesToBase64(new Uint8Array(verifierBytes)),
  };
}

async function encryptWithKey(key: CryptoKey, data: Uint8Array): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv.buffer),
  };
}

async function decryptWithKey(key: CryptoKey, base64Cipher: string, base64Iv: string): Promise<Uint8Array> {
  const ciphertext = base64ToArrayBuffer(base64Cipher);
  const iv = base64ToArrayBuffer(base64Iv);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key, ciphertext);
  return new Uint8Array(decrypted);
}

async function getCachedPasswordKey(identityHash: string): Promise<CryptoKey> {
  const cached = passwordKeyCache.get(identityHash);
  if (!cached) {
    throw new Error('Password required to unlock stored zkLogin data.');
  }
  return cached;
}

function upsertIdentityCache(identityHash: string, entry: Partial<IdentityCacheEntry>) {
  const cache = loadIdentityCache();
  const existing = cache[identityHash];
  cache[identityHash] = {
    encryptedSalt: entry.encryptedSalt || existing?.encryptedSalt || '',
    saltIv: entry.saltIv || existing?.saltIv || '',
    encryptedProof: entry.encryptedProof ?? existing?.encryptedProof,
    proofIv: entry.proofIv ?? existing?.proofIv,
    passwordVerifier: entry.passwordVerifier || existing?.passwordVerifier || '',
    metadata: entry.metadata || existing?.metadata || {
      issHash: '',
      subHash: '',
      audHash: '',
      updatedAt: Date.now(),
    },
  };
  saveIdentityCache(cache);
}

function buildMetadata(jwtPayload: { iss?: string; sub?: string; aud?: unknown }): Promise<IdentityCacheEntry['metadata']> {
  return (async () => {
    const issHash = bytesToBase64Url(await sha256Bytes(jwtPayload?.iss || ''));
    const subHash = bytesToBase64Url(await sha256Bytes(jwtPayload?.sub || ''));
    const audHash = bytesToBase64Url(await sha256Bytes(normalizeAudienceClaim(jwtPayload?.aud)));
    return {
      issHash,
      subHash,
      audHash,
      updatedAt: Date.now(),
    };
  })();
}

async function verifyPassword(verifier: string, encryptionKeyBytes: Uint8Array) {
  const candidateBytes = await crypto.subtle.digest(
    'SHA-256',
    encoder.encode(`${PASSWORD_VERIFIER_PREFIX}|${bytesToBase64(encryptionKeyBytes)}`)
  );
  const expected = base64ToBytes(verifier);
  const actual = new Uint8Array(candidateBytes);
  if (!constantTimeEqual(expected, actual)) {
    throw new Error('Incorrect password for this identity.');
  }
}

function ensureIdentityEntry(identityHash: string): IdentityCacheEntry {
  const cache = loadIdentityCache();
  const entry = cache[identityHash];
  if (!entry) {
    throw new Error('Identity context missing for zkLogin proof.');
  }
  return entry;
}

// ---------------------------------------------------------------------------
// Security Utilities for Cookie Handling and CSRF Protection
// ---------------------------------------------------------------------------

// Secure cookie helper with SameSite protection
function setSecureCookie(name: string, value: string, options: {
  maxAge?: number;
  secure?: boolean;
  sameSite?: 'Strict' | 'Lax' | 'None';
  httpOnly?: boolean;
} = {}) {
  const defaults = {
    secure: window.location.protocol === 'https:',
    sameSite: 'Strict' as const,
    httpOnly: false, // Can't be true for JS access
    maxAge: 900 // 15 minutes default
  };

  const cookieOptions = { ...defaults, ...options };

  let cookieString = `${name}=${encodeURIComponent(value)}`;

  if (cookieOptions.maxAge) {
    cookieString += `; Max-Age=${cookieOptions.maxAge}`;
  }

  if (cookieOptions.secure) {
    cookieString += `; Secure`;
  }

  cookieString += `; SameSite=${cookieOptions.sameSite}`;

  if (cookieOptions.httpOnly) {
    cookieString += `; HttpOnly`;
  }

  // Add path and domain restrictions
  cookieString += `; Path=/`;

  document.cookie = cookieString;
}

// CSRF token generation and validation
function generateCSRFToken(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Store CSRF token in secure cookie
function setCSRFToken(): string {
  const token = generateCSRFToken();
  setSecureCookie('galactic-csrf', token, {
    sameSite: 'Strict',
    secure: true,
    maxAge: 3600 // 1 hour
  });
  return token;
}

// Validate CSRF token
function validateCSRFToken(token: string): boolean {
  const cookies = document.cookie.split(';');
  for (let cookie of cookies) {
    const [name, value] = cookie.trim().split('=');
    if (name === 'galactic-csrf') {
      return decodeURIComponent(value) === token;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Password-based Salt Management Functions
// ---------------------------------------------------------------------------

// Validate password length
function validatePassword(password: string): void {
  if (password.length < 8) {
    throw new Error("Password must be at least 8 characters");
  }
}

// Convert Uint8Array to hex string (browser-compatible)
function uint8ArrayToHex(uint8Array: Uint8Array): string {
  return Array.from(uint8Array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Utility functions for base64 conversion
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// Store salt in session storage with idle timeout
async function storeSaltInSessionStorage(password: string, jwtPayload: any = null): Promise<{ identityHash: string; salt: Uint8Array }> {
  try {
    const material = await derivePasswordMaterial(password, jwtPayload || {});
    const { identityHash, saltBytes, encryptionKey, encryptionKeyBytes, passwordVerifier } = material;

    const cache = loadIdentityCache();
    const existing = cache[identityHash];
    if (existing?.passwordVerifier) {
      await verifyPassword(existing.passwordVerifier, encryptionKeyBytes);
      if (existing.encryptedSalt && existing.saltIv) {
        try {
          const decryptedSalt = await decryptWithKey(encryptionKey, existing.encryptedSalt, existing.saltIv);
          if (!constantTimeEqual(decryptedSalt, saltBytes)) {
            throw new Error('Derived salt mismatch for identity.');
          }
        } catch (error) {
          throw new Error('Incorrect password for this identity.');
        }
      }
    }

    const { ciphertext, iv } = await encryptWithKey(encryptionKey, saltBytes);
    const metadata = await buildMetadata(jwtPayload || {});

    upsertIdentityCache(identityHash, {
      encryptedSalt: ciphertext,
      saltIv: iv,
      passwordVerifier,
      metadata,
    });

    passwordKeyCache.set(identityHash, encryptionKey);
    setActiveIdentityHash(identityHash);
    scheduleIdleTeardown();
    return { identityHash, salt: new Uint8Array(saltBytes) };
  } catch (error) {
    throw new Error(`Session storage failed: ${(error as Error).message}`);
  }
}

// Retrieve salt from session storage
async function getSaltFromSessionStorage(identityHash?: string): Promise<Uint8Array> {
  try {
    const activeIdentity = identityHash || getActiveIdentityHash();
    if (!activeIdentity) throw new Error('No active zkLogin identity');
    const entry = ensureIdentityEntry(activeIdentity);
    if (!entry.encryptedSalt || !entry.saltIv) throw new Error('Salt not found for identity');
    const key = await getCachedPasswordKey(activeIdentity);
    return await decryptWithKey(key, entry.encryptedSalt, entry.saltIv);
  } catch (error) {
    throw new Error(`Salt retrieval failed: ${(error as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// Proof Encryption Functions for Enhanced Security
// ---------------------------------------------------------------------------

// Encrypt zkLogin proof using the password-derived identity key
async function encryptProof(proof: any, identityHash?: string): Promise<void> {
  try {
    const activeIdentity = identityHash || getActiveIdentityHash();
    if (!activeIdentity) throw new Error('No active zkLogin identity');
    const entry = ensureIdentityEntry(activeIdentity);
    const key = await getCachedPasswordKey(activeIdentity);
    const payload = encoder.encode(JSON.stringify(proof));
    const { ciphertext, iv } = await encryptWithKey(key, payload);

    const cache = loadIdentityCache();
    const updatedEntry = cache[activeIdentity];
    if (!updatedEntry) throw new Error('Identity context missing for proof storage.');
    updatedEntry.encryptedProof = ciphertext;
    updatedEntry.proofIv = iv;
    updatedEntry.metadata = { ...entry.metadata, updatedAt: Date.now() };
    cache[activeIdentity] = updatedEntry;
    saveIdentityCache(cache);
  } catch (error) {
    throw new Error(`Proof encryption failed: ${(error as Error).message}`);
  }
}

// Decrypt zkLogin proof from session storage
async function decryptProof(identityHash?: string): Promise<any> {
  try {
    const activeIdentity = identityHash || getActiveIdentityHash();
    if (!activeIdentity) throw new Error('No active zkLogin identity');
    const entry = ensureIdentityEntry(activeIdentity);
    if (!entry.encryptedProof || !entry.proofIv) {
      throw new Error('No encrypted proof available for identity');
    }
    const key = await getCachedPasswordKey(activeIdentity);
    const decrypted = await decryptWithKey(key, entry.encryptedProof, entry.proofIv);
    const proofJson = new TextDecoder().decode(decrypted);
    return JSON.parse(proofJson);
  } catch (error) {
    throw new Error(`Proof decryption failed: ${(error as Error).message}`);
  }
}

// Hash sub, salt, and iss for circuit input
async function hashSubSaltIss(sub: string, salt: Uint8Array, iss: string): Promise<Uint8Array> {
  try {
    const encoder = new TextEncoder();
    const saltHex = uint8ArrayToHex(salt);
    const data = encoder.encode(sub + saltHex + iss);
    const combinedInput = await crypto.subtle.digest("SHA-256", data);
    return new Uint8Array(combinedInput);
  } catch (error) {
    throw new Error(`Hashing failed: ${(error as Error).message}`);
  }
}

// Hash issuer
async function hashIss(iss: string): Promise<Uint8Array> {
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(iss);
    return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  } catch (error) {
    throw new Error(`Issuer hashing failed: ${(error as Error).message}`);
  }
}

// Generate ZKP proof
async function deriveEphemeralKey(userId: string, iss: string, maxEpoch: number): Promise<any> {
  try {
    const salt = await getSaltFromSessionStorage();
    const combinedInput = await hashSubSaltIss(userId, salt, iss);
    const issHash = await hashIss(iss);
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const inputs = {
      combinedInput: BigInt("0x" + uint8ArrayToHex(combinedInput)),
      nonce: BigInt("0x" + uint8ArrayToHex(nonce)),
      maxEpoch: BigInt(maxEpoch),
      iss_hash: BigInt("0x" + uint8ArrayToHex(issHash)),
    };
    const { proof, publicSignals } = await groth16.fullProve(
      inputs,
      "/zklogin.wasm",
      "/zklogin.zkey"
    );

    const ephemeralKey = publicSignals[0]; // Ed25519 key
    return { proof, ephemeralKey, publicSignals };
  } catch (error) {
    throw new Error(`Proof generation failed: ${(error as Error).message}`);
  }
}

// Ensure all functions are available globally
if (typeof window !== 'undefined') {
  (window as any).WitnessCalculatorBuilder = WitnessCalculatorBuilder;
  (window as any).createCircomRuntimeImports = createCircomRuntimeImports;
  (window as any).snarkjs = { groth16 };

  // Expose salt management functions globally for production
  (window as any).storeSaltInSessionStorage = storeSaltInSessionStorage;
  (window as any).getSaltFromSessionStorage = getSaltFromSessionStorage;
  (window as any).deriveEphemeralKey = deriveEphemeralKey;
  (window as any).computeZkLoginIdentityHash = computeIdentityHash;

  // Expose proof encryption functions globally
  (window as any).encryptProof = encryptProof;
  (window as any).decryptProof = decryptProof;

  // Expose security utilities globally
  (window as any).setSecureCookie = setSecureCookie;
  (window as any).setCSRFToken = setCSRFToken;
  (window as any).validateCSRFToken = validateCSRFToken;
}

// ---------------------------------------------------------------------------
// Export salt management functions for dynamic imports and bundling
// ---------------------------------------------------------------------------
export {
  storeSaltInSessionStorage,
  getSaltFromSessionStorage,
  deriveEphemeralKey,
  hashSubSaltIss,
  hashIss,
  encryptProof,
  decryptProof,
  setSecureCookie,
  setCSRFToken,
  validateCSRFToken,
  computeIdentityHash
};

// ---------------------------------------------------------------------------
// Helper that builds the exact JSON expected by the SuiKeyDerivation circuit
// ---------------------------------------------------------------------------
export function buildZkLoginInputs(raw: {
  combinedInput: string;        // hash(sub || salt || iss) - computed client-side
  nonce: string;               // Random nonce
  maxEpoch: string;            // Maximum epoch (currentEpoch + 1)
  iss_hash: string;            // SHA-256 hash of issuer for provider validation
}) {
  // The new circuit expects only these 4 inputs - much simpler!
  const inputs = {
    combinedInput: raw.combinedInput,
    nonce: raw.nonce,
    maxEpoch: raw.maxEpoch,
    iss_hash: raw.iss_hash,
  };

  return inputs;
}

// ---------------------------------------------------------------------------
// Convenience wrapper that runs the full‑prove step
// ---------------------------------------------------------------------------
export async function generateProof(rawInputs: any) {
  // 1️⃣ Build the exact input JSON
  const inputs = buildZkLoginInputs(rawInputs);

  // 2️⃣ Load the compiled circuit files from the public folder
  const wasmBuffer = await fetch('/zklogin.wasm').then(r => r.arrayBuffer());
  const zkeyBuffer = await fetch('/zklogin.zkey').then(r => r.arrayBuffer());

  // 3️⃣ Run snarkjs
  const { proof, publicSignals } = await groth16.fullProve(
    inputs,
    new Uint8Array(wasmBuffer),
    new Uint8Array(zkeyBuffer)
  );

  return { proof, publicSignals };
}
