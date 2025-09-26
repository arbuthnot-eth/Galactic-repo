import { groth16 } from 'snarkjs';
// Import and explicitly re-export circom runtime for witness calculation
import { WitnessCalculatorBuilder, createCircomRuntimeImports } from './circom-runtime';

declare global {
  interface Window {
    ZkLoginHelpers?: {
      preloadZkLoginAssets?: () => Promise<void>;
    };
  }
}

let zkLoginAssetsPrefetch: Promise<void> | null = null;

export function preloadZkLoginAssets(): Promise<void> {
  if (typeof window === 'undefined') {
    return Promise.resolve();
  }

  if (zkLoginAssetsPrefetch) {
    return zkLoginAssetsPrefetch;
  }

  const idle = (window as any).requestIdleCallback || ((cb: Function) => setTimeout(cb, 2000));

  zkLoginAssetsPrefetch = new Promise<void>((resolve) => {
    idle(() => {
      Promise.all([
        fetch('/zklogin.wasm').then((response) => response.arrayBuffer()),
        fetch('/zklogin.zkey').then((response) => response.arrayBuffer()),
      ])
        .then(() => {
          console.info('⚡ zk-login assets pre-loaded');
          resolve();
        })
        .catch((error) => {
          console.warn('⚡ zk-login pre-load failed', error);
          resolve();
        });
    });
  });

  return zkLoginAssetsPrefetch;
}

// ---------------------------------------------------------------------------
// Shared security constants, helpers, and in-memory caches
// ---------------------------------------------------------------------------

const ZKLOGIN_PREFIX = 'galactic:zkLogin';
const ACTIVE_IDENTITY_KEY = `${ZKLOGIN_PREFIX}:activeIssuer`;
const IDLE_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes
const PBKDF2_ITERATIONS = 210_000;
const PBKDF2_DIGEST = 'SHA-256';
const SALT_DERIVATION_PREFIX = 'galactic::salt';

type JwtClaims = {
  sub: string;
  iss: string;
  aud: string | string[];
  exp: number;
  nonce?: string;
};

type ClaimsEntry = {
  encryptedClaims: string;
  claimsIv: string;
};

const passwordKeyCache = new Map<string, CryptoKey>();
const passwordRetryCount = new Map<string, number>();
const passwordCooldownUntil = new Map<string, number>();
let idleTimeoutHandle: number | null = null;
let idleListenersRegistered = false;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function getIssuerKey(iss: string): string {
  return `${ZKLOGIN_PREFIX}:${iss}`;
}

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

function loadClaimsEntry(iss: string): ClaimsEntry | null {
  try {
    const key = getIssuerKey(iss);
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    return JSON.parse(raw) as ClaimsEntry;
  } catch (error) {
    console.warn(`Failed to parse claims entry for ${iss}. Removing.`, error);
    localStorage.removeItem(getIssuerKey(iss));
    return null;
  }
}

function saveClaimsEntry(iss: string, entry: ClaimsEntry) {
  const key = getIssuerKey(iss);
  localStorage.setItem(key, JSON.stringify(entry));
}

function getActiveIssuer(): string | null {
  return localStorage.getItem(ACTIVE_IDENTITY_KEY);
}

function setActiveIssuer(iss: string) {
  localStorage.setItem(ACTIVE_IDENTITY_KEY, iss);
}

function clearSensitiveSessionData() {
  passwordKeyCache.clear();
  localStorage.removeItem(ACTIVE_IDENTITY_KEY);
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

async function deriveSaltFromClaims(password: string, claims: JwtClaims): Promise<Uint8Array> {
  const aud = normalizeAudienceClaim(claims.aud);
  const saltSource = `${SALT_DERIVATION_PREFIX}::${claims.iss}::${claims.sub}::${aud}`;
  const saltHash = await crypto.subtle.digest('SHA-256', encoder.encode(saltSource));

  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt: saltHash,
    iterations: PBKDF2_ITERATIONS,
    hash: PBKDF2_DIGEST
  }, passwordKey, 256);

  return new Uint8Array(derivedBits);
}

async function deriveEncryptionKey(password: string, iss: string): Promise<CryptoKey> {
  validatePassword(password);

  const keySource = `galactic::encryption::${iss}`;
  const keySalt = await crypto.subtle.digest('SHA-256', encoder.encode(keySource));

  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    salt: keySalt,
    iterations: PBKDF2_ITERATIONS,
    hash: PBKDF2_DIGEST
  }, passwordKey, 256);

  return await crypto.subtle.importKey(
    'raw',
    derivedBits,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
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

async function promptForPassword(iss: string): Promise<string> {
  // Check cooldown
  const cooldownEnd = passwordCooldownUntil.get(iss) || 0;
  if (Date.now() < cooldownEnd) {
    const remainingSeconds = Math.ceil((cooldownEnd - Date.now()) / 1000);
    throw new Error(`Too many failed attempts. Try again in ${remainingSeconds} seconds.`);
  }

  return new Promise((resolve, reject) => {
    const issuerName = iss === 'https://accounts.google.com' ? 'Google' : new URL(iss).hostname;
    const retryCount = passwordRetryCount.get(iss) || 0;
    const promptText = retryCount > 0
      ? `Invalid password (${retryCount}/5 attempts). Enter password for ${issuerName} zkLogin:`
      : `Enter password for ${issuerName} zkLogin:`;

    const password = prompt(promptText);
    if (password === null) {
      reject(new Error('Password prompt cancelled'));
    } else if (password.length < 8) {
      reject(new Error('Password must be at least 8 characters'));
    } else {
      resolve(password);
    }
  });
}

function handlePasswordFailure(iss: string): void {
  const currentCount = (passwordRetryCount.get(iss) || 0) + 1;
  passwordRetryCount.set(iss, currentCount);

  if (currentCount >= 5) {
    // 5 second cooldown
    passwordCooldownUntil.set(iss, Date.now() + 5000);
    passwordRetryCount.delete(iss);
  }
}

function handlePasswordSuccess(iss: string): void {
  passwordRetryCount.delete(iss);
  passwordCooldownUntil.delete(iss);
}

async function ensurePasswordKey(iss: string): Promise<CryptoKey> {
  const cached = passwordKeyCache.get(iss);
  if (cached) return cached;

  const password = await promptForPassword(iss);
  const key = await deriveEncryptionKey(password, iss);

  try {
    const entry = loadClaimsEntry(iss);
    if (entry) {
      await decryptWithKey(key, entry.encryptedClaims, entry.claimsIv);
    }
    handlePasswordSuccess(iss);
    passwordKeyCache.set(iss, key);
    scheduleIdleTeardown();
    return key;
  } catch (error) {
    handlePasswordFailure(iss);
    throw new Error('Invalid password');
  }
}

async function storeClaims(password: string, claims: JwtClaims): Promise<void> {
  validatePassword(password);

  const key = await deriveEncryptionKey(password, claims.iss);
  const payload = encoder.encode(JSON.stringify(claims));
  const { ciphertext, iv } = await encryptWithKey(key, payload);

  const entry: ClaimsEntry = {
    encryptedClaims: ciphertext,
    claimsIv: iv
  };

  saveClaimsEntry(claims.iss, entry);
  passwordKeyCache.set(claims.iss, key);
  setActiveIssuer(claims.iss);
  scheduleIdleTeardown();
}

async function loadClaims(iss: string, password?: string): Promise<JwtClaims> {
  const entry = loadClaimsEntry(iss);
  if (!entry) {
    throw new Error('No stored claims for this issuer');
  }

  let key: CryptoKey;
  if (password) {
    key = await deriveEncryptionKey(password, iss);
  } else {
    key = await ensurePasswordKey(iss);
  }

  const decrypted = await decryptWithKey(key, entry.encryptedClaims, entry.claimsIv);
  return JSON.parse(decoder.decode(decrypted));
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

// Store verified JWT claims with password protection
async function storeVerifiedClaims(password: string, claims: JwtClaims): Promise<string> {
  await storeClaims(password, claims);
  return claims.iss;
}

// Get salt derived from stored claims
async function getSaltForClaims(iss?: string): Promise<Uint8Array> {
  const activeIss = iss || getActiveIssuer();
  if (!activeIss) throw new Error('No active zkLogin issuer');

  const claims = await loadClaims(activeIss);
  const password = await promptForPassword(activeIss);

  return await deriveSaltFromClaims(password, claims);
}

// ---------------------------------------------------------------------------
// Simplified Proof Generation Functions
// ---------------------------------------------------------------------------

// Generate fresh proof using stored claims
async function generateFreshProof(iss?: string): Promise<{ proof: any; publicSignals: any }> {
  const activeIss = iss || getActiveIssuer();
  if (!activeIss) throw new Error('No active zkLogin issuer');

  const claims = await loadClaims(activeIss);
  const password = await promptForPassword(activeIss);
  const salt = await deriveSaltFromClaims(password, claims);

  const combinedInput = await hashSubSaltIss(claims.sub, salt, claims.iss);
  const issHash = await hashIss(claims.iss);
  const nonce = crypto.getRandomValues(new Uint8Array(32));

  // Get current epoch for maxEpoch
  const currentEpoch = await getCurrentEpoch();

  const inputs = {
    combinedInput: BigInt('0x' + uint8ArrayToHex(combinedInput)),
    nonce: BigInt('0x' + uint8ArrayToHex(nonce)),
    maxEpoch: BigInt(currentEpoch + 1),
    iss_hash: BigInt('0x' + uint8ArrayToHex(issHash))
  };

  const { proof, publicSignals } = await generateProof(inputs);
  return { proof, publicSignals };
}

// Placeholder for getting current epoch from Sui network
async function getCurrentEpoch(): Promise<number> {
  // TODO: Implement actual epoch fetching from Sui network
  return Math.floor(Date.now() / (24 * 60 * 60 * 1000)); // Daily epoch for now
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

// Smart zkLogin flow: try cached claims first, fallback to OAuth
async function initiateSmartZkLogin(provider: string): Promise<{ proof: any; publicSignals: any; fromCache: boolean }> {
  const iss = getIssuerUrl(provider);
  const existingEntry = loadClaimsEntry(iss);

  if (existingEntry) {
    try {
      console.log(`✅ Found cached ${provider} identity, prompting for password...`);
      const claims = await loadClaims(iss);
      const { proof, publicSignals } = await generateFreshProof(iss);
      return { proof, publicSignals, fromCache: true };
    } catch (error) {
      if (error.message.includes('Too many failed attempts')) {
        throw error; // Don't fallback during cooldown
      }
      if (error.message === 'Invalid password') {
        throw error; // Let user retry password
      }
      console.warn(`⚠️ Failed to use cached ${provider} identity:`, error.message);
    }
  }

  console.log(`🌐 No cached ${provider} identity found, initiating OAuth...`);
  throw new Error(`OAUTH_REQUIRED:${provider}`);
}

function getIssuerUrl(provider: string): string {
  switch (provider.toLowerCase()) {
    case 'google':
      return 'https://accounts.google.com';
    case 'microsoft':
      return 'https://login.microsoftonline.com';
    default:
      throw new Error(`Unsupported provider: ${provider}`);
  }
}

// Legacy function - now redirects to generateFreshProof
async function deriveEphemeralKey(userId: string, iss: string, maxEpoch: number): Promise<any> {
  const claims = await loadClaims(iss);

  if (claims.sub !== userId) {
    throw new Error('User ID mismatch with stored claims');
  }

  const { proof, publicSignals } = await generateFreshProof(iss);
  const ephemeralKey = publicSignals[0]; // Ed25519 key
  return { proof, ephemeralKey, publicSignals };
}

// Ensure all functions are available globally
if (typeof window !== 'undefined') {
  (window as any).WitnessCalculatorBuilder = WitnessCalculatorBuilder;
  (window as any).createCircomRuntimeImports = createCircomRuntimeImports;
  (window as any).snarkjs = { groth16 };

  // Expose simplified zkLogin functions globally
  (window as any).initiateSmartZkLogin = initiateSmartZkLogin;
  (window as any).storeVerifiedClaims = storeVerifiedClaims;
  (window as any).getSaltForClaims = getSaltForClaims;
  (window as any).generateFreshProof = generateFreshProof;
  (window as any).deriveEphemeralKey = deriveEphemeralKey;
  (window as any).loadClaims = loadClaims;

  // Expose security utilities globally
  (window as any).setSecureCookie = setSecureCookie;
  (window as any).setCSRFToken = setCSRFToken;
  (window as any).validateCSRFToken = validateCSRFToken;
}

// ---------------------------------------------------------------------------
// Export simplified zkLogin functions for dynamic imports and bundling
// ---------------------------------------------------------------------------
export {
  initiateSmartZkLogin,
  storeVerifiedClaims,
  getSaltForClaims,
  generateFreshProof,
  deriveEphemeralKey,
  loadClaims,
  hashSubSaltIss,
  hashIss,
  setSecureCookie,
  setCSRFToken,
  validateCSRFToken,
  deriveSaltFromClaims,
  getIssuerUrl
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

if (typeof window !== 'undefined') {
  window.ZkLoginHelpers = {
    ...(window.ZkLoginHelpers ?? {}),
    preloadZkLoginAssets,
  };
}
