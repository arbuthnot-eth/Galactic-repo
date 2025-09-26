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

type JwtEntry = {
  encryptedJwt: string;
  jwtIv: string;
};

type PasswordValidationResult = {
  provider: string;
  iss: string;
  key: CryptoKey;
  fromCache: boolean;
};

type PasswordValidationOptions = {
  requireExistingEntry?: boolean;
};

const passwordKeyCache = new Map<string, CryptoKey>();
const saltMemoryCache = new Map<string, Uint8Array>();
const passwordRetryCount = new Map<string, number>();
const passwordCooldownUntil = new Map<string, number>();
let idleTimeoutHandle: number | null = null;
let idleListenersRegistered = false;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function getProviderKey(provider: string): string {
  return `${ZKLOGIN_PREFIX}:${provider}`;
}

function getIssuerFromProvider(provider: string): string {
  switch (provider.toLowerCase()) {
    case 'google':
      return 'https://accounts.google.com';
    case 'microsoft':
      return 'https://login.microsoftonline.com';
    default:
      throw new Error(`Unknown provider: ${provider}`);
  }
}

function getProviderFromIssuer(iss: string): string {
  switch (iss) {
    case 'https://accounts.google.com':
      return 'google';
    case 'https://login.microsoftonline.com':
      return 'microsoft';
    default:
      throw new Error(`Unknown issuer: ${iss}`);
  }
}

function describeIssuer(iss: string): string {
  try {
    return getProviderFromIssuer(iss);
  } catch {
    try {
      return new URL(iss).hostname;
    } catch {
      return iss;
    }
  }
}

// JWT parsing is handled by parseJWT function in smartwallet-dev.html

function normalizeAudienceClaim(aud: unknown): string {
  if (Array.isArray(aud)) {
    return aud.map(item => String(item)).sort().join(' ');
  }
  if (typeof aud === 'string') {
    return aud;
  }
  return '';
}

// Removed unused sha256Bytes function

// Base64 utilities for encryption/decryption
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const binary = String.fromCharCode(...new Uint8Array(buffer));
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function loadJwtEntry(provider: string): JwtEntry | null {
  try {
    const key = getProviderKey(provider);
    const raw = localStorage.getItem(key);

    if (!raw) return null;
    return JSON.parse(raw) as JwtEntry;
  } catch (error) {
    console.warn(`Failed to parse JWT entry for ${provider}. Removing.`, error);
    localStorage.removeItem(getProviderKey(provider));
    return null;
  }
}

function saveJwtEntry(provider: string, entry: JwtEntry) {
  const key = getProviderKey(provider);
  localStorage.setItem(key, JSON.stringify(entry));
}

function getActiveProvider(): string | null {
  return localStorage.getItem(ACTIVE_IDENTITY_KEY);
}

function setActiveProvider(provider: string) {
  localStorage.setItem(ACTIVE_IDENTITY_KEY, provider);
}


// Removed unused getActiveIssuer function (replaced by getActiveProvider)

function clearSensitiveSessionData() {
  passwordKeyCache.clear();
  saltMemoryCache.clear();
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


async function deriveSaltFromClaims(password: string, claims: JwtClaims): Promise<Uint8Array> {
  // Check for cached salt by provider first
  const provider = getProviderFromIssuer(claims.iss);
  const cachedSalt = saltMemoryCache.get(provider);
  if (cachedSalt) {
    return cachedSalt;
  }

  // Derive salt from password and claims
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

  const salt = new Uint8Array(derivedBits);

  // Cache salt in memory
  saltMemoryCache.set(provider, salt);

  return salt;
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

// Global password prompt function that can be overridden
let globalPasswordPrompt: ((iss: string, attempts: number) => Promise<string>) | null = null;

function setPasswordPromptFunction(fn: (iss: string, attempts: number) => Promise<string>) {
  globalPasswordPrompt = fn;
}

async function promptForPassword(iss: string): Promise<string> {
  // Check cooldown
  const cooldownEnd = passwordCooldownUntil.get(iss) || 0;
  if (Date.now() < cooldownEnd) {
    const remainingSeconds = Math.ceil((cooldownEnd - Date.now()) / 1000);
    throw new Error(`Too many failed attempts. Try again in ${remainingSeconds} seconds.`);
  }

  const retryCount = passwordRetryCount.get(iss) || 0;

  console.log(`🔑 PASSWORD PROMPT #${retryCount + 1} for ${describeIssuer(iss)}`);

  // Use custom prompt if available, otherwise fall back to basic prompt
  if (globalPasswordPrompt) {
    return await globalPasswordPrompt(iss, retryCount);
  }

  // Fallback to basic browser prompt
  return new Promise((resolve, reject) => {
    const issuerName = iss === 'https://accounts.google.com' ? 'Google' : new URL(iss).hostname;
    const promptText = retryCount > 0
      ? `Invalid password (${retryCount}/5 attempts). Enter password for ${issuerName} zkLogin:`
      : `Enter password for ${issuerName} zkLogin:`;

    const password = prompt(promptText);
    if (password === null) {
      console.log(`🔑 Password prompt cancelled for ${describeIssuer(iss)}`);
      reject(new Error('Password prompt cancelled'));
    } else if (password.length < 8) {
      console.log(`🔑 Password too short provided in prompt for ${describeIssuer(iss)}`);
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
  const provider = describeIssuer(iss);
  if (cached) {
    console.log(`🔑 Using CACHED password key for ${provider}`);
    return cached;
  }

  console.log(`🔑 No cached key for ${provider}, prompting for password...`);
  const providerSlug = getProviderFromIssuer(iss);

  while (true) {
    let password: string;

    try {
      password = await promptForPassword(iss);
    } catch (error: any) {
      // Bubble up cancellations or cooldown errors immediately
      if (error?.message === 'Password prompt cancelled' || error?.message?.includes('Too many failed attempts')) {
        throw error;
      }

      handlePasswordFailure(iss);
      console.warn(`🔑 Password prompt error for ${provider}:`, error?.message || error);
      continue;
    }

    try {
      const { key } = await validatePasswordForProvider(providerSlug, password, { requireExistingEntry: true });
      return key;
    } catch (error: any) {
      if (error?.message === 'NO_CACHED_JWT') {
        throw new Error(`No stored JWT for provider: ${providerSlug}`);
      }

      if (error?.message === 'Invalid password') {
        console.warn(`🔑 Invalid password for ${provider}, retrying...`);
        continue;
      }

      throw error;
    }
  }
}

async function validatePasswordForProvider(provider: string, password: string, options: PasswordValidationOptions = {}): Promise<PasswordValidationResult> {
  const { requireExistingEntry = false } = options;
  const iss = getIssuerFromProvider(provider);

  const key = await deriveEncryptionKey(password, iss);
  const entry = loadJwtEntry(provider);
  if (!entry) {
    if (requireExistingEntry) {
      throw new Error('NO_CACHED_JWT');
    }

    handlePasswordSuccess(iss);
    console.log(`🔑 Accepted password for ${provider} (no cached JWT to validate yet)`);
    return {
      provider,
      iss,
      key,
      fromCache: false
    };
  }

  try {
    const decryptedJwt = await decryptWithKey(key, entry.encryptedJwt, entry.jwtIv);
    const jwtText = decoder.decode(decryptedJwt);
    const claims = (window as any).SuiSDK.ZkLogin.decodeJwt(jwtText);
    const salt = await deriveSaltFromClaims(password, claims);

    handlePasswordSuccess(iss);
    passwordKeyCache.set(iss, key);
    saltMemoryCache.set(provider, salt);
    scheduleIdleTeardown();
    console.log(`🔑 Password validated and caches primed for ${provider}`);

    return {
      provider,
      iss,
      key,
      fromCache: true
    };
  } catch (error: any) {
    handlePasswordFailure(iss);
    const failureMessage = error?.message || error;
    console.warn(`🔑 Password validation failed for ${provider}:`, failureMessage);

    if (error?.name === 'OperationError' || (typeof failureMessage === 'string' && failureMessage.includes('decrypt'))) {
      throw new Error('Invalid password');
    }

    if (failureMessage === 'Invalid password') {
      throw new Error('Invalid password');
    }

    throw new Error('Password validation failed. Please try again.');
  }
}

async function storeJwt(password: string, jwt: string, provider: string): Promise<void> {
  validatePassword(password);

  const iss = getIssuerFromProvider(provider);
  const key = await deriveEncryptionKey(password, iss);
  const payload = encoder.encode(jwt);
  const { ciphertext, iv } = await encryptWithKey(key, payload);

  const entry: JwtEntry = {
    encryptedJwt: ciphertext,
    jwtIv: iv
  };

  saveJwtEntry(provider, entry);
  passwordKeyCache.set(iss, key);
  setActiveProvider(provider);
  scheduleIdleTeardown();
}

async function loadJwt(provider: string, password?: string): Promise<string> {
  const entry = loadJwtEntry(provider);
  if (!entry) {
    throw new Error(`No stored JWT for provider: ${provider}`);
  }

  const iss = getIssuerFromProvider(provider);
  let key: CryptoKey;
  if (password) {
    key = await deriveEncryptionKey(password, iss);
  } else {
    key = await ensurePasswordKey(iss);
  }

  try {
    const decrypted = await decryptWithKey(key, entry.encryptedJwt, entry.jwtIv);
    return decoder.decode(decrypted);
  } catch (error: any) {
    // If decryption fails, it's likely due to wrong password
    if (error?.name === 'OperationError' || error?.message?.includes('decrypt')) {
      throw new Error('Invalid password');
    }
    throw error;
  }
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
    throw new Error('Password must be at least 8 characters');
  }
}

// Convert Uint8Array to hex string (browser-compatible)
function uint8ArrayToHex(uint8Array: Uint8Array): string {
  return Array.from(uint8Array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Base64 functions defined above - no duplicates needed

// Store verified JWT with password protection
async function storeVerifiedJwt(password: string, jwt: string): Promise<string> {
  // Use official Sui SDK to decode JWT (note: this will need proper typing in production)
  const decoded = (window as any).SuiSDK.ZkLogin.decodeJwt(jwt);
  const provider = getProviderFromIssuer(decoded.iss);

  await storeJwt(password, jwt, provider);
  return provider;
}

// Get salt - use cached salt from memory if available
async function getSaltForClaims(provider?: string): Promise<Uint8Array> {
  const activeProvider = provider || getActiveProvider();
  if (!activeProvider) throw new Error('No active zkLogin provider');

  // Check memory cache first
  const cachedSalt = saltMemoryCache.get(activeProvider);
  if (cachedSalt) {
    return cachedSalt;
  }

  // Fallback: derive salt (this should rarely happen if caching works)
  const jwt = await loadJwt(activeProvider);
  const decoded = (window as any).SuiSDK.ZkLogin.decodeJwt(jwt);
  const password = await promptForPassword(decoded.iss);

  const salt = await deriveSaltFromClaims(password, decoded);
  saltMemoryCache.set(activeProvider, salt); // Cache for next time
  return salt;
}

// ---------------------------------------------------------------------------
// Simplified Proof Generation Functions
// ---------------------------------------------------------------------------

// Generate fresh proof using stored JWT
async function generateFreshProof(provider?: string): Promise<{ proof: any; publicSignals: any }> {
  const activeProvider = provider || getActiveProvider();
  if (!activeProvider) throw new Error('No active zkLogin provider');

  // Load JWT - this should use cached password key if available
  const jwt = await loadJwt(activeProvider);
  const claims = (window as any).SuiSDK.ZkLogin.decodeJwt(jwt);

  // Get salt - either from cache or derive with password prompt
  const salt = await getSaltForClaims(activeProvider);

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

// Smart zkLogin flow: check cache first, then prompt for password only when needed
async function initiateSmartZkLogin(provider: string): Promise<{ proof: any; publicSignals: any; fromCache: boolean }> {
  console.log(`🔑 ENTRY: initiateSmartZkLogin() called for ${provider}`);

  const iss = getIssuerFromProvider(provider);

  const existingEntry = loadJwtEntry(provider);

  if (existingEntry) {
    // Cache exists - use retry mechanism like ensurePasswordKey
    console.log(`🔐 Found cached ${provider} identity, prompting for password...`);
    try {
      // Use ensurePasswordKey which has built-in retry logic
      const key = await ensurePasswordKey(iss);
      console.log(`🔑 Password validated and key cached for ${provider}`);

      // Load and decrypt JWT using the validated password key
      console.log(`🔑 Loading JWT with validated password key...`);
      const jwt = await loadJwt(provider); // Use cached key, no password needed
      const decoded = (window as any).SuiSDK.ZkLogin.decodeJwt(jwt);

      // Derive and cache salt at the same time since we have validated key + claims
      console.log(`🔑 Deriving and caching salt...`);
      const salt = await getSaltForClaims(provider);

      console.log(`🔑 Generating proof with cached data...`);
      const { proof, publicSignals } = await generateFreshProof(provider);
      return { proof, publicSignals, fromCache: true };
    } catch (error: any) {
      if (error?.message?.includes('Too many failed attempts')) {
        throw error; // Don't fallback during cooldown
      }
      if (error?.message === 'Invalid password') {
        throw error; // Let user retry password
      }
      console.warn(`⚠️ Failed to use cached ${provider} identity:`, error?.message);
      // Continue to OAuth fallback
    }
  }

  // No cache exists or cache failed - need OAuth
  console.log(`🌐 No cached ${provider} identity found, will need OAuth...`);
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

// Ensure all functions are available globally
if (typeof window !== 'undefined') {
  (window as any).WitnessCalculatorBuilder = WitnessCalculatorBuilder;
  (window as any).createCircomRuntimeImports = createCircomRuntimeImports;
  (window as any).snarkjs = { groth16 };

  // Expose simplified zkLogin functions globally
  (window as any).initiateSmartZkLogin = initiateSmartZkLogin;
  (window as any).storeVerifiedJwt = storeVerifiedJwt;
  (window as any).getSaltForClaims = getSaltForClaims;
  (window as any).generateFreshProof = generateFreshProof;
  (window as any).loadJwt = loadJwt;

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
  storeVerifiedJwt,
  getSaltForClaims,
  generateFreshProof,
  loadJwt,
  hashSubSaltIss,
  hashIss,
  setSecureCookie,
  setCSRFToken,
  validateCSRFToken,
  deriveSaltFromClaims,
  getIssuerUrl,
  setPasswordPromptFunction,
  clearSensitiveSessionData,
  validatePasswordForProvider
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
