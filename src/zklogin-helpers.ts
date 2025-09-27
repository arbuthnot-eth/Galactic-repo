import { groth16 } from 'snarkjs';
import { argon2id } from '@noble/hashes/argon2';
// Import and explicitly re-export circom runtime for witness calculation
import { WitnessCalculatorBuilder, createCircomRuntimeImports } from './circom-runtime';
import { Transaction as SuiTransaction } from '@mysten/sui/transactions';
import {
  decodeJwt as sdkDecodeJwt,
  genAddressSeed as sdkGenAddressSeed,
  jwtToAddress as sdkJwtToAddress,
  hashASCIIStrToField as sdkHashASCIIStrToField,
  poseidonHash as sdkPoseidonHash
} from '@mysten/sui/zklogin';

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
          resolve();
        })
        .catch(() => {
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
const ARGON2_MEMORY_KIB = 64 * 1024; // 64 MiB
const ARGON2_TIME_COST = 3;
const ARGON2_PARALLELISM = 1;
const ARGON2_OUTPUT_LENGTH = 32;
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
    case 'apple':
      return 'https://appleid.apple.com';
    case 'facebook':
      return 'https://www.facebook.com';
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

function normalizeIssuerForZkLogin(iss: string): string {
  if (iss === 'accounts.google.com') {
    return 'https://accounts.google.com';
  }
  return iss;
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

function normalizeProofArray(values: any): any {
  if (Array.isArray(values)) {
    return values.map(item => normalizeProofArray(item));
  }

  if (typeof values === 'bigint') {
    return values.toString();
  }

  if (typeof values === 'number') {
    return values.toString();
  }

  if (typeof values === 'string') {
    return values;
  }

  if (values && typeof values === 'object' && typeof values.toString === 'function') {
    return values.toString();
  }

  throw new Error('Unsupported proof value type');
}

function base64UrlToBigIntString(segment: string): string {
  if (!segment) {
    return '0';
  }

  const paddedLength = segment.length % 4;
  const padding = paddedLength ? '='.repeat(4 - paddedLength) : '';
  const base64 = segment.replace(/-/g, '+').replace(/_/g, '/') + padding;

  let bytes: Uint8Array;
  if (typeof atob === 'function') {
    const binary = atob(base64);
    bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
  } else {
    bytes = Uint8Array.from(Buffer.from(base64, 'base64'));
  }

  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }

  if (!hex) {
    return '0';
  }

  return BigInt('0x' + hex).toString();
}

function loadJwtEntry(provider: string): JwtEntry | null {
  try {
    const key = getProviderKey(provider);
    const raw = localStorage.getItem(key);

    if (!raw) return null;
    return JSON.parse(raw) as JwtEntry;
  } catch (_error) {
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
  const saltSource = `${SALT_DERIVATION_PREFIX}::${provider}::${aud}::${claims.sub}`;
  const saltHash = await crypto.subtle.digest('SHA-256', encoder.encode(saltSource));
  const argonSalt = new Uint8Array(saltHash);
  const passwordBytes = encoder.encode(password);

  const derivedSalt = argon2id(passwordBytes, argonSalt, {
    m: ARGON2_MEMORY_KIB,
    t: ARGON2_TIME_COST,
    p: ARGON2_PARALLELISM,
    dkLen: ARGON2_OUTPUT_LENGTH,
  });

  const salt = new Uint8Array(derivedSalt);

  // Cache salt in memory
  saltMemoryCache.set(provider, salt);

  return salt;
}

async function deriveEncryptionKey(password: string, iss: string): Promise<CryptoKey> {
  validatePassword(password);

  const keySource = `galactic::encryption::${iss}`;
  const keySalt = await crypto.subtle.digest('SHA-256', encoder.encode(keySource));
  const argonSalt = new Uint8Array(keySalt);
  const passwordBytes = encoder.encode(password);

  const derivedKey = argon2id(passwordBytes, argonSalt, {
    m: ARGON2_MEMORY_KIB,
    t: ARGON2_TIME_COST,
    p: ARGON2_PARALLELISM,
    dkLen: ARGON2_OUTPUT_LENGTH,
  });

  return await crypto.subtle.importKey(
    'raw',
    derivedKey,
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

  // Use custom prompt if available, otherwise fall back to basic prompt
  if (globalPasswordPrompt) {
    return await globalPasswordPrompt(iss, 0);
  }

  // Fallback to basic browser prompt
  return new Promise((resolve, reject) => {
    const issuerName = iss === 'https://accounts.google.com' ? 'Google' : new URL(iss).hostname;
    const promptText = `Enter password for ${issuerName} zkLogin:`;

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

async function ensurePasswordKey(iss: string): Promise<CryptoKey> {
  const cached = passwordKeyCache.get(iss);
  const provider = describeIssuer(iss);
  if (cached) {
    return cached;
  }

  const providerSlug = getProviderFromIssuer(iss);

  while (true) {
    let password: string;

    try {
      password = await promptForPassword(iss);
    } catch (error: any) {
      // Bubble up cancellations immediately
      if (error?.message === 'Password prompt cancelled') {
        throw error;
      }

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

    passwordKeyCache.set(iss, key);
    saltMemoryCache.set(provider, salt);
    scheduleIdleTeardown();

    return {
      provider,
      iss,
      key,
      fromCache: true
    };
  } catch (error: any) {
    const failureMessage = error?.message || error;

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

function hexToUint8Array(hex: string): Uint8Array {
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (normalized.length % 2 !== 0) {
    throw new Error('Hex string must have an even length');
  }
  const result = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < result.length; i += 1) {
    const byte = normalized.slice(i * 2, i * 2 + 2);
    result[i] = parseInt(byte, 16);
  }
  return result;
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

// Hybrid zkLogin signature: Official Sui utils + Custom lean circuit
async function generateZkLoginSignature(
  provider: string,
  intent: {
    type: 'transaction' | 'personal_message';
    data: Uint8Array | string | SuiTransaction | undefined;
  },
  ephemeralKeyPair: any,
  randomness?: string
): Promise<{
  zkLoginSignature: any;
  address: string;
  maxEpoch: string;
  intentScope: string;
  addressSeed: string;
  intentHash: string;
  addressCommitment: string;
  zkProof: {
    proofPoints: {
      a: string[];
      b: string[][];
      c: string[];
    };
    publicSignals: {
      addressSeed: string;
      intentHash: string;
    };
  };
}> {
  const activeProvider = provider || getActiveProvider();
  if (!activeProvider) throw new Error('No active zkLogin provider');

  const decodeJwt = (window as any).SuiSDK?.ZkLogin?.decodeJwt || sdkDecodeJwt;
  const genAddressSeed = (window as any).SuiSDK?.ZkLogin?.genAddressSeed || sdkGenAddressSeed;
  const jwtToAddress = (window as any).SuiSDK?.ZkLogin?.jwtToAddress || sdkJwtToAddress;
  const hashASCIIStrToField = (window as any).SuiSDK?.ZkLogin?.hashASCIIStrToField || sdkHashASCIIStrToField;
  const poseidonHash = (window as any).SuiSDK?.ZkLogin?.poseidonHash || sdkPoseidonHash;

  // Load JWT using cached credentials
  const jwt = await loadJwt(activeProvider);
  const claims = decodeJwt(jwt);

  // Get salt using existing cache mechanism
  const salt = await getSaltForClaims(activeProvider);
  const saltHex = uint8ArrayToHex(salt);
  const saltBigInt = BigInt('0x' + saltHex);
  const BN254_FIELD_MODULUS = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
  const saltFieldElement = saltBigInt % BN254_FIELD_MODULUS;

  const audClaim = Array.isArray(claims.aud) ? claims.aud[0] : claims.aud;
  if (!audClaim || typeof audClaim !== 'string') {
    throw new Error('JWT missing aud field');
  }

  const claimNameHashField = hashASCIIStrToField('sub', 32);
  const claimValueHashField = hashASCIIStrToField(claims.sub, 115);
  const audFieldElement = hashASCIIStrToField(audClaim, 145);
  const epochWindow = 1n;

  const addressSeed = genAddressSeed(
    saltFieldElement,
    'sub',
    claims.sub,
    audClaim
  );
  const addressSeedString = addressSeed.toString();

  // Use official Sui functions for address derivation
  const zkLoginAddress = jwtToAddress(jwt, saltFieldElement, false);

  // Get current epoch
  if (!(window as any).SuiSDK?.client) {
    throw new Error('No Sui client available - ensure SDK is properly injected');
  }
  const currentEpochInfo = await (window as any).SuiSDK.client.getLatestSuiSystemState();
  const currentEpoch = Number(currentEpochInfo.epoch);
  const maxEpoch = (BigInt(currentEpoch) + epochWindow).toString();

  const transactionCtor =
    (window as any).SuiSDK?.Sui?.Transaction ||
    (window as any).SuiSDK?.Sui?.TransactionBlock;

  // Ensure transaction tier is loaded so the constructor exists
  let transactionCtorResolved = transactionCtor;

  if (!transactionCtorResolved) {
    if (typeof (window as any).SuiSDK?.loadTransaction === 'function') {
      await (window as any).SuiSDK.loadTransaction();
      transactionCtorResolved =
        (window as any).SuiSDK?.Sui?.Transaction ||
        (window as any).SuiSDK?.Sui?.TransactionBlock;
    }
  }

  if (!transactionCtorResolved) {
    transactionCtorResolved = SuiTransaction as unknown as { new (): any };

    // Backfill global reference for downstream consumers if missing
    if ((window as any).SuiSDK?.Sui && !(window as any).SuiSDK.Sui.Transaction) {
      (window as any).SuiSDK.Sui.Transaction = SuiTransaction;
    }
  }

  let signingBytes: Uint8Array;
  let userSignature: string;
  let intentScopeValue: string;

  if (intent.type === 'transaction') {
    if (typeof transactionCtorResolved !== 'function') {
      throw new Error('Transaction tier not loaded - call window.SuiSDK.loadTransaction() before generating zkLogin proofs.');
    }

    intentScopeValue = 'TransactionData';
    let txBytes: Uint8Array;

    if (intent.data instanceof transactionCtorResolved) {
      const txb = intent.data;
      if (typeof txb.setSender === 'function') {
        txb.setSender(zkLoginAddress);
      }
      txBytes = await txb.build({ client: (window as any).SuiSDK.client });
    } else if (intent.data && typeof (intent.data as SuiTransaction).build === 'function') {
      const txb = intent.data as SuiTransaction;
      if (typeof (txb as any).setSender === 'function') {
        (txb as any).setSender(zkLoginAddress);
      }
      txBytes = await txb.build({ client: (window as any).SuiSDK.client });
    } else if (intent.data instanceof Uint8Array) {
      txBytes = intent.data;
    } else if (typeof intent.data === 'string') {
      txBytes = hexToUint8Array(intent.data);
    } else {
      throw new Error('Unsupported transaction intent payload');
    }

    const transactionSignature = await ephemeralKeyPair.signTransaction(txBytes);
    userSignature = transactionSignature.signature;
    signingBytes = txBytes;
  } else {
    intentScopeValue = 'PersonalMessage';
    const messageSource = intent.data ?? 'zkLogin proof intent';
    const messageBytes = typeof messageSource === 'string'
      ? new TextEncoder().encode(messageSource)
      : messageSource;

    if (!(messageBytes instanceof Uint8Array)) {
      throw new Error('Unsupported personal message payload');
    }

    const personalMessageSignature = await ephemeralKeyPair.signPersonalMessage(messageBytes);
    userSignature = personalMessageSignature.signature;
    signingBytes = messageBytes;
  }

  // Generate proof with lean circuit
  const wasmBuffer = await fetch('/zklogin.wasm').then(r => r.arrayBuffer());
  const zkeyBuffer = await fetch('/zklogin.zkey').then(r => r.arrayBuffer());

  // Process intent and compute hash for circuit
  const intentHash = await crypto.subtle.digest('SHA-256', signingBytes);
  const intentDataBigInt = BigInt('0x' + uint8ArrayToHex(new Uint8Array(intentHash)));
  const intentDataField = intentDataBigInt % BN254_FIELD_MODULUS;

  const addressCommitmentInput = poseidonHash([
    BigInt(5),
    addressSeed
  ]).toString();

  const intentCommitmentInput = poseidonHash([
    intentDataField
  ]).toString();

  const circuitInputs = {
    claim_name_hash: claimNameHashField.toString(),
    claim_value_hash: claimValueHashField.toString(),
    aud_hash: audFieldElement.toString(),
    salt_field: saltFieldElement.toString(),
    intent_data: intentDataField.toString(),
    address_seed: addressSeedString,
    intent_hash: intentCommitmentInput
  };

  const wasmBytes = new Uint8Array(wasmBuffer);
  const zkeyBytes = new Uint8Array(zkeyBuffer);

  const { proof, publicSignals } = await groth16.fullProve(
    buildZkLoginInputs(circuitInputs),
    wasmBytes,
    zkeyBytes
  );

  if (!proof?.pi_a || !proof?.pi_b || !proof?.pi_c) {
    throw new Error('Proof generation returned incomplete proof structure');
  }

  if (!Array.isArray(proof.pi_a) || !Array.isArray(proof.pi_b) || !Array.isArray(proof.pi_c)) {
    throw new Error('Proof elements missing expected array structure');
  }

  const proofPoints = {
    a: normalizeProofArray(proof.pi_a),
    b: normalizeProofArray(proof.pi_b),
    c: normalizeProofArray(proof.pi_c),
  } as {
    a: string[];
    b: string[][];
    c: string[];
  };

  const [circuitAddressSeed, circuitIntentHash] = publicSignals ?? [];

  if (!circuitAddressSeed) {
    throw new Error('Circuit address seed missing from proof');
  }
  if (!circuitIntentHash) {
    throw new Error('Circuit intent hash missing from proof');
  }

  if (circuitAddressSeed !== addressSeedString) {
    throw new Error('Circuit address seed mismatch');
  }

  if (circuitIntentHash !== intentCommitmentInput) {
    throw new Error('Circuit intent hash mismatch');
  }

  const zkProof = {
    proofPoints,
    publicSignals: {
      addressSeed: circuitAddressSeed,
      intentHash: circuitIntentHash
    }
  };

  // Sign the transaction with ephemeral key using official Sui pattern
  const client = (window as any).SuiSDK.client;
  if (!client) {
    throw new Error('Sui client not available');
  }

  // Use official Sui getZkLoginSignature format
  const zkLoginSignature = (window as any).SuiSDK.ZkLogin.getZkLoginSignature({
    inputs: {
      proofPoints,
      issBase64Details: {
        value: jwt.split('.')[1],
        indexMod4: 0
      },
      headerBase64: jwt.split('.')[0],
      addressSeed: addressSeedString
    },
    maxEpoch: BigInt(maxEpoch),
    userSignature
  });

  return {
    zkLoginSignature,
    address: zkLoginAddress,
    maxEpoch,
    intentScope: intentScopeValue,
    addressSeed: addressSeedString,
    intentHash: circuitIntentHash,
    addressCommitment: addressCommitmentInput,
    zkProof
  };
}


// Note: Removed hashSubSaltIss and hashIss functions as they are no longer needed
// The new circuit takes sub, salt, and aud as separate inputs instead of combined hash

// Smart zkLogin flow: check cache first, then prompt for password only when needed
async function initiateSmartZkLogin(provider: string): Promise<{ needsOAuth: boolean; reason: string }> {
  const iss = getIssuerFromProvider(provider);
  const existingEntry = loadJwtEntry(provider);

  if (existingEntry) {
    try {
      // Test if cached credentials work
      await ensurePasswordKey(iss);
      return { needsOAuth: false, reason: 'Cached credentials valid' };
    } catch (error: any) {
      if (error?.message === 'Invalid password') {
        throw error; // Let user retry password
      }
      return { needsOAuth: true, reason: 'Cached credentials invalid' };
    }
  }

  return { needsOAuth: true, reason: 'No cached credentials' };
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

function getClientIdForProvider(provider: string): string {
  switch (provider.toLowerCase()) {
    case 'google':
      return '373405271144-kevesn5h18jt8grqh5cel7jcsu9si73t.apps.googleusercontent.com';
    case 'microsoft':
      throw new Error('Microsoft client ID not configured');
    default:
      throw new Error(`Unsupported provider: ${provider}`);
  }
}

function getAuthUrlForProvider(provider: string): string {
  switch (provider.toLowerCase()) {
    case 'google':
      return 'https://accounts.google.com/o/oauth2/v2/auth';
    case 'microsoft':
      return 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
    default:
      throw new Error(`Unsupported provider: ${provider}`);
  }
}

// Ensure all functions are available globally
if (typeof window !== 'undefined') {
  const globalTarget: any = window;
  globalTarget.WitnessCalculatorBuilder = WitnessCalculatorBuilder;
  globalTarget.createCircomRuntimeImports = createCircomRuntimeImports;
  globalTarget.snarkjs = { groth16 };

  const helperBindings: Record<string, unknown> = {
    initiateSmartZkLogin,
    storeVerifiedJwt,
    getSaltForClaims,
    generateZkLoginSignature,
    loadJwt,
    setPasswordPromptFunction,
    setActiveProvider,
    validatePasswordForProvider,
    clearSensitiveSessionData,
    deriveSaltFromClaims,
    getIssuerFromProvider,
    getIssuerUrl,
    getClientIdForProvider,
    getAuthUrlForProvider,
    setSecureCookie,
    setCSRFToken,
    validateCSRFToken,
    preloadZkLoginAssets,
  };

  Object.entries(helperBindings).forEach(([key, value]) => {
    globalTarget[key] = value;
  });

  const helpers = {
    ...(globalTarget.ZkLoginHelpers || {}),
    ...helperBindings,
  };
  globalTarget.ZkLoginHelpers = helpers;
  globalTarget.__zkLoginHelpersLoaded__ = true;
}

// ---------------------------------------------------------------------------
// Export simplified zkLogin functions for dynamic imports and bundling
// ---------------------------------------------------------------------------
export {
  initiateSmartZkLogin,
  storeVerifiedJwt,
  getSaltForClaims,
  generateZkLoginSignature,
  loadJwt,
  setSecureCookie,
  setCSRFToken,
  validateCSRFToken,
  deriveSaltFromClaims,
  getIssuerUrl,
  getIssuerFromProvider,
  getClientIdForProvider,
  getAuthUrlForProvider,
  setPasswordPromptFunction,
  setActiveProvider,
  clearSensitiveSessionData,
  validatePasswordForProvider
};

// ---------------------------------------------------------------------------
// Helper that builds the exact JSON expected by the SuiZkLogin circuit
// ---------------------------------------------------------------------------
export function buildZkLoginInputs(raw: {
  claim_name_hash: string;
  claim_value_hash: string;
  aud_hash: string;
  salt_field: string;
  intent_data: string;
  address_seed: string;
  intent_hash: string;
}) {
  // Lean circuit inputs matching new circuit structure
  const inputs = {
    claim_name_hash: raw.claim_name_hash,
    claim_value_hash: raw.claim_value_hash,
    aud_hash: raw.aud_hash,
    salt_field: raw.salt_field,
    intent_data: raw.intent_data,
    address_seed: raw.address_seed,
    intent_hash: raw.intent_hash,
  };

  return inputs;
}
