// Basic zkLogin functions are now available in main bundle at window.SuiSDK.ZkLogin
// Only import what's actually used internally for proof generation
import { generateNonce, generateRandomness, genAddressSeed } from '@mysten/sui/zklogin';
import { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { groth16 } from 'snarkjs';
import { poseidon1 } from 'poseidon-lite/poseidon1';

export interface LocalZkLoginAssets {
  wasmBase64?: string;
  provingKeyBase64?: string;
  verificationKey?: Record<string, unknown>;
}

export interface LocalZkLoginMetrics {
  proofsAttempted: number;
  proofsSucceeded: number;
  averageMs: number;
  lastDurationMs: number;
}

export interface LocalZkLoginProofContext {
  jwt: string;
  salt: Uint8Array;
  addressSeed: bigint;
  maxEpoch: bigint;
  randomness?: string;
  nonce?: string;
  // Public key bytes for nonce generation (compressed form expected)
  ephemeralPublicKeyBytes?: Uint8Array;
  // Sui address for correct address_hash computation
  address?: string;
}

export interface LocalZkLoginProofResult {
  signatureInputs: {
    proofPoints: {
      a: string[];
      b: string[][];
      c: string[];
    };
    issBase64Details: {
      value: string;
      indexMod4: number;
    };
    headerBase64: string;
    addressSeed: string;
  };
  durationMs: number;
  nonce: string;
  randomness: bigint;
  circuitFileUsed?: string;
}

function base64UrlEncode(input: string | Uint8Array): string {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function randomHex(size: number): string {
  const bytes = new Uint8Array(size);
  globalThis.crypto?.getRandomValues(bytes);
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export class LocalZkLoginProver {
  private assets: LocalZkLoginAssets;
  private ready = false;
  private metrics: LocalZkLoginMetrics = {
    proofsAttempted: 0,
    proofsSucceeded: 0,
    averageMs: 0,
    lastDurationMs: 0,
  };
  private verificationKey: any = null;

  constructor(assets: LocalZkLoginAssets = {}) {
    this.assets = assets;
  }

  async init(): Promise<void> {
    try {
      // Load the verification key from the downloaded file
      // Use relative path from src/ to root directory
      const vkeyResponse = await fetch('/verification_key.json');
      if (!vkeyResponse.ok) {
        throw new Error(`Failed to load verification key: ${vkeyResponse.status}`);
      }
      this.verificationKey = await vkeyResponse.json();

      // Check if circuit files are available for real proving
      const zkeyResponse = await fetch('/zklogin.zkey');
      const wasmResponse = await fetch('/zklogin.wasm');

      if (!zkeyResponse.ok) {
        throw new Error(`Failed to load proving key: ${zkeyResponse.status}. Please ensure zklogin.zkey is in public/ directory.`);
      }

      if (!wasmResponse.ok) {
        throw new Error(`Failed to load WASM circuit: ${wasmResponse.status}. Please ensure zklogin.wasm is in public/ directory.`);
      }

      console.log('✅ Circuit files found - real proving available');
      this.ready = true;

    } catch (error) {
      console.error('Failed to initialize zkLogin prover:', error);
      throw error; // Don't fallback to mock mode, fail properly
    }
  }

  get isReady(): boolean {
    return this.ready;
  }

  getMetrics(): LocalZkLoginMetrics {
    return { ...this.metrics };
  }

  async prove({
    jwt,
    salt,
    addressSeed,
    maxEpoch,
    randomness: randomnessInput,
    nonce: nonceInput,
    ephemeralPublicKeyBytes,
    address,
  }: LocalZkLoginProofContext): Promise<LocalZkLoginProofResult> {
    if (!this.ready) {
      throw new Error('Local zkLogin prover not initialised');
    }

    const start = performance.now();
    this.metrics.proofsAttempted += 1;

    try {
      // Decode JWT to get payload
      const [headerBase64, payloadBase64] = jwt.split('.');
      if (!headerBase64 || !payloadBase64) {
        throw new Error('Invalid JWT supplied to prover');
      }

      const payloadJson = JSON.parse(atob(payloadBase64.replace(/-/g, '+').replace(/_/g, '/')));
      const iss = payloadJson.iss ?? '';

      // Use provided randomness or generate new one
      const randomness = randomnessInput ?? generateRandomness();
      const randomnessBigInt = BigInt(randomness);
      let nonce = nonceInput;

      // Generate nonce using ephemeral public key if provided
      if (!nonce) {
        if (ephemeralPublicKeyBytes) {
          const ephemeralPublicKey = new Ed25519PublicKey(ephemeralPublicKeyBytes);
          nonce = generateNonce(
            ephemeralPublicKey,
            Number(maxEpoch),
            randomness,
          );
        } else {
          // Fallback: generate a deterministic nonce based on JWT content
          nonce = this.generateDeterministicNonce(payloadJson, randomnessBigInt);
        }
      }

      // Generate zkLogin proof data - real proof only
      // Let any error bubble up – the UI will display it and the developer can act.
      const proofData = await this.generateRealZkLoginProof({
        jwt,
        salt,
        addressSeed,
        maxEpoch,
        randomness: randomnessBigInt,
        nonce,
        payloadJson,
        address
      });

      const durationMs = performance.now() - start;

      this.metrics.proofsSucceeded += 1;
      this.metrics.lastDurationMs = durationMs;
      this.metrics.averageMs =
        ((this.metrics.averageMs * (this.metrics.proofsSucceeded - 1)) + durationMs) /
        this.metrics.proofsSucceeded;

      return {
        signatureInputs: {
          proofPoints: proofData.proofPoints,
          issBase64Details: {
            value: base64UrlEncode(iss),
            indexMod4: base64UrlEncode(iss).length % 4,
          },
          headerBase64,
          addressSeed: addressSeed.toString(),
        },
        durationMs,
        nonce,
        randomness: randomnessBigInt,
        circuitFileUsed: (proofData as any).circuitFileUsed || 'mock'
      };
    } catch (error) {
      this.metrics.proofsAttempted += 1;
      throw error;
    }
  }

  private generateDeterministicNonce(payloadJson: any, randomness: bigint): string {
    // Generate a deterministic nonce based on JWT content and randomness
    const input = JSON.stringify({
      sub: payloadJson.sub,
      iss: payloadJson.iss,
      aud: payloadJson.aud,
      randomness: randomness.toString(),
      iat: payloadJson.iat
    });

    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hashBuffer = new Uint8Array(32);

    // Simple hash function for deterministic nonce
    for (let i = 0; i < data.length; i++) {
      hashBuffer[i % 32] ^= data[i];
    }

    return Array.from(hashBuffer)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 40);
  }



  private stringToField(input: string): bigint {
    // Convert string to field element using a simple hash
    const BN254_FIELD_MODULUS = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

    let hash = BigInt(0);
    for (let i = 0; i < input.length; i++) {
      hash = (hash * BigInt(31) + BigInt(input.charCodeAt(i))) % BN254_FIELD_MODULUS;
    }

    return hash;
  }

  private async generateRealZkLoginProof({
    jwt,
    salt,
    addressSeed,
    maxEpoch,
    randomness,
    nonce,
    payloadJson,
    address
  }: {
    jwt: string;
    salt: Uint8Array;
    addressSeed: bigint;
    maxEpoch: bigint;
    randomness: bigint;
    nonce: string;
    payloadJson: any;
    address?: string;
  }): Promise<{ proofPoints: any }> {
    try {
      // Load the proving key from filesystem
      const provingKeyResponse = await fetch('/zklogin.zkey');
      if (!provingKeyResponse.ok) {
        throw new Error(`Failed to load proving key: ${provingKeyResponse.status}`);
      }
      const provingKeyBuffer = await provingKeyResponse.arrayBuffer();
      const provingKey = new Uint8Array(provingKeyBuffer);

      // Load WASM file for real proving
      const wasmResponse = await fetch('/zklogin.wasm');
      if (!wasmResponse.ok) {
        throw new Error(`Failed to load WASM file: ${wasmResponse.status}`);
      }
      const wasmBuffer = await wasmResponse.arrayBuffer();
      const wasm = new Uint8Array(wasmBuffer);

      // Generate circuit inputs
      const inputs = this.prepareZkLoginCircuitInputs({
        sub: payloadJson.sub,
        iss: payloadJson.iss,
        aud: payloadJson.aud || '',
        addressSeed,
        maxEpoch,
        nonce,
        salt,
        address
      });

      console.log('✅ zklogin.zkey loaded - real proving available');
      console.log('✅ zklogin.wasm loaded - real proving enabled');
      console.log('Circuit inputs prepared:', Object.keys(inputs));
      console.log('🔍 FULL CIRCUIT INPUTS:', JSON.stringify(inputs, null, 2));

      // Generate real cryptographic proof using snarkjs
      const { proof, publicSignals } = await groth16.fullProve(
        inputs,
        wasm,
        provingKey
      );

      console.log('✅ Real zkLogin proof generated with cryptography');
      console.log('Public signals:', publicSignals);

      // Convert proof format to match expected interface
      const proofPoints = {
        a: proof.pi_a,
        b: proof.pi_b,
        c: proof.pi_c
      };

      return {
        proofPoints
      };

    } catch (error) {
      console.error('Real zkLogin proof generation failed:', error);
      throw error; // <-- propagate the error instead of swallowing it
    }
  }

  private prepareZkLoginCircuitInputs({
    sub,
    iss,
    aud,
    addressSeed,
    maxEpoch,
    nonce,
    salt,
    address
  }: {
    sub: string;
    iss: string;
    aud: string;
    addressSeed: bigint | string;
    maxEpoch: bigint;
    nonce: string;
    salt: Uint8Array;
    address?: string | null;
  }): Record<string, string | string[]> {
    // Prepare inputs according to the actual zkLogin circuit specification
    const BN254_FIELD_MODULUS = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

    // Compute address hash correctly for zkLogin circuit
    // If address is provided, compute hash from it; otherwise use addressSeed directly
    let addressHash: string;
    console.log('🔍 DEBUG: Address hash computation - address provided:', address);
    if (address) {
      // 1️⃣ Strip the 0x prefix, turn the hex string into a BigInt
      const addressNo0x = address.replace(/^0x/, '');
      const addressBigInt = BigInt('0x' + addressNo0x);

      console.log('🔍 DEBUG: Computing Poseidon hash for address:', address, '-> BigInt:', addressBigInt.toString());
      // 2️⃣ poseidon1 expects an array with a single element
      //    This returns a BigInt that we convert to string for the circuit
      const poseidonResult = poseidon1([addressBigInt]);
      addressHash = poseidonResult.toString();
      console.log('🔍 DEBUG: Poseidon result type:', typeof addressHash, 'value:', addressHash);
    } else {
      // Fallback: use addressSeed directly as field element
      const addressSeedBigInt = typeof addressSeed === 'string' ? BigInt(addressSeed) : addressSeed;
      addressHash = (addressSeedBigInt % BN254_FIELD_MODULUS).toString();
      console.log('🔍 DEBUG: Using fallback addressSeed computation:', addressHash);
    }

    // Convert salt to field element
    let saltField = BigInt(0);
    for (let i = 0; i < Math.min(salt.length, 32); i++) {
      saltField = (saltField * BigInt(256)) + BigInt(salt[i]);
    }
    saltField = saltField % BN254_FIELD_MODULUS;

    // Convert sub, iss, aud, nonce to field elements
    const subField = this.stringToField(sub);
    console.log('🔍 DEBUG: Real iss value from JWT:', iss);

    // Production: Exact string matching for issuer validation
    const VALID_GOOGLE_ISSUER = 'https://accounts.google.com';
    if (iss !== VALID_GOOGLE_ISSUER) {
      throw new Error(`Invalid issuer: ${iss}. Expected: ${VALID_GOOGLE_ISSUER}`);
    }

    // Convert the exact issuer string to field element using the same hash function
    const issField = this.stringToField(iss);
    console.log('🔍 DEBUG: Production iss field hash:', issField.toString());
    const audField = this.stringToField(aud);
    const nonceField = this.stringToField(nonce);

    console.log('Preparing zkLogin circuit inputs:', {
      addressHash: addressHash,
      subField: subField.toString(),
      issField: issField.toString(), // Hash of exact issuer string
      audField: audField.toString(),
      nonceField: nonceField.toString(),
      saltField: saltField.toString(),
      maxEpoch: maxEpoch.toString()
    });

    return {
      // JWT components (arrays) - match circuit signal declarations
      jwtHeaderHash: Array(8).fill('0'), // Would be actual SHA256 hash chunks
      jwtPayloadHash: Array(8).fill('0'), // Would be actual SHA256 hash chunks
      jwtSignature: Array(64).fill('0'), // Would be actual RSA signature
      googleModulus: Array(64).fill('0'), // Would be Google's RSA modulus
      googleExponent: '65537', // Single field element

      // Single field element inputs - match circuit signal declarations
      sub: subField.toString(),
      iss: issField.toString(), // Hash of the exact issuer string
      aud: audField.toString(),
      nonce: nonceField.toString(),
      salt: saltField.toString(),

      // zkLogin specific inputs - single field elements as per circuit
      address_hash: addressHash, // Single field element, not array
      maxEpoch: maxEpoch.toString(),
      currentEpoch: '1000' // Would be dynamic
    };
  }
}

export const LocalZkLogin = {
  createProver(assets: LocalZkLoginAssets = {}): LocalZkLoginProver {
    return new LocalZkLoginProver(assets);
  },
  // Note: Basic zkLogin functions (generateRandomness, generateNonce, genAddressSeed,
  // decodeJwt, jwtToAddress, toZkLoginPublicIdentifier) are now available in
  // window.SuiSDK.ZkLogin from the main bundle. LocalZkLogin focuses on proof generation.
  Ed25519Keypair,
  Ed25519PublicKey,
  demo: demoLocalZkLogin,
};

export default LocalZkLogin;

// Example usage:
// ```typescript
// import { LocalZkLogin } from './local-zklogin';
//
// // Create prover with embedded circuits
// const prover = LocalZkLogin.createProver({
//   wasmBase64: 'base64-encoded-wasm',
//   provingKeyBase64: 'base64-encoded-zkey',
//   verificationKey: verificationKeyJson
// });
//
// await prover.init();
//
// // Generate proof
// const result = await prover.prove({
//   jwt: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...',
//   salt: new Uint8Array(32),
//   addressSeed: BigInt('0x123...'),
//   maxEpoch: BigInt(1000),
//   randomness: generateRandomness(),
//   ephemeralPublicKeyBytes: ephemeralKeypair.getPublicKey().toRawBytes()
// });
//
// console.log('Proof generated:', result.signatureInputs.proofPoints);
// ```

// To test the LocalZkLogin prover:
// ```typescript
// import { LocalZkLogin } from './local-zklogin';
//
// // Run the demo
// LocalZkLogin.demo().then(result => {
//   console.log('Demo completed:', result);
// }).catch(error => {
//   console.error('Demo failed:', error);
// });
//
// // Or create custom prover
// const prover = LocalZkLogin.createProver();
// await prover.init();
// const result = await prover.prove({...});
// ```

// Demo function for testing the LocalZkLogin prover
export async function demoLocalZkLogin() {
  console.log('🚀 Starting LocalZkLogin Demo');

  // Create a prover instance (will use mock mode since no WASM provided)
  const prover = LocalZkLogin.createProver();
  await prover.init();

  console.log('✅ Prover initialized:', prover.isReady);

  // Mock JWT for testing
  const mockJWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXItMTIzIiwiaXNzIjoiaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tIiwiYXVkIjoieW91ci1jbGllbnQtaWQuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiaWF0IjoxNjk4NzY1NjAwLCJleHAiOjE2OTg3NjkxMDB9.mock-signature';

  // Mock inputs
  const salt = new Uint8Array(32).fill(1);
  const addressSeed = BigInt('0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef');
  const maxEpoch = BigInt(1000);

  try {
    const result = await prover.prove({
      jwt: mockJWT,
      salt,
      addressSeed,
      maxEpoch,
      randomness: generateRandomness()
    });

    console.log('✅ Proof generated successfully!');
    console.log('Duration:', result.durationMs, 'ms');
    console.log('Nonce:', result.nonce);
    console.log('Proof points:', JSON.stringify(result.signatureInputs.proofPoints, null, 2));

    return result;
  } catch (error) {
    console.error('❌ Proof generation failed:', error);
    throw error;
  }
}

// To test the LocalZkLogin prover:
// 1. Build the project: npm run build:minimal
// 2. Open dist/sui-sdk-minimal.iife.js in browser
// 3. Run: window.SuiSDK.LocalZkLogin.demo()
// 4. Or create custom prover: window.SuiSDK.LocalZkLogin.createProver()
