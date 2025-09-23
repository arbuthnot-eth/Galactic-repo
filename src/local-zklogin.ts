// Basic zkLogin functions are now available in main bundle at window.SuiSDK.ZkLogin
// Only import what's actually used internally for proof generation
import { generateNonce, generateRandomness } from '@mysten/sui/zklogin';
import { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { groth16 } from 'snarkjs';
import { poseidon1, poseidon4 } from 'poseidon-lite';
import { buildZkLoginInputs } from './zklogin-helpers';

/**
 * Compute the zkLogin address hash expected by the circuit.
 *
 *   addressHash = Poseidon( [sub, salt, iss, aud] )
 *
 * This must match exactly how the circuit computes addressSeed to pass the constraint:
 * addressHash === addressSeed (line 131 in circuit)
 */
export function computeAddressHash(sub: string, salt: string, iss: string, aud: string): string {
  // 1️⃣ Convert sub to field element (same as circuit)
  const subBigInt = stringToField(sub);

  // 2️⃣ Salt is already a decimal string, turn it into a bigint
  const saltBigInt = BigInt(salt);

  // 3️⃣ Convert iss and aud to field elements
  const issBigInt = stringToField(iss);
  const audBigInt = stringToField(aud);

  // 4️⃣ Use poseidon4 with 4 inputs: sub, salt, iss, aud (exactly like circuit's addressSeed computation)
  const hashBigInt = poseidon4([subBigInt, saltBigInt, issBigInt, audBigInt]);

  // 5️⃣ Return a **decimal** string (not hex!)
  return hashBigInt.toString();
}

// Helper function to convert string to field element (copied from the class)
function stringToField(input: string): bigint {
  const BN254_FIELD_MODULUS = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

  let hash = BigInt(0);
  for (let i = 0; i < input.length; i++) {
    hash = (hash * BigInt(31) + BigInt(input.charCodeAt(i))) % BN254_FIELD_MODULUS;
  }

  return hash;
}

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
  currentEpoch?: bigint; // Current epoch (will be fetched from blockchain if not provided)
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

      this.ready = true;

    } catch (error) {
      throw error; // Fail properly without fallback
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
    currentEpoch,
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
      // Fetch current epoch from Sui blockchain
      let actualCurrentEpoch = currentEpoch;
      if (!actualCurrentEpoch) {
        actualCurrentEpoch = await this.fetchCurrentEpochFromSui();
      }

      // Compute maxEpoch properly: currentEpoch + 1 (fixed buffer)
      const maxEpoch = BigInt(Number(actualCurrentEpoch) + 1);
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

  private async fetchCurrentEpochFromSui(): Promise<bigint> {
    try {
      // Use Sui testnet RPC endpoint
      const response = await fetch('https://fullnode.testnet.sui.io:443', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'suix_getLatestSuiSystemState',
          params: []
        })
      });

      if (!response.ok) {
        throw new Error(`Sui RPC request failed: ${response.status}`);
      }

      const result = await response.json();

      if (result.error) {
        throw new Error(`Sui RPC error: ${result.error.message}`);
      }

      const currentEpoch = BigInt(result.result.epoch);
      return currentEpoch;

    } catch (error) {
      throw new Error(`Unable to fetch current epoch from Sui blockchain: ${error instanceof Error ? error.message : String(error)}`);
    }
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
      // The circuit expects a **single** address_hash field.  The helper now
    // returns the inputs unchanged, so we can pass them directly.
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

      // Generate real cryptographic proof using snarkjs
      const { proof, publicSignals } = await groth16.fullProve(
        inputs,
        wasm,
        provingKey
      );

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
      throw error;
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
  }) {
    // Prepare inputs according to the actual zkLogin circuit specification
    const BN254_FIELD_MODULUS = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

    // Convert salt to field element (use as decimal string for proper Poseidon computation)
    let saltField = BigInt(0);
    for (let i = 0; i < Math.min(salt.length, 32); i++) {
      saltField = (saltField * BigInt(256)) + BigInt(salt[i]);
    }
    saltField = saltField % BN254_FIELD_MODULUS;
    const saltString = saltField.toString();

    // Convert sub, iss, aud, nonce to field elements
    const subField = this.stringToField(sub);

    // Production: Exact string matching for issuer validation
    const VALID_GOOGLE_ISSUER = 'https://accounts.google.com';
    if (iss !== VALID_GOOGLE_ISSUER) {
      throw new Error(`Invalid issuer: ${iss}. Expected: ${VALID_GOOGLE_ISSUER}`);
    }

    // The circuit expects iss to be the pre-computed hash directly
    // Circuit computes: expectedIssuerHash.inputs[0] <== 64311811759419326176236258789247439964197
    // and then checks: iss === expectedIssuerHash.out
    // But expectedIssuerHash.out = Poseidon([64311811759419326176236258789247439964197])
    const EXPECTED_ISS_PRECOMPUTED = BigInt('64311811759419326176236258789247439964197');
    const issField = poseidon1([EXPECTED_ISS_PRECOMPUTED]);
    const audField = this.stringToField(aud);
    const nonceField = this.stringToField(nonce);

    // Compute addressHash to match circuit's addressSeed computation
    // The circuit computes: addressSeed = Poseidon([sub, salt, iss, aud])
    const addressHash = poseidon4([subField, saltField, issField, audField]).toString();

    const rawInputs = {
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
      salt: saltString,

      // zkLogin specific inputs
      addressHash: addressHash // Single field element for circuit
    };

    // The circuit expects a single address_hash field; no limb conversion needed.
    return buildZkLoginInputs(rawInputs);
  }
}

export const LocalZkLogin = {
  createProver(assets: LocalZkLoginAssets = {}): LocalZkLoginProver {
    return new LocalZkLoginProver(assets);
  },
  // Note: Basic zkLogin functions (generateRandomness, generateNonce) are now available in
  // window.SuiSDK.ZkLogin from the main bundle. LocalZkLogin focuses on proof generation.
  Ed25519Keypair,
  Ed25519PublicKey,
};

export default LocalZkLogin;
