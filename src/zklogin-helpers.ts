import { poseidon1 } from 'poseidon-lite/poseidon1';
import { groth16 } from 'snarkjs';
// Import and explicitly re-export circom runtime for witness calculation
import { WitnessCalculatorBuilder, createCircomRuntimeImports } from './circom-runtime';

// Ensure WitnessCalculatorBuilder is available globally
if (typeof window !== 'undefined') {
  window.WitnessCalculatorBuilder = WitnessCalculatorBuilder;
  window.createCircomRuntimeImports = createCircomRuntimeImports;
  window.snarkjs = { groth16 };
}

// ---------------------------------------------------------------------------
// Helper that builds the exact JSON expected by the zkLogin circuit
// ---------------------------------------------------------------------------
export async function buildZkLoginInputs(raw: {
  jwtHeaderHash: string[];
  jwtPayloadHash: string[];
  jwtSignature: string[];
  googleModulus: string[];
  googleExponent: string;
  sub: string;
  iss: string;
  aud: string;
  nonce: string;
  salt: string;
  addressHash: string;          // ← single scalar field element (decimal string)
  maxEpoch: string;
  currentEpoch: string;
}) {
  // The circuit expects a *single* addressHash field.
  // It must be a decimal string (or bigint‑toString()) – never an array.
  const addressHash = raw.addressHash;

  // Assemble the final input object exactly as the circuit defines it.
  const inputs = {
    jwtHeaderHash: raw.jwtHeaderHash,
    jwtPayloadHash: raw.jwtPayloadHash,
    jwtSignature: raw.jwtSignature,
    googleModulus: raw.googleModulus,
    googleExponent: raw.googleExponent,
    sub: raw.sub,
    iss: raw.iss,
    aud: raw.aud,
    nonce: raw.nonce,
    salt: raw.salt,
    addressHash,                 // ← camel‑case name, will be lower‑cased to address_hash
    maxEpoch: raw.maxEpoch,
    currentEpoch: raw.currentEpoch,
  };

  return inputs;
}

// ---------------------------------------------------------------------------
// Convenience wrapper that runs the full‑prove step
// ---------------------------------------------------------------------------
export async function generateProof(rawInputs: any) {
  // 1️⃣ Build the exact input JSON
  const inputs = await buildZkLoginInputs(rawInputs);

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