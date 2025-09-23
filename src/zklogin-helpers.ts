// On-demand zkLogin helper bundle, loaded only when the Galactic SmartWallet needs
// advanced jwt/seed utilities. This keeps the minimal bundle smaller while
// preserving existing window.SuiSDK semantics once helpers are injected.

import {
  decodeJwt,
  jwtToAddress,
  genAddressSeed,
  toZkLoginPublicIdentifier,
  getExtendedEphemeralPublicKey,
  getZkLoginSignature,
  parseZkLoginSignature,
  generateNonce,
  generateRandomness,
} from '@mysten/sui/zklogin';

// Import circom WebAssembly runtime support
import { WitnessCalculatorBuilder, createCircomRuntimeImports } from './circom-runtime';

// Import Poseidon hash function
import { poseidon1 } from 'poseidon-lite/poseidon1';

// Use type assertion instead of interface declaration to avoid conflicts

const globalTarget = typeof window !== 'undefined' ? window : (globalThis as any);

if (globalTarget && !(globalTarget as any).__zkLoginHelpersLoaded__) {
  const sdk = (globalTarget as any).SuiSDK ?? {};
  const existingZkLogin = sdk.ZkLogin ?? {};

  sdk.ZkLogin = {
    ...existingZkLogin,
    decodeJwt,
    jwtToAddress,
    genAddressSeed,
    toZkLoginPublicIdentifier,
    getExtendedEphemeralPublicKey,
    getZkLoginSignature,
    parseZkLoginSignature,
    generateNonce,
    generateRandomness,
  };

  // Attach circom runtime support to global context
  globalTarget.WitnessCalculatorBuilder = WitnessCalculatorBuilder;
  globalTarget.createCircomRuntimeImports = createCircomRuntimeImports;

  // Attach Poseidon hash function
  globalTarget.poseidon1 = poseidon1;
  sdk.poseidon1 = poseidon1;

  // Note: snarkjs is attached by circom-runtime.ts import

  globalTarget.SuiSDK = sdk;
  globalTarget.__zkLoginHelpersLoaded__ = true;

  if (typeof globalTarget.console !== 'undefined') {
    globalTarget.console.log('Galactic: zkLogin helpers loaded');
  }
}

// -------------------------------------------------------------------------
//  ZkLogin circuit helper utilities
// -------------------------------------------------------------------------

/**
 * **NOTE:** The zkLogin circuit defines `address_hash` as a **single** field element
 * (see `zklogin.circom` line `signal input addressHash;`).  Earlier versions of the
 * helper mistakenly split this into two 128‑bit limbs, which caused the runtime
 * error *"Too many values for input signal address_hash"*.  The helper now simply
 * passes the hash through unchanged.
 *
 * @param rawInputs - Raw zkLogin inputs that already contain `address_hash` as a
 *                    decimal string (or any format accepted by the circuit).
 * @returns The same input object without modification.
 */
export function buildZkLoginInputs(rawInputs: Record<string, any>) {
  // No splitting required – the circuit expects a single field element.
  return { ...rawInputs };
}

// -------------------------------------------------------------------------
//  ZkLogin proof generation – **real proof only**
// -------------------------------------------------------------------------
//
// The library used to catch any error from the real prover and replace it with a
// pre‑computed mock proof.  That behaviour masked genuine circuit‑/input‑issues
// (like the `address_hash` shape bug) and made debugging impossible.
//
// We now expose a single `generateZkLoginProof` function that *always* attempts
// the real proof generation and propagates any exception to the caller.
//

import { LocalZkLogin, LocalZkLoginProofContext } from './local-zklogin';

export async function generateZkLoginProof(context: LocalZkLoginProofContext) {
  // Let any error bubble up – the UI will display it and the developer can act.
  const prover = LocalZkLogin.createProver();
  await prover.init();
  return await prover.prove(context);
}

export {};
