// src/index-advanced.ts - Advanced SDK tier for zkLogin and optional features
// Contains zkLogin functionality, keypair generation, and other advanced features

// Keypair functionality (moved from transaction tier for zkLogin)
import { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';

// ZkLogin functionality
import {
  getExtendedEphemeralPublicKey,
  getZkLoginSignature,
  generateNonce,
  generateRandomness,
  jwtToAddress,
  genAddressSeed,
  decodeJwt,
  toZkLoginPublicIdentifier,
  hashASCIIStrToField,
  poseidonHash
} from '@mysten/sui/zklogin';

// Advanced tier functions
const AdvancedZkLogin = {
  getExtendedEphemeralPublicKey,
  getZkLoginSignature,
  generateNonce,
  generateRandomness,
  jwtToAddress,
  genAddressSeed,
  decodeJwt,
  toZkLoginPublicIdentifier,
  hashASCIIStrToField,
  poseidonHash,
};

// Update the global SDK with advanced functionality
if (window.SuiSDK) {
  // Add keypair functionality to Sui namespace
  window.SuiSDK.Sui.Ed25519Keypair = Ed25519Keypair;
  window.SuiSDK.Sui.Ed25519PublicKey = Ed25519PublicKey;

  // Merge the advanced zkLogin helpers, preserving any utility methods that
  // were already attached during earlier tiers or runtime customization.
  window.SuiSDK.ZkLogin = {
    ...(window.SuiSDK.ZkLogin || {}),
    ...AdvancedZkLogin,
  };
} else {
  throw new Error('SuiSDK not found - advanced tier cannot load without core tier');
}
