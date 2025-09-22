// src/index-minimal.ts - Ultra-minimal bundle with ONLY functions actually used
// Analysis: Only these specific functions are called in smartwallet-dev.html

// Sui - import only the specific functions we actually use
import { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { getFullnodeUrl } from '@mysten/sui/client';
import { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { normalizeSuiAddress } from '@mysten/sui/utils';

// ZkLogin - functions used for zkLogin authentication
import {
  getExtendedEphemeralPublicKey,
  getZkLoginSignature,
  generateNonce,
  generateRandomness,
  jwtToAddress,
  genAddressSeed,
  decodeJwt,
  toZkLoginPublicIdentifier
} from '@mysten/sui/zklogin';

// BCS - only fromBase64 (bcs object not used directly)
import { fromBase64 } from '@mysten/bcs';

// SuiNS - required for core functionality
import { SuinsClient } from '@mysten/suins';

// WalletStandard - only getWallets
import { getWallets } from '@mysten/wallet-standard';

// Local zkLogin helper (mock/prover utilities)
import LocalZkLogin from './local-zklogin';

// Poseidon hash function for zkLogin
import { poseidon1 } from 'poseidon-lite/poseidon1';

// Minimal Sui object with only used functions
const Sui = {
  Ed25519Keypair,
  Ed25519PublicKey,
  getFullnodeUrl,
  SuiClient,
  Transaction,
  normalizeSuiAddress,
  // For backward compatibility
  TransactionBlock: Transaction,
  // Include SuinsClient for core functionality
  SuinsClient,
};

// Minimal BCS object - only fromBase64 is used
const BCS = {
  fromBase64,
};

// Minimal ZkLogin object
const ZkLogin = {
  getExtendedEphemeralPublicKey,
  getZkLoginSignature,
  generateNonce,
  generateRandomness,
  jwtToAddress,
  genAddressSeed,
  decodeJwt,
  toZkLoginPublicIdentifier,
  poseidon1,
};

// Minimal SuiNS object
const SuiNS = {
  SuinsClient,
};

// Minimal WalletStandard object
const WalletStandard = {
  getWallets,
};

// Ultra-minimal SDK interface
declare global {
  interface Window {
    SuiSDK: {
      Sui: typeof Sui;
      BCS: typeof BCS;
      ZkLogin: typeof ZkLogin;
      SuiNS: typeof SuiNS;
      WalletStandard: typeof WalletStandard;
      LocalZkLogin: typeof LocalZkLogin;
      // Extended SDKs
      // Walrus?: any;
      // Seal?: any;
      // DappKit?: any;
      // GraphQLTransport?: any;
      // ZkSend?: any;
      // Kiosk?: any;
      // Bip39?: any;
    };
  }
}

window.SuiSDK = {
  Sui,
  BCS,
  ZkLogin,
  SuiNS,
  WalletStandard,
  LocalZkLogin,
};

// Also expose poseidon1 directly on window for easy access
(window as any).poseidon1 = poseidon1;

