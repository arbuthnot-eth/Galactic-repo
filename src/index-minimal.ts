// src/index-minimal.ts - Ultra-minimal bundle with only used functions
// Based on actual SmartWallet usage analysis

// Core Sui imports - only what's actually used
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { normalizeSuiAddress } from '@mysten/sui/utils';

// ZkLogin - minimal imports (load heavier helpers on demand)
import { getExtendedEphemeralPublicKey, getZkLoginSignature } from '@mysten/sui/zklogin';

// BCS - minimal imports
import { fromBase64, bcs } from '@mysten/bcs';

// Enoki - only EnokiClient
import { EnokiClient } from '@mysten/enoki';

// SuiNS - only SuinsClient
import { SuinsClient } from '@mysten/suins';

// WalletStandard - only getWallets
import { getWallets } from '@mysten/wallet-standard';

// Minimal Sui object with only used functions
const Sui = {
  Ed25519Keypair,
  getFullnodeUrl,
  SuiClient,
  Transaction,
  normalizeSuiAddress,
  // For backward compatibility
  TransactionBlock: Transaction,
};

// Minimal BCS object
const BCS = {
  fromBase64,
  bcs,
};

// Minimal ZkLogin object
const ZkLogin = {
  getExtendedEphemeralPublicKey,
  getZkLoginSignature,
};

// Minimal SuiNS object
const SuiNS = {
  SuinsClient,
};

// Minimal WalletStandard object
const WalletStandard = {
  getWallets,
};

// Minimal Enoki object
const Enoki = {
  EnokiClient,
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
      Enoki: typeof Enoki;
      // Extended SDKs loaded separately
      DappKit?: any;
      Walrus?: any;
      Seal?: any;
      Kiosk?: any;
      ZkSend?: any;
      GraphQLTransport?: any;
    };
  }
}

window.SuiSDK = {
  Sui,
  BCS,
  ZkLogin,
  SuiNS,
  WalletStandard,
  Enoki,
};

// Legacy globals for Enoki
try {
  (window as any).EnokiClient = EnokiClient;
  (window as any).EnokiSDK = { EnokiClient };
} catch (_) {}

// Environment variables
try {
  const defaultEnokiKey = (import.meta as any)?.env?.VITE_ENOKI_PUBLIC_API_KEY ?? '';
  if (defaultEnokiKey) {
    (window as any).ENOKI_API_KEY = defaultEnokiKey;
  }
} catch (_) {}

try {
  const defaultEnokiUrl = (import.meta as any)?.env?.VITE_ENOKI_API_URL ?? '';
  if (defaultEnokiUrl) {
    (window as any).ENOKI_API_URL = defaultEnokiUrl;
  }
} catch (_) {}

console.log('Minimal Sui SDK Bundle loaded successfully');
console.log('Available SDKs:', Object.keys(window.SuiSDK));
console.log('Bundle size optimized for SmartWallet usage');
