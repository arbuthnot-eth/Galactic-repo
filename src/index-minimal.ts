// src/index-minimal.ts - Ultra-minimal bundle with ONLY functions actually used
// Analysis: Only these specific functions are called in smartwallet-dev.html

// Sui - import only the specific functions we actually use
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { getFullnodeUrl } from '@mysten/sui/client';
import { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { normalizeSuiAddress } from '@mysten/sui/utils';

// ZkLogin - only the 2 functions actually used
import { getExtendedEphemeralPublicKey, getZkLoginSignature } from '@mysten/sui/zklogin';

// BCS - only fromBase64 (bcs object not used directly)
import { fromBase64 } from '@mysten/bcs';

// Enoki - only EnokiClient
import { EnokiClient } from '@mysten/enoki';

// SuiNS - required for core functionality
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

// Environment variables - simplified for minimal bundle
try {
  if (typeof (import.meta as any)?.env?.VITE_ENOKI_PUBLIC_API_KEY === 'string') {
    (window as any).ENOKI_API_KEY = (import.meta as any).env.VITE_ENOKI_PUBLIC_API_KEY;
  }
  if (typeof (import.meta as any)?.env?.VITE_ENOKI_API_URL === 'string') {
    (window as any).ENOKI_API_URL = (import.meta as any).env.VITE_ENOKI_API_URL;
  }
} catch (_) {}

// Bundle loaded successfully
