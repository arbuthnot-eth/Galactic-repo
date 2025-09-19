// src/index-core.ts - Core SDKs only (essential for SmartWallet)
import { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { PasskeyKeypair, BrowserPasskeyProvider, PasskeyPublicKey } from '@mysten/sui/keypairs/passkey';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { normalizeSuiAddress, isValidSuiAddress } from '@mysten/sui/utils';
import * as ZkLogin from '@mysten/sui/zklogin';
import * as BCS from '@mysten/bcs';
import * as SuiNS from '@mysten/suins';
import * as WalletStandard from '@mysten/wallet-standard';
import * as Bip39 from '@scure/bip39';
import { EnokiClient } from '@mysten/enoki';
import * as Enoki from '@mysten/enoki';

// Core Sui with specific imports
const Sui = {
  Ed25519Keypair,
  PasskeyKeypair,
  BrowserPasskeyProvider,
  PasskeyPublicKey,
  getFullnodeUrl,
  SuiClient,
  Transaction,
  TransactionBlock: Transaction, // Backward compatibility
  normalizeSuiAddress,
  isValidSuiAddress,
  Ed25519PublicKey,
  BCS: BCS,
  ZkLogin: ZkLogin,
};

// Core SDK interface
declare global {
  interface Window {
    SuiSDK: {
      Sui: typeof Sui;
      BCS: typeof BCS;
      SuiNS: typeof SuiNS;
      WalletStandard: typeof WalletStandard;
      ZkLogin: typeof ZkLogin;
      Bip39: typeof Bip39;
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
  SuiNS,
  WalletStandard,
  ZkLogin,
  Bip39,
  Enoki: { ...Enoki, EnokiClient },
};

// Ensure Enoki is properly exposed for zkLogin
try {
  (window as any).SuiSDK.EnokiClient = EnokiClient;
  (window as any).EnokiSDK = Enoki;
  (window as any).EnokiClient = EnokiClient;
} catch (_) {}

try {
  const defaultEnokiKey = (import.meta as any)?.env?.VITE_ENOKI_PUBLIC_API_KEY ?? '';
  if (defaultEnokiKey && typeof window !== 'undefined') {
    (window as any).ENOKI_API_KEY = defaultEnokiKey;
  }
} catch (_) {}

try {
  const defaultEnokiUrl = (import.meta as any)?.env?.VITE_ENOKI_API_URL ?? '';
  if (defaultEnokiUrl && typeof window !== 'undefined') {
    (window as any).ENOKI_API_URL = defaultEnokiUrl;
  }
} catch (_) {}

console.log('Core Sui SDK Bundle loaded successfully');
console.log('Available Core SDKs:', Object.keys(window.SuiSDK));