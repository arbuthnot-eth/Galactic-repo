// src/index.ts - Entry file for bundling all Mysten Labs SDKs
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { getFullnodeUrl, SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import * as ZkLogin from '@mysten/sui/zklogin';
import * as BCS from '@mysten/bcs';
import * as Walrus from '@mysten/walrus';
import * as Seal from '@mysten/seal';
import * as DappKit from '@mysten/dapp-kit';
import * as SuiNS from '@mysten/suins';
import * as WalletStandard from '@mysten/wallet-standard';
import * as GraphQLTransport from '@mysten/graphql-transport';
import * as ZkSend from '@mysten/zksend';
import * as Kiosk from '@mysten/kiosk';

// Re-export Sui with specific imports using proper package exports
const Sui = {
  Ed25519Keypair,
  getFullnodeUrl,
  SuiClient,
  Transaction, // Note: Using Transaction instead of TransactionBlock in v1.37.6
  // Add an alias for backward compatibility
  TransactionBlock: Transaction,
  // Include BCS utilities from Sui
  BCS: BCS,
  // Include zkLogin functionality
  ZkLogin: ZkLogin,
};

// Re-export as a global object for easy access in HTML
declare global {
  interface Window {
    SuiSDK: {
      Sui: typeof Sui;
      BCS: typeof BCS;
      Walrus: typeof Walrus;
      Seal: typeof Seal;
      DappKit: typeof DappKit;
      SuiNS: typeof SuiNS;
      WalletStandard: typeof WalletStandard;
      GraphQLTransport: typeof GraphQLTransport;
      ZkSend: typeof ZkSend;
      Kiosk: typeof Kiosk;
      ZkLogin: typeof ZkLogin;
    };
  }
}

window.SuiSDK = {
  Sui,
  BCS,
  Walrus,
  Seal,
  DappKit,
  SuiNS,
  WalletStandard,
  GraphQLTransport,
  ZkSend,
  Kiosk,
  // Also expose ZkLogin separately for convenience
  ZkLogin,
};

// Handle async init if needed (e.g., for Walrus WASM)
// Note: Walrus init may not be available in current version
try {
  if (Walrus && typeof (Walrus as any).init === 'function') {
    (Walrus as any).init().catch(console.error);
  }
} catch (error) {
  console.warn('Walrus init not available:', error);
}

console.log('Sui SDK Bundle loaded successfully');
console.log('Available SDKs:', Object.keys(window.SuiSDK));