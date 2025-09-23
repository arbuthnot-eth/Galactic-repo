// src/index-shell.ts - Ultra-minimal shell for immediate page load
// Contains ONLY what's needed for initial UI rendering and basic interactivity

// Import types for proper typing
import type { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import type { Transaction } from '@mysten/sui/transactions';
import type { SuiClient } from '@mysten/sui/client';
import type { SuinsClient } from '@mysten/suins';
import type { fromBase64 } from '@mysten/bcs';
import type { getWallets } from '@mysten/wallet-standard';

// Ultra-minimal shell object with loading placeholders
const SuiShell = {
  // Placeholder functions that will be replaced when full SDK loads
  Ed25519Keypair: null as typeof Ed25519Keypair | null,
  Ed25519PublicKey: null as typeof Ed25519PublicKey | null,
  getFullnodeUrl: null as ((network: 'mainnet' | 'testnet' | 'devnet' | 'localnet') => string) | null,
  SuiClient: null as typeof SuiClient | null,
  Transaction: null as typeof Transaction | null,
  normalizeSuiAddress: null as ((address: string) => string) | null,
  TransactionBlock: null as typeof Transaction | null, // Backward compatibility
  SuinsClient: null as typeof SuinsClient | null,
};

const BCSShell = {
  fromBase64: null as typeof fromBase64 | null,
};

const ZkLoginShell = {} as Record<string, any>;

const SuiNSShell = {
  SuinsClient: null as typeof SuinsClient | null,
};

const WalletStandardShell = {
  getWallets: null as typeof getWallets | null,
};

const LocalZkLoginShell = {} as Record<string, any>;

// Ultra-minimal SDK interface with proper typing for dynamic loading
declare global {
  interface Window {
    SuiSDK: {
      Sui: {
        Ed25519Keypair: typeof Ed25519Keypair | null;
        Ed25519PublicKey: typeof Ed25519PublicKey | null;
        getFullnodeUrl: ((network: 'mainnet' | 'testnet' | 'devnet' | 'localnet') => string) | null;
        SuiClient: typeof SuiClient | null;
        Transaction: typeof Transaction | null;
        normalizeSuiAddress: ((address: string) => string) | null;
        TransactionBlock: typeof Transaction | null;
        SuinsClient: typeof SuinsClient | null;
      };
      BCS: {
        fromBase64: typeof fromBase64 | null;
      };
      ZkLogin: Record<string, any>;
      SuiNS: {
        SuinsClient: typeof SuinsClient | null;
      };
      WalletStandard: {
        getWallets: typeof getWallets | null;
      };
      LocalZkLogin: Record<string, any>;
      // Loading state (optional for compatibility with minimal build)
      _loading?: {
        core: boolean;
        transaction: boolean;
        advanced: boolean;
      };
      // Loader functions (optional for compatibility with minimal build)
      loadCore?: () => Promise<void>;
      loadTransaction?: () => Promise<void>;
      loadAdvanced?: () => Promise<void>;
    };
  }
}

// SDK Loading system
const loadingPromises = {
  core: null as Promise<void> | null,
  transaction: null as Promise<void> | null,
  advanced: null as Promise<void> | null,
};

function createLoader(tier: 'core' | 'transaction' | 'advanced', scriptSrc: string) {
  return function() {
    if (loadingPromises[tier]) {
      return loadingPromises[tier]!;
    }

    loadingPromises[tier] = new Promise((resolve, reject) => {
      window.SuiSDK._loading[tier] = true;

      const script = document.createElement('script');
      script.src = scriptSrc;
      script.onload = () => {
        window.SuiSDK._loading[tier] = false;
        console.log(`📦 ${tier} SDK tier loaded`);
        resolve();
      };
      script.onerror = () => {
        window.SuiSDK._loading[tier] = false;
        reject(new Error(`Failed to load ${tier} SDK tier`));
      };
      document.head.appendChild(script);
    });

    return loadingPromises[tier]!;
  };
}

window.SuiSDK = {
  Sui: SuiShell,
  BCS: BCSShell,
  ZkLogin: ZkLoginShell,
  SuiNS: SuiNSShell,
  WalletStandard: WalletStandardShell,
  LocalZkLogin: LocalZkLoginShell,
  _loading: {
    core: false,
    transaction: false,
    advanced: false,
  },
  loadCore: createLoader('core', '/dist/sui-sdk-core.iife.js'),
  loadTransaction: createLoader('transaction', '/dist/sui-sdk-transaction.iife.js'),
  loadAdvanced: createLoader('advanced', '/dist/sui-sdk-advanced.iife.js'),
};

// Start loading all tiers immediately for better UX
setTimeout(() => {
  window.SuiSDK.loadCore().catch(err =>
    console.warn('Core SDK loading failed:', err.message)
  );
}, 100);

setTimeout(() => {
  window.SuiSDK.loadTransaction().catch(err =>
    console.warn('Transaction SDK loading failed:', err.message)
  );
}, 200);

// Load advanced tier early since zkLogin is commonly used
setTimeout(() => {
  window.SuiSDK.loadAdvanced().catch(err =>
    console.warn('Advanced SDK loading failed:', err.message)
  );
}, 300);

console.log('🚀 Galactic SmartWallet shell loaded - progressive enhancement starting...');