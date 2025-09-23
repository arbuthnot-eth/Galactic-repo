// src/index-shell.ts - Ultra-minimal shell for immediate page load
// Contains ONLY what's needed for initial UI rendering and basic interactivity

// Ultra-minimal shell object with loading placeholders
const SuiShell = {
  // Placeholder functions that will be replaced when full SDK loads
  Ed25519Keypair: null,
  Ed25519PublicKey: null,
  getFullnodeUrl: null,
  SuiClient: null,
  Transaction: null,
  normalizeSuiAddress: null,
  TransactionBlock: null, // Backward compatibility
  SuinsClient: null,
};

const BCSShell = {
  fromBase64: null,
};

const ZkLoginShell = {
  // These will be replaced by the advanced tier when it loads
};

const SuiNSShell = {
  SuinsClient: null,
};

const WalletStandardShell = {
  getWallets: null,
};

const LocalZkLoginShell = {
  createProver: null,
};

// Ultra-minimal SDK interface
declare global {
  interface Window {
    SuiSDK: {
      Sui: typeof SuiShell;
      BCS: typeof BCSShell;
      ZkLogin: typeof ZkLoginShell;
      SuiNS: typeof SuiNSShell;
      WalletStandard: typeof WalletStandardShell;
      LocalZkLogin: typeof LocalZkLoginShell;
      // Loading state
      _loading: {
        core: boolean;
        transaction: boolean;
        advanced: boolean;
      };
      // Loader functions
      loadCore: () => Promise<void>;
      loadTransaction: () => Promise<void>;
      loadAdvanced: () => Promise<void>;
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