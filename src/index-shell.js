// src/index-shell.js - Ultra-minimal shell for immediate page load
// Contains ONLY what's needed for initial UI rendering and basic interactivity

// SDK Loading system
const loadingPromises = {
  core: null,
  transaction: null,
  advanced: null,
};

function createLoader(tier, scriptSrc) {
  return function() {
    if (loadingPromises[tier]) {
      return loadingPromises[tier];
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

    return loadingPromises[tier];
  };
}

window.SuiSDK = {
  Sui: {
    Ed25519Keypair: null,
    Ed25519PublicKey: null,
    getFullnodeUrl: null,
    SuiClient: null,
    Transaction: null,
    normalizeSuiAddress: null,
    TransactionBlock: null,
    SuinsClient: null,
  },
  BCS: {
    fromBase64: null,
  },
  ZkLogin: {},
  SuiNS: {
    SuinsClient: null,
  },
  WalletStandard: {
    getWallets: null,
  },
  LocalZkLogin: {},
  _loading: {
    core: false,
    transaction: false,
    advanced: false,
  },
  loadCore: createLoader('core', '/dist/sui-sdk-core.iife.js'),
  loadTransaction: createLoader('transaction', '/dist/sui-sdk-transaction.iife.js'),
  loadAdvanced: createLoader('advanced', '/dist/sui-sdk-advanced.iife.js'),
};

console.log('🚀 Galactic SmartWallet shell loaded - progressive enhancement starting...');