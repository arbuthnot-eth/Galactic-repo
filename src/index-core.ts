// src/index-core.ts - Core SDK tier for basic wallet connection
// Contains essential functions for wallet connection and network setup

// Core Sui functionality - connection and basic utilities
import { getFullnodeUrl } from '@mysten/sui/client';
import { SuiClient } from '@mysten/sui/client';
import { normalizeSuiAddress } from '@mysten/sui/utils';

// Basic wallet detection
import { getWallets } from '@mysten/wallet-standard';

import { lazyLoadImages } from './lazy-images';

// Core functions that are needed early
const CoreSui = {
  getFullnodeUrl,
  SuiClient,
  normalizeSuiAddress,
};

const CoreWalletStandard = {
  getWallets,
};

const CoreUtils = {
  lazyLoadImages,
};

// Update the global SDK with core functionality
if (window.SuiSDK) {
  // Merge with existing shell, preserving loading state
  window.SuiSDK.Sui = { ...window.SuiSDK.Sui, ...CoreSui };
  window.SuiSDK.WalletStandard = { ...window.SuiSDK.WalletStandard, ...CoreWalletStandard };
  window.SuiSDK.Utils = { ...(window.SuiSDK.Utils || {}), ...CoreUtils };
} else {
  // Fallback if shell didn't load properly
  console.warn('SuiSDK shell not found, creating core SDK directly');
  (window as any).SuiSDK = {
    Sui: CoreSui,
    WalletStandard: CoreWalletStandard,
    Utils: CoreUtils,
  };
}
