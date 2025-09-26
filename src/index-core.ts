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
  // Placeholders for functions loaded in transaction tier
  Ed25519Keypair: null,
  Ed25519PublicKey: null,
  Transaction: null,
  TransactionBlock: null,
  SuinsClient: null,
};

const CoreBCS = {
  // Placeholder - loaded in transaction tier
  fromBase64: null,
};

const CoreZkLogin = {
  // Placeholders - loaded in advanced tier
  getExtendedEphemeralPublicKey: null,
  getZkLoginSignature: null,
  generateNonce: null,
  generateRandomness: null,
  jwtToAddress: null,
  genAddressSeed: null,
  decodeJwt: null,
  toZkLoginPublicIdentifier: null,
};

const CoreSuiNS = {
  // Placeholder - loaded in advanced tier
  SuinsClient: null,
};

const CoreWalletStandard = {
  getWallets,
};

const CoreLocalZkLogin = {
  // Placeholder - loaded in advanced tier
  createProver: null,
};

const CoreUtils = {
  lazyLoadImages,
};

// Update the global SDK with core functionality
if (window.SuiSDK) {
  // Merge with existing shell, preserving loading state
  window.SuiSDK.Sui = { ...window.SuiSDK.Sui, ...CoreSui };
  window.SuiSDK.BCS = { ...window.SuiSDK.BCS, ...CoreBCS };
  window.SuiSDK.ZkLogin = { ...window.SuiSDK.ZkLogin, ...CoreZkLogin };
  window.SuiSDK.SuiNS = { ...window.SuiSDK.SuiNS, ...CoreSuiNS };
  window.SuiSDK.WalletStandard = { ...window.SuiSDK.WalletStandard, ...CoreWalletStandard };
  window.SuiSDK.LocalZkLogin = { ...window.SuiSDK.LocalZkLogin, ...CoreLocalZkLogin };
  window.SuiSDK.Utils = { ...(window.SuiSDK.Utils || {}), ...CoreUtils };
} else {
  // Fallback if shell didn't load properly
  console.warn('SuiSDK shell not found, creating core SDK directly');
  (window as any).SuiSDK = {
    Sui: CoreSui,
    BCS: CoreBCS,
    ZkLogin: CoreZkLogin,
    SuiNS: CoreSuiNS,
    WalletStandard: CoreWalletStandard,
    LocalZkLogin: CoreLocalZkLogin,
    Utils: CoreUtils,
  };
}
