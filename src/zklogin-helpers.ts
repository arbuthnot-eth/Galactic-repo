// On-demand zkLogin helper bundle, loaded only when the SmartWallet needs
// advanced jwt/seed utilities. This keeps the minimal bundle smaller while
// preserving existing window.SuiSDK semantics once helpers are injected.

import {
  decodeJwt,
  jwtToAddress,
  genAddressSeed,
  toZkLoginPublicIdentifier,
  getExtendedEphemeralPublicKey,
  getZkLoginSignature,
  parseZkLoginSignature,
  generateNonce,
  generateRandomness,
} from '@mysten/sui/zklogin';

declare global {
  interface Window {
    SuiSDK?: Record<string, any>;
    __zkLoginHelpersLoaded__?: boolean;
  }
}

const globalTarget = typeof window !== 'undefined' ? window : (globalThis as any);

if (globalTarget && !globalTarget.__zkLoginHelpersLoaded__) {
  const sdk = globalTarget.SuiSDK ?? {};
  const existingZkLogin = sdk.ZkLogin ?? {};

  sdk.ZkLogin = {
    ...existingZkLogin,
    decodeJwt,
    jwtToAddress,
    genAddressSeed,
    toZkLoginPublicIdentifier,
    getExtendedEphemeralPublicKey,
    getZkLoginSignature,
    parseZkLoginSignature,
    generateNonce,
    generateRandomness,
  };

  globalTarget.SuiSDK = sdk;
  globalTarget.__zkLoginHelpersLoaded__ = true;

  if (typeof globalTarget.console !== 'undefined') {
    globalTarget.console.log('SmartWallet: zkLogin helpers loaded');
  }
}

export {};
