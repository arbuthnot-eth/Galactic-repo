// src/index-advanced.ts - Advanced SDK tier for zkLogin and optional features
// Contains zkLogin functionality and other advanced features

// ZkLogin functionality
import {
  getExtendedEphemeralPublicKey,
  getZkLoginSignature,
  generateNonce,
  generateRandomness,
  jwtToAddress,
  genAddressSeed,
  decodeJwt,
  toZkLoginPublicIdentifier
} from '@mysten/sui/zklogin';

// Poseidon hash function for zkLogin
import { poseidon1 } from 'poseidon-lite/poseidon1';

// Local zkLogin helper
import LocalZkLogin from './local-zklogin';

// Advanced tier functions
const AdvancedZkLogin = {
  getExtendedEphemeralPublicKey,
  getZkLoginSignature,
  generateNonce,
  generateRandomness,
  jwtToAddress,
  genAddressSeed,
  decodeJwt,
  toZkLoginPublicIdentifier,
  poseidon1,
};

const AdvancedLocalZkLogin = LocalZkLogin;

// Update the global SDK with advanced functionality
if (window.SuiSDK) {
  console.log('🔧 Before replacing zkLogin object:', {
    zkLoginObject: typeof window.SuiSDK.ZkLogin,
    zkLoginKeys: Object.keys(window.SuiSDK.ZkLogin || {}),
    advancedZkLoginKeys: Object.keys(AdvancedZkLogin)
  });

  // Completely replace the ZkLogin object to ensure clean state
  window.SuiSDK.ZkLogin = AdvancedZkLogin;
  window.SuiSDK.LocalZkLogin = AdvancedLocalZkLogin;

  console.log('✅ zkLogin functions completely replaced:', {
    zkLoginObject: typeof window.SuiSDK.ZkLogin,
    getExtendedEphemeralPublicKey: typeof window.SuiSDK.ZkLogin.getExtendedEphemeralPublicKey,
    generateNonce: typeof window.SuiSDK.ZkLogin.generateNonce,
    generateRandomness: typeof window.SuiSDK.ZkLogin.generateRandomness,
    jwtToAddress: typeof window.SuiSDK.ZkLogin.jwtToAddress,
    decodeJwt: typeof window.SuiSDK.ZkLogin.decodeJwt,
    actualFunctions: {
      getExtendedEphemeralPublicKey: AdvancedZkLogin.getExtendedEphemeralPublicKey?.name,
      generateNonce: AdvancedZkLogin.generateNonce?.name
    }
  });
} else {
  console.error('SuiSDK not found - advanced tier cannot load without core tier');
}

// Also expose poseidon1 directly on window for easy access
(window as any).poseidon1 = poseidon1;

console.log('📦 Advanced SDK tier loaded - zkLogin and advanced features ready');