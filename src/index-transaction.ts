// src/index-transaction.ts - Transaction SDK tier for wallet operations
// Contains keypair generation, transaction building, and signing functionality

// Transaction and keypair functionality
import { Ed25519Keypair, Ed25519PublicKey } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';

// BCS for transaction serialization
import { fromBase64 } from '@mysten/bcs';

// SuiNS for name resolution
import { SuinsClient } from '@mysten/suins';

// Transaction tier functions
const TransactionSui = {
  Ed25519Keypair,
  Ed25519PublicKey,
  Transaction,
  TransactionBlock: Transaction, // Backward compatibility alias
  SuinsClient,
  // Keep existing functions from core tier
  getFullnodeUrl: window.SuiSDK?.Sui?.getFullnodeUrl || null,
  SuiClient: window.SuiSDK?.Sui?.SuiClient || null,
  normalizeSuiAddress: window.SuiSDK?.Sui?.normalizeSuiAddress || null,
};

const TransactionBCS = {
  fromBase64,
};

const TransactionSuiNS = {
  SuinsClient,
};

// Update the global SDK with transaction functionality
if (window.SuiSDK) {
  // Merge transaction functions with existing SDK
  window.SuiSDK.Sui = { ...window.SuiSDK.Sui, ...TransactionSui };
  window.SuiSDK.BCS = { ...window.SuiSDK.BCS, ...TransactionBCS };
  window.SuiSDK.SuiNS = { ...window.SuiSDK.SuiNS, ...TransactionSuiNS };
} else {
  console.error('SuiSDK not found - transaction tier cannot load without core tier');
}

console.log('📦 Transaction SDK tier loaded - wallet operations ready');