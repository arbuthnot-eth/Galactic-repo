// src/index-extended.ts - Extended SDKs (loaded on demand)
import * as Walrus from '@mysten/walrus';
import * as Seal from '@mysten/seal';
import * as DappKit from '@mysten/dapp-kit';
import * as ZkSend from '@mysten/zksend';
import * as Kiosk from '@mysten/kiosk';
import * as GraphQLTransport from '@mysten/graphql-transport';

// Extend the existing SuiSDK with optional features
if (window.SuiSDK) {
  window.SuiSDK.DappKit = DappKit;
  window.SuiSDK.Walrus = Walrus;
  window.SuiSDK.Seal = Seal;
  window.SuiSDK.ZkSend = ZkSend;
  window.SuiSDK.Kiosk = Kiosk;
  window.SuiSDK.GraphQLTransport = GraphQLTransport;

  // Legacy globals removed - Enoki now in core bundle

  // Handle async init for Walrus WASM (if available)
  try {
    if (Walrus && typeof (Walrus as any).init === 'function') {
      (Walrus as any).init().catch(console.error);
    }
  } catch (error) {
    // Walrus init not available in current version - this is expected
  }

  console.log('Extended Sui SDK Bundle loaded successfully');
  console.log('Extended SDKs added:', ['DappKit', 'Walrus', 'Seal', 'ZkSend', 'Kiosk', 'GraphQLTransport']);
} else {
  console.error('Core SuiSDK not found! Load core bundle first.');
}