// src/wallet-logic.ts - Core wallet functionality using Mysten Labs SDKs

// Type declarations for the global SuiSDK object
declare global {
  interface Window {
    SuiSDK: any;
  }
}

// Wallet creation and key management
export function createWallet() {
  try {
    const { Ed25519Keypair } = window.SuiSDK.Sui;
    const keypair = Ed25519Keypair.generate();
    const address = keypair.toSuiAddress();
    
    console.log('New wallet created!');
    console.log('Address:', address);
    console.log('Private key (keep secure):', keypair.export().privateKey);
    
    return {
      address,
      keypair,
      privateKey: keypair.export().privateKey
    };
  } catch (error) {
    console.error('Error creating wallet:', error);
    throw error;
  }
}

// Get balance for a given address
export async function getBalance(address: string, network: 'mainnet' | 'testnet' | 'devnet' = 'devnet') {
  try {
    const { SuiClient, getFullnodeUrl } = window.SuiSDK.Sui;
    const client = new SuiClient({ url: getFullnodeUrl(network) });
    
    const balance = await client.getBalance({ owner: address });
    const suiBalance = Number(balance.totalBalance) / 1_000_000_000; // Convert from MIST to SUI
    
    console.log(`Balance for ${address}:`, suiBalance, 'SUI');
    return suiBalance;
  } catch (error) {
    console.error('Error getting balance:', error);
    throw error;
  }
}

// Get wallet objects/NFTs
export async function getWalletObjects(address: string, network: 'mainnet' | 'testnet' | 'devnet' = 'devnet') {
  try {
    const { SuiClient, getFullnodeUrl } = window.SuiSDK.Sui;
    const client = new SuiClient({ url: getFullnodeUrl(network) });
    
    const objects = await client.getOwnedObjects({
      owner: address,
      options: {
        showContent: true,
        showDisplay: true,
        showType: true,
      }
    });
    
    console.log(`Objects for ${address}:`, objects.data);
    return objects.data;
  } catch (error) {
    console.error('Error getting wallet objects:', error);
    throw error;
  }
}

// Transfer SUI tokens
export async function transferSui(fromKeypair: any, toAddress: string, amount: number, network: 'mainnet' | 'testnet' | 'devnet' = 'devnet') {
  try {
    const { SuiClient, getFullnodeUrl, TransactionBlock } = window.SuiSDK.Sui;
    const client = new SuiClient({ url: getFullnodeUrl(network) });
    
    const txb = new TransactionBlock();
    const coin = txb.splitCoins(txb.gas, [txb.pure(amount * 1_000_000_000)]); // Convert SUI to MIST
    txb.transferObjects([coin], txb.pure(toAddress));
    
    const result = await client.signAndExecuteTransactionBlock({
      signer: fromKeypair,
      transactionBlock: txb,
    });
    
    console.log('Transfer successful:', result.digest);
    return result;
  } catch (error) {
    console.error('Error transferring SUI:', error);
    throw error;
  }
}

// Restore wallet from private key
export function restoreWallet(privateKeyHex: string) {
  try {
    const { Ed25519Keypair } = window.SuiSDK.Sui;
    const keypair = Ed25519Keypair.fromSecretKey(privateKeyHex);
    const address = keypair.toSuiAddress();
    
    console.log('Wallet restored!');
    console.log('Address:', address);
    
    return {
      address,
      keypair
    };
  } catch (error) {
    console.error('Error restoring wallet:', error);
    throw error;
  }
}

// SuiNS name resolution
export async function resolveSuiNSName(name: string, network: 'mainnet' | 'testnet' | 'devnet' = 'devnet') {
  try {
    const { SuiClient, getFullnodeUrl } = window.SuiSDK.Sui;
    const client = new SuiClient({ url: getFullnodeUrl(network) });
    
    // This is a simplified example - actual SuiNS integration would require more setup
    console.log(`Resolving SuiNS name: ${name}`);
    // Implementation would use window.SuiSDK.SuiNS
    
    return null; // Placeholder
  } catch (error) {
    console.error('Error resolving SuiNS name:', error);
    throw error;
  }
}

// Wallet connection using dApp kit
export async function connectWallet() {
  try {
    // This would use window.SuiSDK.DappKit for wallet connection
    console.log('Connecting to wallet...');
    // Implementation would integrate with browser wallet extensions
    
    return null; // Placeholder
  } catch (error) {
    console.error('Error connecting wallet:', error);
    throw error;
  }
}

// Export utility functions for UI
export const WalletUtils = {
  createWallet,
  getBalance,
  getWalletObjects,
  transferSui,
  restoreWallet,
  resolveSuiNSName,
  connectWallet
};