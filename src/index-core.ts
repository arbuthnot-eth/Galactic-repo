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

const SUINS_NAME_REGEX = /^[a-z0-9]+(?:[-.][a-z0-9]+)*\.sui$/i;

function normalizeSuinsTarget(value: string): string | null {
  const trimmed = (value || '').trim().toLowerCase();
  if (!trimmed) {
    return null;
  }

  if (SUINS_NAME_REGEX.test(trimmed)) {
    return trimmed;
  }

  if (!trimmed.endsWith('.sui')) {
    const appended = `${trimmed}.sui`;
    if (SUINS_NAME_REGEX.test(appended)) {
      return appended;
    }
  }

  return trimmed;
}

function isValidSuinsName(value: string | null | undefined): boolean {
  if (!value) {
    return false;
  }
  return SUINS_NAME_REGEX.test(value);
}

function setInputError(element: HTMLElement | null | undefined, hasError: boolean, className = 'view-only-input-error') {
  if (!element) {
    return;
  }
  if (hasError) {
    element.classList.add(className);
  } else {
    element.classList.remove(className);
  }
}

const CoreUtils = {
  lazyLoadImages,
  normalizeSuinsTarget,
  isValidSuinsName,
  setInputError,
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
