# Galactic Coding Agent Instructions

## Agent Processing Flow

### 1. Context - Gather All Relevant Information First
**Before any coding changes, thoroughly understand the Galactic project context:**

- **Project Structure & Module Organization**
  - `src/`: TypeScript sources. `index.ts` bundles Mysten SDKs to `window.SuiSDK`.
  - `src/smartwallet-dev.html`: SmartWallet development HTML template served by the dev server. This is the primary editable HTML surface for SmartWallet functionality. Uses a shared Roster object for membership indexing; UI variables and docs consistently use `roster` naming (e.g., `rosterId`).
  - `dist/smartwallet.html`: SmartWallet single-file build output (auto-generated from `src/smartwallet-dev.html` during injection/build; never edit directly).
  - `dist/`: Build output (`sui-sdk-bundle.iife.js`).
  - `scripts/`: Dev utilities (`tunnel-dev.sh`).
  - Config: `vite.config.ts`, `tsconfig.json`. Auth callback assets under `auth/`.

- **CRITICAL Build Workflow**:
  - **ONLY EDIT `src/smartwallet-dev.html`** - This is the primary development template for SmartWallet functionality. It must stay in sync with the roster-driven UX and is the source of truth for SmartWallet markup and scripting.
  - **NEVER EDIT `dist/smartwallet.html`** - This file is auto-generated from `src/smartwallet-dev.html` by the HTML injector during `npm run inject` and `npm run build`.
  - Build process: `npm run build` compiles TypeScript and injects the `dist/sui-sdk-minimal.iife.js` bundle into `dist/smartwallet.html` (via the injector pipeline).

- **Technology Stack**
  - TypeScript, ESNext with 2-space indentation, semicolons, and single quotes
  - Browser-based wallet for Sui blockchain using Mysten SDKs
  - Vite for development and building
  - Cloudflare Tunnel for secure development previews
  - IIFE (Immediately Invoked Function Expression) bundle for browser compatibility

- **Mysten Labs Dependencies & Documentation**
  - **@mysten/bcs** (^1.7.0): Binary Canonical Serialization utilities
    - [GitHub](https://github.com/MystenLabs/sui/tree/main/sdk/bcs) | [Docs](https://docs.sui.io/references/framework/sui-framework/bcs)
  - **@mysten/dapp-kit** (^0.17.7): React hooks and components for Sui dApps
    - [GitHub](https://github.com/MystenLabs/sui/tree/main/sdk/dapp-kit) | [Docs](https://sdk.mystenlabs.com/dapp-kit)
  - **@mysten/graphql-transport** (^0.3.9): GraphQL transport layer for Sui
    - [GitHub](https://github.com/MystenLabs/sui/tree/main/sdk/graphql-transport) | [Docs](https://docs.sui.io/guides/developer/sui-101/graphql-rpc)
  - **@mysten/kiosk** (^0.12.26): Kiosk SDK for trading and commerce
    - [GitHub](https://github.com/MystenLabs/sui/tree/main/sdk/kiosk) | [Docs](https://sdk.mystenlabs.com/kiosk)
  - **@mysten/seal** (^0.5.2): Decentralized secrets management
    - [GitHub](https://github.com/MystenLabs/seal) | [Docs](https://seal.mystenlabs.com/)
  - **@mysten/sui** (^1.37.6): Core Sui TypeScript SDK
    - [GitHub](https://github.com/MystenLabs/sui/tree/main/sdk/typescript) | [Docs](https://docs.sui.io/guides/developer/first-app/client-tssdk)
  - **@mysten/suins** (^0.7.36): SuiNS name service integration
    - [GitHub](https://github.com/MystenLabs/suins-contracts) | [Docs](https://docs.sui.io/standards/sui-name-service)
  - **@mysten/wallet-standard** (^0.16.14): Wallet standard implementation
    - [GitHub](https://github.com/MystenLabs/sui/tree/main/sdk/wallet-adapter/wallet-standard) | [Docs](https://docs.sui.io/standards/wallet-standard)
  - **@mysten/walrus** (^0.6.7): Decentralized blob storage using Sui
    - [GitHub](https://github.com/MystenLabs/walrus) | [Docs](https://docs.wal.app)
  - **@mysten/zksend** (^0.13.24): Zero-knowledge send functionality
    - [GitHub](https://github.com/MystenLabs/sui/tree/main/sdk/zksend) | [Docs](https://sdk.mystenlabs.com/zksend)

- **Critical Files to Review**
  - `src/index.ts`: Main SDK bundling and browser API exposure
  - `src/smartwallet-dev.html`: SmartWallet development template (**ONLY FILE TO EDIT**)
  - `dist/smartwallet.html`: SmartWallet single-file output (**AUTO-GENERATED - DO NOT EDIT**)
  - `vite.config.ts`: Build configuration
  - `package.json`: Dependencies and scripts

### 2. Create a Plan - AI Formulates Strategy Before Coding
**Develop a comprehensive strategy that considers:**

- **Impact Analysis**: How changes affect the browser-based wallet functionality
- **Module Dependencies**: Impact on `window.SuiSDK` API and wallet helpers
- **Build Process**: Effects on IIFE bundling and HTML injection
- **Security Implications**: Cryptographic operations and key management
- **Testing Strategy**: Unit tests for wallet logic, integration tests for SDK bundling
- **Environment Considerations**: Development vs production build differences

### 3. Add Tests for Changes - Create Verification Tests
**Implement testing strategy for Galactic project:**

- **Test Framework**: Prefer Vitest for browser-compatible testing
- **Test Location**: Place tests as `src/*.test.ts` alongside source files
- **Test Focus Areas**:
  - Wallet key generation and management functions
  - Mysten SDK integration and API calls
  - Browser API exposure via `window.SuiSDK`
  - IIFE bundle functionality
  - SmartWallet template behaviors defined in `src/smartwallet-dev.html` (roster rendering, action flows)
  - Authentication callback handling

- **Test Patterns**:
  ```typescript
  // Example: src/wallet.test.ts
  import { describe, it, expect, vi } from 'vitest';
  import { createWallet, signTransaction } from './wallet';
  ```

### 4. Implement Changes - Apply Modifications Based on Plan
**Execute changes following established patterns:**

- **Coding Standards**:
  - `camelCase` for variables/functions
  - `PascalCase` for types/classes
  - `kebab-case` for file names (e.g., `wallet-utils.ts`)
  - Explicit re-exports for `window.SuiSDK`
  - Avoid implicit globals

- **Implementation Checklist**:
  - [ ] Update `src/index.ts` for new SDK exports
  - [ ] Update HTML templates if needed (`src/smartwallet-dev.html`; never touch generated outputs)
  - [ ] Test build process with `npm run build`
  - [ ] Verify bundle injection works correctly for `dist/smartwallet.html`

### 5. Run & Observe - User Executes Build Commands
**The user will run these commands to test changes:**

- **Development Server**: `npm run dev` or `npm run tunnel-dev` (Cloudflare Tunnel + Vite with HTTPS)
- **Quick Build**: `npm run mini-build` (Fast build for testing)
- **Full Build**: `npm run build` (Creates IIFE bundle)
- **Injection Test**: `npm run inject` (Injects bundle into `dist/smartwallet.html` from `src/smartwallet-dev.html`)

**IMPORTANT**: Agents should NOT run development servers (`npm run dev`, `npm run tunnel-dev`) or build commands. The user will execute these commands when ready to test.

**Instead, agents should:**
- Inform the user which command to run for testing
- Explain what the user should look for when testing
- Ask the user to report results if needed

### 6. Test Details - Specify Exactly How to Test
**Detailed testing procedures for Galactic:**

#### Wallet Functionality Tests
1. **Key Generation**: Create new wallet and verify key pairs
2. **Transaction Signing**: Test signing Sui transactions
3. **Balance Queries**: Verify account balance retrieval
4. **Network Connection**: Test Sui network connectivity

#### Build System Tests
1. **Bundle Creation**: Verify `dist/sui-sdk-bundle.iife.js` is created
2. **HTML Injection**: Confirm bundle is properly injected into `dist/smartwallet.html`
3. **SmartWallet Output**: Diff `src/smartwallet-dev.html` vs generated `dist/smartwallet.html` to ensure expected sections are injected and no manual edits were lost
4. **Browser Loading**: Test that `window.SuiSDK` is available globally
5. **SDK Methods**: Verify all expected methods are accessible

#### Integration Tests
1. **Development Server**: Test HMR functionality with `npm run dev`
2. **Tunnel Access**: Verify public URL access with `npm run tunnel-dev`
3. **SmartWallet Preview**: Load `src/smartwallet-dev.html` via the dev server to validate roster interactions, modal flows, and SmartWallet-specific scripts before injection. After build, test `dist/smartwallet.html`.
4. **Production Build**: Test final generated `dist/smartwallet.html` in multiple browsers

### 7. Environment Details - Development Setup
**Required environment for Galactic development:**

- **Node.js**: Version compatible with Vite and Mysten SDKs
- **Browser**: Modern browser with ESNext support
- **Cloudflare Tunnel**: `CLOUDFLARE_TUNNEL_TOKEN` in `.env`
- **HTTPS**: Provided by Cloudflare Tunnel (no local certificates needed)
- **Sui Network**: Access to Sui Devnet/Testnet for testing
 - **GALACTIC_OPEN_SMARTWALLET**: Set to `false` to prevent auto-opening the SmartWallet dev URL in `npm run tunnel-dev` (default: `true`).

## Development Workflow Example

```bash
# 1. Context Gathering (Agent performs)
git status
# Agent reviews files and understands current state

# 2. Plan Creation (Agent performs)
# Agent reviews src/index.ts and HTML wallet functions
# Agent audits src/smartwallet-dev.html for impacted markup/scripts
# Agent identifies required changes and dependencies

# 3. Test Implementation (Agent performs if needed)
# Agent creates tests in src/wallet.test.ts if applicable

# 4. Code Implementation (Agent performs)
# Agent makes changes to wallet functionality
# Agent updates SDK exports if needed
# Agent applies HTML/template changes only in src/smartwallet-dev.html

# 5. User Testing (User performs)
npm run mini-build  # Quick build for testing
# OR
npm run build      # Full build
# OR
npm run dev        # Development server

# 6. Detailed Testing (User performs)
# User tests wallet creation, transaction signing
# User verifies browser console for errors
# User tests in multiple browsers
# User reports results to agent if issues found
```

## Commit & Pull Request Guidelines
- **Conventional Commits**: Use `feat:`, `fix:`, `docs:`, `test:` prefixes
- **PR Content**: Include summary, linked issues, reproduction steps
- **Testing Notes**: Document wallet-specific testing procedures
- **Security Review**: Note any cryptographic or key management changes

## Security & Configuration Tips
- **Secrets Management**: Never commit keys; use `.env` for `CLOUDFLARE_TUNNEL_TOKEN`
- **Production Safety**: Remove/guard key logging in production builds
- **HTTPS Security**: Provided by Cloudflare Tunnel (recommended for production)
- **Bundle Security**: Ensure IIFE bundle doesn't expose sensitive data
