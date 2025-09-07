# vWallet Coding Agent Instructions

## Agent Processing Flow

### 1. Context - Gather All Relevant Information First
**Before any coding changes, thoroughly understand the vWallet project context:**

- **Project Structure & Module Organization**
  - `src/`: TypeScript sources. `index.ts` bundles Mysten SDKs to `window.SuiSDK`.
  - `dist/`: Build output (`sui-sdk-bundle.iife.js`).
  - `scripts/`: Dev utilities (`tunnel-dev.sh`).
  - Root HTML: `vWallet-dev.html` (dev), `vWallet.html` (built single-file output).
  - Config: `vite.config.ts`, `tsconfig.json`. Auth callback assets under `auth/`.

- **Technology Stack**
  - TypeScript, ESNext with 2-space indentation, semicolons, and single quotes
  - Browser-based wallet for Sui blockchain using Mysten SDKs
  - Vite for development and building
  - Cloudflare Tunnel for secure development previews
  - IIFE (Immediately Invoked Function Expression) bundle for browser compatibility

- **Critical Files to Review**
  - `src/index.ts`: Main SDK bundling and browser API exposure
  - `vWallet-dev.html`: Development HTML template
  - `vWallet.html`: Production single-file output
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
**Implement testing strategy for vWallet project:**

- **Test Framework**: Prefer Vitest for browser-compatible testing
- **Test Location**: Place tests as `src/*.test.ts` alongside source files
- **Test Focus Areas**:
  - Wallet key generation and management functions
  - Mysten SDK integration and API calls
  - Browser API exposure via `window.SuiSDK`
  - IIFE bundle functionality
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
  - [ ] Update HTML templates if needed
  - [ ] Test build process with `npm run build`
  - [ ] Verify bundle injection works correctly

### 5. Run & Observe - Monitor Execution Outputs
**Execute and monitor the following commands:**

- **Development Mode**: `npm run dev` (Vite on `http://localhost:5173`)
- **Tunnel Mode**: `npm run tunnel-dev` (Cloudflare Tunnel + Vite with HTTPS)
- **Build Process**: `npm run build` (Creates IIFE bundle)
- **Injection Test**: `npm run inject` (Injects bundle into HTML)

**Monitor for:**
- Browser console errors in wallet operations
- Build process completion and bundle size
- HTML injection success
- Network requests in development tools

### 6. Test Details - Specify Exactly How to Test
**Detailed testing procedures for vWallet:**

#### Wallet Functionality Tests
1. **Key Generation**: Create new wallet and verify key pairs
2. **Transaction Signing**: Test signing Sui transactions
3. **Balance Queries**: Verify account balance retrieval
4. **Network Connection**: Test Sui network connectivity

#### Build System Tests
1. **Bundle Creation**: Verify `dist/sui-sdk-bundle.iife.js` is created
2. **HTML Injection**: Confirm bundle is properly injected into `vWallet.html`
3. **Browser Loading**: Test that `window.SuiSDK` is available globally
4. **SDK Methods**: Verify all expected methods are accessible

#### Integration Tests
1. **Development Server**: Test HMR functionality with `npm run dev`
2. **Tunnel Access**: Verify public URL access with `npm run tunnel-dev`
3. **Production Build**: Test final `vWallet.html` in multiple browsers

### 7. Environment Details - Development Setup
**Required environment for vWallet development:**

- **Node.js**: Version compatible with Vite and Mysten SDKs
- **Browser**: Modern browser with ESNext support
- **Cloudflare Tunnel**: `CLOUDFLARE_TUNNEL_TOKEN` in `.env`
- **HTTPS**: Provided by Cloudflare Tunnel (no local certificates needed)
- **Sui Network**: Access to Sui Devnet/Testnet for testing

## Development Workflow Example

```bash
# 1. Context Gathering
git status
npm install
npm run dev

# 2. Plan Creation
# Review src/index.ts and HTML wallet functions
# Identify required changes and dependencies

# 3. Test Implementation
# Create tests in src/wallet.test.ts
npm test

# 4. Code Implementation
# Make changes to wallet functionality
# Update SDK exports if needed

# 5. Run & Observe
npm run build
npm run inject
open vWallet.html

# 6. Detailed Testing
# Test wallet creation, transaction signing
# Verify browser console for errors
# Test in multiple browsers
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

