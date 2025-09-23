import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    lib: {
      entry: process.env.BUILD_TARGET === 'zklogin'
        ? './src/zklogin-helpers.ts'
        : process.env.BUILD_TARGET === 'shell'
        ? './src/index-shell.js'
        : process.env.BUILD_TARGET === 'core'
        ? './src/index-core.ts'
        : process.env.BUILD_TARGET === 'transaction'
        ? './src/index-transaction.ts'
        : process.env.BUILD_TARGET === 'advanced'
        ? './src/index-advanced.ts'
        : './src/index-shell.js', // Default to shell
      name: process.env.BUILD_TARGET === 'zklogin'
        ? 'SuiSDKZkLoginHelpers'
        : process.env.BUILD_TARGET === 'shell'
        ? 'SuiSDKShell'
        : process.env.BUILD_TARGET === 'core'
        ? 'SuiSDKCore'
        : process.env.BUILD_TARGET === 'transaction'
        ? 'SuiSDKTransaction'
        : process.env.BUILD_TARGET === 'advanced'
        ? 'SuiSDKAdvanced'
        : 'SuiSDKShell', // Default to shell
      fileName: process.env.BUILD_TARGET === 'zklogin'
        ? 'zklogin-helpers'
        : process.env.BUILD_TARGET === 'shell'
        ? 'sui-sdk-shell'
        : process.env.BUILD_TARGET === 'core'
        ? 'sui-sdk-core'
        : process.env.BUILD_TARGET === 'transaction'
        ? 'sui-sdk-transaction'
        : process.env.BUILD_TARGET === 'advanced'
        ? 'sui-sdk-advanced'
        : 'sui-sdk-shell', // Default to shell
      formats: ['iife'],
    },
    minify: true,
    sourcemap: false, // Disable source maps for production builds to reduce bundle size
    target: 'esnext',
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
      treeshake: {
        preset: 'smallest',
        manualPureFunctions: ['console.log'],
      },
    },
    outDir: process.env.BUILD_TARGET === 'zklogin'
      ? 'dist-temp-zklogin'
      : process.env.BUILD_TARGET === 'shell'
      ? 'dist-temp-shell'
      : process.env.BUILD_TARGET === 'core'
      ? 'dist-temp-core'
      : process.env.BUILD_TARGET === 'transaction'
      ? 'dist-temp-transaction'
      : process.env.BUILD_TARGET === 'advanced'
      ? 'dist-temp-advanced'
      : 'dist',
  },
  server: {
    host: true, // Listen on all interfaces
    port: 5173,
    strictPort: true,
    // Serve circuit files from root directory
    fs: {
      allow: ['..'], // Allow serving files from parent directory
    },

    // Ensure Vite HMR works behind Cloudflare Tunnel on custom domain
    ...(process.env.GALACTIC_DEV_HOST ? {
      hmr: {
        host: process.env.GALACTIC_DEV_HOST,
        protocol: 'wss',
        clientPort: 443,
      }
    } : {}),
    allowedHosts: [
      'localhost',
      ...(process.env.GALACTIC_DEV_HOST ? [process.env.GALACTIC_DEV_HOST] : []),
      ...(process.env.GALACTIC_PROD_HOST ? [process.env.GALACTIC_PROD_HOST] : []),
    ],
  },
  preview: {
    host: true,
    port: 5173,
    allowedHosts: [
      'localhost',
      ...(process.env.GALACTIC_DEV_HOST ? [process.env.GALACTIC_DEV_HOST] : []),
      ...(process.env.GALACTIC_PROD_HOST ? [process.env.GALACTIC_PROD_HOST] : []),
    ],
  },
  resolve: {
    alias: {
      '@mysten/sui': '@mysten/sui',
    },
  },
  define: {
    global: 'globalThis',
    'process.env.NODE_ENV': '"production"',
    'process.env': '{}',
  },
});
