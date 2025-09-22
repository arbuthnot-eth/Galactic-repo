import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    lib: {
      entry: process.env.BUILD_TARGET === 'minimal'
        ? './src/index-minimal.ts'
        : process.env.BUILD_TARGET === 'zklogin'
        ? './src/zklogin-helpers.ts'
        : './src/index-minimal.ts', // Default to minimal
      name: process.env.BUILD_TARGET === 'minimal'
        ? 'SuiSDKMinimal'
        : process.env.BUILD_TARGET === 'zklogin'
        ? 'SuiSDKZkLoginHelpers'
        : 'SuiSDKMinimal', // Default to minimal
      fileName: process.env.BUILD_TARGET === 'minimal'
        ? 'sui-sdk-minimal'
        : process.env.BUILD_TARGET === 'zklogin'
        ? 'zklogin-helpers'
        : 'sui-sdk-minimal', // Default to minimal
      formats: ['iife'],
    },
    minify: true,
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
    outDir: process.env.BUILD_TARGET === 'minimal'
      ? 'dist-temp-minimal'
      : process.env.BUILD_TARGET === 'zklogin'
      ? 'dist-temp-zklogin'
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
    'import.meta.env.VITE_ENOKI_API_KEY': JSON.stringify(process.env.VITE_ENOKI_API_KEY || process.env.ENOKI_PUBLIC_API_KEY || ''),
    'import.meta.env.VITE_ENOKI_API_URL': JSON.stringify(process.env.VITE_ENOKI_API_URL || process.env.ENOKI_API_URL || ''),
  },
});
