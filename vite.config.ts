import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    lib: {
      entry: './src/index.ts',
      name: 'SuiSDKBundle',
      fileName: 'sui-sdk-bundle',
      formats: ['iife'],
    },
    minify: true,
    target: 'esnext',
    rollupOptions: {
      output: {
        inlineDynamicImports: true,
      },
    },
  },
  server: {
    host: true, // Listen on all interfaces
    port: 5173,
    strictPort: true,
    // Ensure Vite HMR works behind Cloudflare Tunnel on custom domain
    ...(process.env.VWALLET_DEV_HOST ? {
      hmr: {
        host: process.env.VWALLET_DEV_HOST,
        protocol: 'wss',
        clientPort: 443,
      }
    } : {}),
    allowedHosts: [
      'localhost',
      ...(process.env.VWALLET_DEV_HOST ? [process.env.VWALLET_DEV_HOST] : []),
      ...(process.env.VWALLET_PROD_HOST ? [process.env.VWALLET_PROD_HOST] : []),
    ],
  },
  preview: {
    host: true,
    port: 5173,
    allowedHosts: [
      'localhost',
      ...(process.env.VWALLET_DEV_HOST ? [process.env.VWALLET_DEV_HOST] : []),
      ...(process.env.VWALLET_PROD_HOST ? [process.env.VWALLET_PROD_HOST] : []),
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
