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
  resolve: {
    alias: {
      // Help resolve package exports
      '@mysten/sui': '@mysten/sui',
    },
  },
  define: {
    global: 'globalThis',
    'process.env.NODE_ENV': '"production"',
    'process.env': '{}',
  },
});