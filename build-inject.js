// build-inject.js - Script to inject the bundled SDK into HTML files for production
const fs = require('fs');
const path = require('path');

// Define input and output files
const htmlFiles = [
  {
    input: 'src/smartwallet-dev.html',
    output: 'dist/smartwallet.html',
    name: 'SmartWallet'
  }
];

const shellBundlePath = path.join(__dirname, 'dist/sui-sdk-shell.iife.js');
const zkLoginBundlePath = path.join(__dirname, 'dist/zklogin-helpers.iife.js');

/**
 * Wrap a bundle in a base64 loader so the browser never parses the raw code inline.
 * This avoids HTML parser edge-cases (e.g. unexpected identifiers) while keeping
 * the single-file build behavior for SmartWallet outputs.
 */
function createInlineLoader(bundle, { label }) {
  if (!bundle) return '';

  const base64 = Buffer.from(bundle, 'utf8').toString('base64');

  const loaderLines = [
    '(function(){',
    '  try {',
    `    const bundleBase64 = '${base64}';`,
    "    const decode = typeof globalThis.atob === 'function'",
    "      ? (value) => globalThis.atob(value)",
    "      : (value) => {",
    "          if (globalThis.Buffer && typeof globalThis.Buffer.from === 'function') {",
    "            return globalThis.Buffer.from(value, 'base64').toString('utf8');",
    '          }',
    "          throw new Error('Base64 decoder unavailable in this environment');",
    '        };',
    '    const execute = new Function(decode(bundleBase64));',
    '    execute();',
    '  } catch (error) {',
    `    console.error('Failed to execute inline ${label} bundle:', error);`,
    '  }',
    '}())'
  ];

  return `<script>${loaderLines.join('')}</script>`;
}

try {
  // Check if bundles exist
  const hasShell = fs.existsSync(shellBundlePath);
  const hasZkLogin = fs.existsSync(zkLoginBundlePath);

  if (!hasShell) {
    console.error('❌ No shell bundle found! Please run "npm run build:tiered" first.');
    process.exit(1);
  }

  // Read the shell bundle for SmartWallet
  let shellBundle = '';
  if (hasShell) {
    shellBundle = fs.readFileSync(shellBundlePath, 'utf8');
    shellBundle = shellBundle.replace(/<\/script>/gi, '<\\/script>');
    console.log('📦 Shell bundle loaded successfully');
  }


  let zkLoginBundle = '';
  let zkLoginBundleBase64 = '';
  if (hasZkLogin) {
    zkLoginBundle = fs.readFileSync(zkLoginBundlePath, 'utf8');
    zkLoginBundle = zkLoginBundle.replace(/<\/script>/gi, '<\\/script>');
    zkLoginBundleBase64 = Buffer.from(zkLoginBundle, 'utf8').toString('base64');
    console.log('📦 zkLogin helper bundle loaded successfully');
  }

  // Process each HTML file
  htmlFiles.forEach(file => {
    const inputPath = path.join(__dirname, file.input);
    const outputPath = path.join(__dirname, file.output);
    
    // Skip if input file doesn't exist
    if (!fs.existsSync(inputPath)) {
      console.log(`⚠️ Skipping ${file.name}: ${file.input} not found`);
      return;
    }
    
    console.log(`🔄 Processing ${file.name}...`);
    
    // Read the base HTML file
    let html = fs.readFileSync(inputPath, 'utf8');
    
    // Use shell bundle for SmartWallet
    const bundleToUse = shellBundle;
    const bundleName = 'shell';

    const inlineLoader = createInlineLoader(bundleToUse, { label: `${file.name} ${bundleName}` });
    let bundleReplacement = inlineLoader;

    // For SmartWallet, use tiered loading - shell bundle with progressive enhancement
    if (file.name === 'SmartWallet') {
      // Read the passkey icon and convert to base64
      const passkeyIconPath = path.join(__dirname, 'assets', 'passkey-low.webp');
      let passkeyIconBase64 = '';
      if (fs.existsSync(passkeyIconPath)) {
        const passkeyIconBuffer = fs.readFileSync(passkeyIconPath);
        passkeyIconBase64 = passkeyIconBuffer.toString('base64');
      }

      bundleReplacement += `
    <script>
      // SmartWallet performance optimization: Using ${bundleName} bundle
      console.log('SmartWallet: ${bundleName} SDK loaded. Progressive enhancement starting...');
      // Tiered loading: Core/Transaction/Advanced tiers load progressively
      window.__SMARTWALLET_PASSKEY_ICON__ = 'data:image/webp;base64,' + '${passkeyIconBase64}';
      // Note: window.__SMARTWALLET_ZKLOGIN_BASE64 removed for size optimization - zkLogin helpers load from external file

      // Load zkLogin helpers when browser is idle for better UX
      if ('requestIdleCallback' in window) {
        requestIdleCallback(() => {
          window.loadZkLoginHelpers?.().catch(err =>
            console.log('Background zkLogin helpers load failed (non-critical):', err.message)
          );
        }, { timeout: 2000 });
      } else {
        // Fallback for browsers without requestIdleCallback
        setTimeout(() => {
          window.loadZkLoginHelpers?.().catch(err =>
            console.log('Background zkLogin helpers load failed (non-critical):', err.message)
          );
        }, 1000);
      }
    </script>`;
    }

    html = html.replace('<!-- BUNDLE_PLACEHOLDER -->', bundleReplacement);
    
    // Add/replace favicon: if dev link exists, replace with data URL for single-file prod
    const faviconTxtPath = path.join(__dirname, 'assets', 'vw-favicon.webp');
    const faviconLinkRegex = /<link\s+[^>]*rel=["']icon["'][^>]*>/i;
    const hasFaviconLink = faviconLinkRegex.test(html);
    if (fs.existsSync(faviconTxtPath)) {
      const iconBuffer = fs.readFileSync(faviconTxtPath);
      const iconBase64 = iconBuffer.toString('base64');
      const dataUrlTag = `<link rel="icon" type="image/webp" href="data:image/webp;base64,${iconBase64}">`;
      if (hasFaviconLink) {
        html = html.replace(faviconLinkRegex, dataUrlTag);
      } else {
        html = html.replace('</title>', `</title>\n    ${dataUrlTag}`);
      }
    }
    
    // Remove any dev-only script references (if they exist)
    html = html.replace(/<script src="\.?\/dist\/sui-sdk-.*\.iife\.js"><\/script>/g, '');
    
    // Write the production HTML file to dist/
    fs.writeFileSync(outputPath, html);
    
    const stats = fs.statSync(outputPath);
    const fileSize = (stats.size / 1024 / 1024).toFixed(2);
    
    console.log(`✅ ${file.name} bundle injected successfully!`);
    console.log(`   📁 Output: ${file.output}`);
    console.log(`   📏 File size: ${fileSize} MB`);
  });
  
  console.log('🌐 All single-file bundles built successfully!');
  
} catch (error) {
  console.error('❌ Error injecting bundle:', error.message);
  process.exit(1);
}
