// build-inject.js - Script to inject the bundled SDK into HTML files for production
const fs = require('fs');
const path = require('path');

// Define input and output files
const htmlFiles = [
  {
    input: 'vWallet-dev.html',
    output: 'vWallet.html',
    name: 'vWallet'
  },
  {
    input: 'src/smartwallet-dev.html', 
    output: 'src/smartwallet.html',
    name: 'SmartWallet'
  }
];

const bundlePath = path.join(__dirname, 'dist/sui-sdk-bundle.iife.js');

try {
  // Check if bundle exists
  if (!fs.existsSync(bundlePath)) {
    console.error('❌ Bundle not found! Please run "npm run build" first.');
    process.exit(1);
  }
  
  // Read the bundled JavaScript once
  let bundle = fs.readFileSync(bundlePath, 'utf8');
  // Escape closing script tags to keep HTML parsers happy when inlining
  // This prevents premature </script> termination in the single-file HTML.
  bundle = bundle.replace(/<\/script>/gi, '<\\/script>');
  console.log('📦 Bundle loaded successfully');
  
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
    
    // Inject the bundle at the placeholder
    html = html.replace('<!-- BUNDLE_PLACEHOLDER -->', `<script>${bundle}</script>`);
    
    // Add/replace favicon: if dev link exists, replace with data URL for single-file prod
    const faviconTxtPath = path.join(__dirname, 'assets', 'vWallet.txt');
    const faviconLinkRegex = /<link\s+[^>]*rel=["']icon["'][^>]*>/i;
    const hasFaviconLink = faviconLinkRegex.test(html);
    if (fs.existsSync(faviconTxtPath)) {
      const iconBase64 = fs.readFileSync(faviconTxtPath, 'utf8').trim();
      const dataUrlTag = `<link rel="icon" type="image/png" href="data:image/png;base64,${iconBase64}">`;
      if (hasFaviconLink) {
        html = html.replace(faviconLinkRegex, dataUrlTag);
      } else {
        html = html.replace('</title>', `</title>\n    ${dataUrlTag}`);
      }
    }
    
    // Remove any dev-only script references (if they exist)
    html = html.replace(/<script src="\.?\/dist\/sui-sdk-bundle\.iife\.js"><\/script>/g, '');
    
    // Write the production HTML file (root)
    fs.writeFileSync(outputPath, html);

    // Also write into dist/ so `vite preview` or any static server can serve it without dev transforms
    try {
      const distOut = path.join(__dirname, 'dist', file.output);
      fs.writeFileSync(distOut, html);
    } catch (e) {
      // Non-fatal: dist folder should exist after vite build; if not, skip
    }
    
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
