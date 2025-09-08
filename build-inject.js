// build-inject.js - Script to inject the bundled SDK into HTML for production
const fs = require('fs');
const path = require('path');

const htmlPath = path.join(__dirname, 'vWallet-dev.html');
const bundlePath = path.join(__dirname, 'dist/sui-sdk-bundle.iife.js');
const outputPath = path.join(__dirname, 'vWallet.html');

try {
  // Check if bundle exists
  if (!fs.existsSync(bundlePath)) {
    console.error('❌ Bundle not found! Please run "npm run build" first.');
    process.exit(1);
  }
  
  // Read the base HTML file
  let html = fs.readFileSync(htmlPath, 'utf8');
  
  // Read the bundled JavaScript
  const bundle = fs.readFileSync(bundlePath, 'utf8');
  
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
  
  // Write the production HTML file
  fs.writeFileSync(outputPath, html);
  
  const stats = fs.statSync(outputPath);
  const fileSize = (stats.size / 1024 / 1024).toFixed(2);
  
  console.log('✅ Bundle injected successfully!');
  console.log(`📁 Output: ${outputPath}`);
  console.log(`📏 File size: ${fileSize} MB`);
  console.log('🌐 Built single-file bundle. Note: Passkeys require trusted HTTPS (not file://).');
  
} catch (error) {
  console.error('❌ Error injecting bundle:', error.message);
  process.exit(1);
}
