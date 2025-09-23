#!/usr/bin/env bash
set -euo pipefail

echo "🚀 Galactic SmartWallet Fast Build Script"
echo "========================================="

# 1️⃣ Clean previous artifacts
echo "🧹 Cleaning previous build artifacts..."
rm -rf dist dist-temp-*
mkdir -p dist

# 2️⃣ Ensure PNGs are converted to WebP (run only if files changed)
echo "🖼️  Converting icons to WebP format..."
if command -v convert >/dev/null 2>&1; then
  # Check if WebP files are older than PNG files or don't exist
  if [ ! -f assets/vw-favicon.webp ] || [ assets/vw-favicon-original.png -nt assets/vw-favicon.webp ]; then
    echo "   Converting vw-favicon-original.png..."
    convert assets/vw-favicon-original.png -quality 100 assets/vw-favicon.webp
  fi

  if [ ! -f assets/passkey-low.webp ] || [ assets/passkey-low.png -nt assets/passkey-low.webp ]; then
    echo "   Converting passkey-low.png..."
    convert assets/passkey-low.png -quality 100 assets/passkey-low.webp
  fi
  echo "   ✅ WebP conversion complete"
else
  echo "   ⚠️  ImageMagick not found, skipping WebP conversion"
  echo "   Install ImageMagick with: sudo apt-get install imagemagick"
fi

# 3️⃣ Build everything (tiered SDK + zklogin + inject)
echo "📦 Building SmartWallet with tiered loading..."
npm run build:tiered

# 4️⃣ Verify output size and show comparison
echo ""
echo "📊 Build Results"
echo "==============="

if [ -f src/smartwallet-dev.html ]; then
  SRC_SIZE=$(du -h src/smartwallet-dev.html | cut -f1)
  echo "📁 Source template: $SRC_SIZE (src/smartwallet-dev.html)"
fi

if [ -f dist/smartwallet.html ]; then
  DIST_SIZE=$(du -h dist/smartwallet.html | cut -f1)
  echo "📦 Production build: $DIST_SIZE (dist/smartwallet.html)"
else
  echo "❌ dist/smartwallet.html not found!"
  exit 1
fi

echo ""
echo "🎯 Performance Optimizations Applied:"
echo "   ✅ WebP icons (30-40% smaller than PNG)"
echo "   ✅ Ultra-minimal shell bundle inlined for instant UI"
echo "   ✅ Tiered loading: Core → Transaction → Advanced SDK features"
echo "   ✅ zkLogin helpers load when browser is idle for better UX"
echo "   ✅ No source maps in production build"
echo "   ✅ Inline icons as data URLs for single-file deployment"

echo ""
echo "🚀 Ready for deployment! Test with:"
echo "   npx serve dist/"
echo "   Then open: http://localhost:3000/smartwallet.html"