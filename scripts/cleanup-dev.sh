#!/usr/bin/env bash
# Manual cleanup script for vWallet dev processes

echo "🧹 Cleaning up vWallet dev processes..."

# Kill all processes on port 5173 (Vite)
if command -v lsof >/dev/null 2>&1 && lsof -ti:5173 >/dev/null 2>&1; then
  echo "Killing processes on port 5173 (Vite)..."
  kill -9 $(lsof -ti:5173) 2>/dev/null || true
fi

# Kill all cloudflared processes
if pgrep -x cloudflared >/dev/null 2>&1; then
  echo "Killing cloudflared processes..."
  pkill -x cloudflared 2>/dev/null || true
fi

# Kill any Vite processes by name
if pgrep -f "vite.*5173" >/dev/null 2>&1; then
  echo "Killing Vite processes..."
  pkill -f "vite.*5173" 2>/dev/null || true
fi

# Wait a moment for processes to cleanup
sleep 1

# Check if ports are clear
echo "Checking port status..."
if command -v lsof >/dev/null 2>&1; then
  if lsof -ti:5173 >/dev/null 2>&1; then
    echo "⚠️  Port 5173 still has processes:"
    lsof -ti:5173
  else
    echo "✅ Port 5173 is clear"
  fi
else
  echo "ℹ️  Install lsof for better port checking"
fi

if pgrep -x cloudflared >/dev/null 2>&1; then
  echo "⚠️  Cloudflared processes still running:"
  pgrep -x cloudflared
else
  echo "✅ No cloudflared processes running"
fi

echo "🎉 Cleanup complete!"