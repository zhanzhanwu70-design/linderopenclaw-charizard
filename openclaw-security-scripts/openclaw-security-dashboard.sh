#!/bin/bash
# openclaw-security-dashboard.sh

while true; do
  clear
  echo "🔒 OpenClaw Security Monitoring Dashboard"
  echo "=========================================="
  echo "Last Updated: $(date)"
  echo ""
  
  # Check OpenClaw processes
  echo "📊 OpenClaw Process Status:"
  ps aux | grep -E "(openclaw|clawdbot)" | grep -v grep || echo "❌ No OpenClaw processes running"
  echo ""
  
  # Check credential security
  echo "🔐 Credential Security:"
  if [ -d ~/.openclaw ]; then
    CREDENTIAL_FILES=$(find ~/.openclaw/credentials -type f 2>/dev/null | wc -l)
    echo "📁 Credential files: $CREDENTIAL_FILES"
    
    UNPROTECTED=$(find ~/.openclaw/ -type f -not -perm 600 2>/dev/null | wc -l)
    if [ "$UNPROTECTED" -gt 0 ]; then
      echo "⚠️  $UNPROTECTED files have insecure permissions"
    else
      echo "✅ All files have secure permissions"
    fi
  else
    echo "✅ No ~/.openclaw directory found"
  fi
  echo ""
  
  # Check network security
  echo "🌐 Network Security:"
  if lsof -i :18789 >/dev/null 2>&1; then
    CONNECTIONS=$(lsof -i :18789 | grep -v "PID" | wc -l)
    echo "🔗 Port 18789 connections: $CONNECTIONS"
  else
    echo "✅ Port 18789 not listening"
  fi
  echo ""
  
  # Recent security events
  echo "🚨 Recent Security Events:"
  if [ -f $HOME/openclaw-integrity.log ]; then
    echo "📝 Integrity log:"
    tail -3 $HOME/openclaw-integrity.log | while read line; do
      echo "   $line"
    done
  fi
  echo ""
  
  echo "Press Ctrl+C to exit. Dashboard refreshes every 10 seconds."
  sleep 10
done
