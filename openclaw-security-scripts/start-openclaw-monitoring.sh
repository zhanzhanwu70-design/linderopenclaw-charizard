#!/bin/bash
# start-openclaw-monitoring.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "🚀 Starting OpenClaw security monitoring..."

# Start file integrity monitoring
$SCRIPT_DIR/file-integrity-monitor.sh &
echo "✅ File integrity monitor started (PID: $!)"

# Start credential theft monitoring
$SCRIPT_DIR/credential-theft-monitor.sh &
echo "✅ Credential theft monitor started (PID: $!)"

# Start network anomaly detection
$SCRIPT_DIR/network-anomaly-detector.sh &
echo "✅ Network anomaly detector started (PID: $!)"

# Start process anomaly detection
$SCRIPT_DIR/process-anomaly-detector.sh &
echo "✅ Process anomaly detector started (PID: $!)"

echo ""
echo "🎉 OpenClaw security monitoring is now active!"
echo "📊 Run ./openclaw-security-dashboard.sh for real-time status"
